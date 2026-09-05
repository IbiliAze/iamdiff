package aws

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/IbiliAze/iamdiff/internal/model"
	"github.com/IbiliAze/iamdiff/internal/plan"
	"github.com/IbiliAze/iamdiff/internal/provider"
)

// FromPlan reads every IAM-bearing resource out of a Terraform plan and
// groups the documents by the principal they attach to.
//
// Policies attached by reference resolve through the plan's
// configuration, because a policy created in the same plan has no ARN
// until apply. Anything the plan cannot show -- a policy computed at
// apply time, an attached policy that lives outside the plan, a
// permissions boundary by ARN -- is a gap on the side it affects, so the
// result is partial rather than confidently wrong.
func (p *Provider) FromPlan(pl *plan.Plan) ([]provider.PrincipalChange, error) {
	b := &planBuilder{
		plan:       pl,
		principals: map[string]*principalChange{},
		policies:   map[string]*planPolicy{},
	}
	for i := range pl.ResourceChanges {
		rc := &pl.ResourceChanges[i]
		if rc.Mode != "managed" {
			continue
		}
		switch rc.Type {
		case "aws_iam_policy":
			b.policy(rc)
		case "aws_iam_role":
			b.role(rc)
		case "aws_iam_role_policy":
			b.inlinePolicy(rc, "role")
		case "aws_iam_user_policy":
			b.inlinePolicy(rc, "user")
		case "aws_iam_group_policy":
			b.inlinePolicy(rc, "group")
		case "aws_iam_role_policy_attachment":
			b.attachment(rc, "role")
		case "aws_iam_user_policy_attachment":
			b.attachment(rc, "user")
		case "aws_iam_group_policy_attachment":
			b.attachment(rc, "group")
		case "aws_iam_policy_attachment":
			for _, kind := range []string{"role", "user", "group"} {
				for _, side := range []side{before, after} {
					for _, name := range plan.Strings(rc.Side(int(side)), kind+"s") {
						b.link(b.principal(kind, name), rc, side)
					}
				}
			}
		case "aws_organizations_policy":
			b.scp(rc)
		}
	}
	return b.finish(), nil
}

type side int

const (
	before side = iota
	after
)

func (s side) String() string {
	if s == before {
		return "before"
	}
	return "after"
}

// principalChange accumulates one principal's documents on both sides.
type principalChange struct {
	principal model.Principal
	sides     [2]*provider.RawSet
}

// planPolicy is an aws_iam_policy resource: its document on each side,
// its ARN where known, and whether anything attached it.
type planPolicy struct {
	rc     *plan.ResourceChange
	docs   [2]*provider.Document
	arns   [2]string
	linked bool
}

type planBuilder struct {
	plan       *plan.Plan
	principals map[string]*principalChange
	policies   map[string]*planPolicy
}

func (b *planBuilder) principal(kind, ref string) *principalChange {
	key := kind + "/" + ref
	pc, ok := b.principals[key]
	if !ok {
		pr := model.Principal{Provider: Name, Kind: kind, Ref: ref}
		pc = &principalChange{principal: pr}
		for s := range pc.sides {
			pc.sides[s] = &provider.RawSet{Principal: pr}
		}
		b.principals[key] = pc
	}
	return pc
}

func (pc *principalChange) add(s side, doc provider.Document) {
	pc.sides[s].Documents = append(pc.sides[s].Documents, doc)
}

func (pc *principalChange) gap(s side, format string, args ...any) {
	pc.sides[s].Gaps = append(pc.sides[s].Gaps, fmt.Sprintf(format, args...))
}

// document reads a policy string attribute on one side as a document.
// The second result is false when the resource does not exist on that
// side; an unknown or malformed value is a gap.
func (b *planBuilder) document(rc *plan.ResourceChange, s side, attr string, kind model.SourceKind, name string) (*provider.Document, string) {
	m := rc.Side(int(s))
	if m == nil {
		return nil, ""
	}
	if s == after && rc.Unknown(attr) {
		return nil, fmt.Sprintf("%s: %s is not known until apply", rc.Address, attr)
	}
	body, ok := plan.String(m, attr)
	if !ok || body == "" {
		return nil, ""
	}
	if !json.Valid([]byte(body)) {
		return nil, fmt.Sprintf("%s: %s is not valid JSON", rc.Address, attr)
	}
	return &provider.Document{Kind: kind, Name: name, Body: json.RawMessage(body)}, ""
}

// ownerRef works out which principal an inline policy or attachment
// belongs to. The name is usually known; when the owner is created in
// the same plan with a generated name it is not, and the configuration
// reference leads to the owner resource instead.
func (b *planBuilder) ownerRef(rc *plan.ResourceChange, kind string) (string, bool) {
	for _, s := range []side{after, before} {
		if name, ok := plan.String(rc.Side(int(s)), kind); ok && name != "" {
			return name, true
		}
	}
	for _, owner := range b.plan.References(rc.Address, kind) {
		if owner.Type == "aws_iam_"+kind {
			return b.resourceRef(owner), true
		}
	}
	return "", false
}

// resourceRef names a principal resource by its name when known and by
// its address otherwise.
func (b *planBuilder) resourceRef(rc *plan.ResourceChange) string {
	for _, s := range []side{after, before} {
		if name, ok := plan.String(rc.Side(int(s)), "name"); ok && name != "" {
			return name
		}
	}
	return rc.Address
}

func (b *planBuilder) policy(rc *plan.ResourceChange) {
	pp := &planPolicy{rc: rc}
	for _, s := range []side{before, after} {
		doc, gap := b.document(rc, s, "policy", model.SourceIdentity, rc.Address)
		if gap != "" {
			// Recorded against whoever ends up holding the policy.
			doc = &provider.Document{Kind: model.SourceIdentity, Name: rc.Address, Body: nil}
			doc.Name = gap
		}
		pp.docs[s] = doc
		pp.arns[s], _ = plan.String(rc.Side(int(s)), "arn")
	}
	b.policies[rc.Address] = pp
}

// attach adds a policy's document on one side to a principal, or the gap
// standing in for it.
func (b *planBuilder) attach(pc *principalChange, pp *planPolicy, s side) {
	pp.linked = true
	doc := pp.docs[s]
	if doc == nil {
		return
	}
	if doc.Body == nil {
		pc.gap(s, "%s", doc.Name)
		return
	}
	pc.add(s, *doc)
}

// link connects a principal to the policy an attachment names, on the
// sides where the attachment exists.
func (b *planBuilder) link(pc *principalChange, rc *plan.ResourceChange, s side) {
	if rc.Side(int(s)) == nil {
		return
	}
	targets := b.plan.References(rc.Address, "policy_arn")
	linked := false
	for _, t := range targets {
		if pp, ok := b.policies[t.Address]; ok {
			b.attach(pc, pp, s)
			linked = true
		}
	}
	if linked {
		return
	}
	arn, _ := plan.String(rc.Side(int(s)), "policy_arn")
	if arn == "" {
		if s == after && rc.Unknown("policy_arn") {
			pc.gap(s, "%s: policy_arn is not known until apply", rc.Address)
		}
		return
	}
	if pp := b.policyByARN(arn, s); pp != nil {
		b.attach(pc, pp, s)
		return
	}
	pc.gap(s, "%s: attached policy %s is not in the plan; its permissions are not evaluated", rc.Address, arn)
}

func (b *planBuilder) policyByARN(arn string, s side) *planPolicy {
	for _, pp := range b.policies {
		if pp.arns[s] == arn {
			return pp
		}
	}
	return nil
}

func (b *planBuilder) attachment(rc *plan.ResourceChange, kind string) {
	ref, ok := b.ownerRef(rc, kind)
	if !ok {
		return
	}
	pc := b.principal(kind, ref)
	for _, s := range []side{before, after} {
		b.link(pc, rc, s)
	}
}

func (b *planBuilder) inlinePolicy(rc *plan.ResourceChange, kind string) {
	ref, ok := b.ownerRef(rc, kind)
	if !ok {
		return
	}
	pc := b.principal(kind, ref)
	for _, s := range []side{before, after} {
		doc, gap := b.document(rc, s, "policy", model.SourceIdentity, rc.Address)
		switch {
		case gap != "":
			pc.gap(s, "%s", gap)
		case doc != nil:
			pc.add(s, *doc)
		}
	}
}

func (b *planBuilder) role(rc *plan.ResourceChange) {
	pc := b.principal("role", b.resourceRef(rc))
	for _, s := range []side{before, after} {
		m := rc.Side(int(s))
		if m == nil {
			continue
		}
		// inline_policy and managed_policy_arns are optional computed
		// attributes: unknown on every created role whether or not the
		// configuration wrote them. Only a configured one can hide a
		// document.
		if s == after && rc.Unknown("inline_policy") && b.plan.Configured(rc.Address, "inline_policy") {
			pc.gap(s, "%s: inline_policy is not known until apply", rc.Address)
		} else {
			for _, block := range plan.Blocks(m, "inline_policy") {
				name, _ := plan.String(block, "name")
				body, ok := plan.String(block, "policy")
				if !ok || body == "" {
					continue
				}
				if !json.Valid([]byte(body)) {
					pc.gap(s, "%s: inline policy %q is not valid JSON", rc.Address, name)
					continue
				}
				pc.add(s, provider.Document{Kind: model.SourceIdentity, Name: rc.Address + "/" + name, Body: json.RawMessage(body)})
			}
		}

		if boundary, ok := plan.String(m, "permissions_boundary"); ok && boundary != "" {
			b.boundary(pc, rc, s, boundary)
		} else if s == after && rc.Unknown("permissions_boundary") && b.plan.Configured(rc.Address, "permissions_boundary") {
			pc.gap(s, "%s: permissions_boundary is not known until apply", rc.Address)
		}

		if b.plan.Configured(rc.Address, "managed_policy_arns") {
			if s == after && rc.Unknown("managed_policy_arns") {
				pc.gap(s, "%s: managed_policy_arns is not known until apply", rc.Address)
			}
			for _, arn := range plan.Strings(m, "managed_policy_arns") {
				if pp := b.policyByARN(arn, s); pp != nil {
					b.attach(pc, pp, s)
					continue
				}
				pc.gap(s, "%s: managed policy %s is not in the plan; its permissions are not evaluated", rc.Address, arn)
			}
			for _, t := range b.plan.References(rc.Address, "managed_policy_arns") {
				if pp, ok := b.policies[t.Address]; ok {
					b.attach(pc, pp, s)
				}
			}
		}
	}
}

// boundary attaches a permissions boundary. The boundary is a managed
// policy named by ARN; only one created in the same plan has content the
// plan can show.
func (b *planBuilder) boundary(pc *principalChange, rc *plan.ResourceChange, s side, arn string) {
	for _, t := range b.plan.References(rc.Address, "permissions_boundary") {
		if pp, ok := b.policies[t.Address]; ok && pp.docs[s] != nil && pp.docs[s].Body != nil {
			doc := *pp.docs[s]
			doc.Kind = model.SourceBoundary
			pc.add(s, doc)
			pp.linked = true
			return
		}
	}
	if pp := b.policyByARN(arn, s); pp != nil && pp.docs[s] != nil && pp.docs[s].Body != nil {
		doc := *pp.docs[s]
		doc.Kind = model.SourceBoundary
		pc.add(s, doc)
		pp.linked = true
		return
	}
	pc.gap(s, "%s: permissions boundary %s is not in the plan; it is not applied", rc.Address, arn)
}

// scp reads a service control policy as its own principal, so a change
// to what the guardrail permits reads as a widening or narrowing of the
// guardrail itself.
func (b *planBuilder) scp(rc *plan.ResourceChange) {
	for _, s := range []side{before, after} {
		if t, ok := plan.String(rc.Side(int(s)), "type"); ok && t != "" && t != "SERVICE_CONTROL_POLICY" {
			return
		}
	}
	pc := b.principal("scp", b.resourceRef(rc))
	for _, s := range []side{before, after} {
		doc, gap := b.document(rc, s, "content", model.SourceIdentity, rc.Address)
		switch {
		case gap != "":
			pc.gap(s, "%s", gap)
		case doc != nil:
			pc.add(s, *doc)
		}
	}
}

// finish gives every policy nobody attached a principal of its own and
// returns the changes in a stable order.
func (b *planBuilder) finish() []provider.PrincipalChange {
	addresses := make([]string, 0, len(b.policies))
	for addr := range b.policies {
		addresses = append(addresses, addr)
	}
	sort.Strings(addresses)
	for _, addr := range addresses {
		pp := b.policies[addr]
		if pp.linked {
			continue
		}
		pc := b.principal("policy", addr)
		for _, s := range []side{before, after} {
			b.attach(pc, pp, s)
		}
	}

	keys := make([]string, 0, len(b.principals))
	for k := range b.principals {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]provider.PrincipalChange, 0, len(keys))
	for _, k := range keys {
		pc := b.principals[k]
		out = append(out, provider.PrincipalChange{Principal: pc.principal, Before: pc.sides[before], After: pc.sides[after]})
	}
	return out
}

var _ provider.PlanAdapter = (*Provider)(nil)
