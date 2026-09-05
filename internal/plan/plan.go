// Package plan reads the machine-readable form of an infrastructure plan,
// as written by "terraform show -json". It is cloud-neutral: it knows the
// shape of a plan, not what any resource means. A provider's PlanAdapter
// decides which resources carry policy and how they group into
// principals.
package plan

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Plan is the parts of a plan file this tool reads.
type Plan struct {
	FormatVersion    string           `json:"format_version"`
	TerraformVersion string           `json:"terraform_version,omitempty"`
	ResourceChanges  []ResourceChange `json:"resource_changes"`
	Configuration    *Configuration   `json:"configuration,omitempty"`

	byAddress map[string][]*ResourceChange // instance address without its own index -> instances
}

// ResourceChange is one resource instance and what the plan does to it.
type ResourceChange struct {
	Address       string `json:"address"`
	ModuleAddress string `json:"module_address,omitempty"`
	Mode          string `json:"mode"`
	Type          string `json:"type"`
	Name          string `json:"name"`
	Index         any    `json:"index,omitempty"`
	Change        Change `json:"change"`
}

// Change is the before and after of a resource. After is incomplete when
// values are unknown until apply; AfterUnknown marks those leaves true.
type Change struct {
	Actions      []string       `json:"actions"`
	Before       map[string]any `json:"before"`
	After        map[string]any `json:"after"`
	AfterUnknown map[string]any `json:"after_unknown"`
}

// Configuration is the source configuration behind the plan, kept for
// the references between resources that resolved values lose.
type Configuration struct {
	RootModule Module `json:"root_module"`
}

type Module struct {
	Resources   []ConfigResource      `json:"resources,omitempty"`
	ModuleCalls map[string]ModuleCall `json:"module_calls,omitempty"`
}

type ConfigResource struct {
	Address     string                     `json:"address"`
	Mode        string                     `json:"mode"`
	Type        string                     `json:"type"`
	Name        string                     `json:"name"`
	Expressions map[string]json.RawMessage `json:"expressions,omitempty"`
}

type ModuleCall struct {
	Source string `json:"source"`
	Module Module `json:"module"`
}

// Parse reads a plan file.
func Parse(b []byte) (*Plan, error) {
	var p Plan
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("plan: parse: %w", err)
	}
	if p.FormatVersion == "" {
		return nil, fmt.Errorf("plan: no format_version; is this the output of \"terraform show -json\"?")
	}
	if major, _, _ := strings.Cut(p.FormatVersion, "."); major != "1" {
		return nil, fmt.Errorf("plan: format_version %s is not supported (want 1.x)", p.FormatVersion)
	}
	p.byAddress = map[string][]*ResourceChange{}
	for i := range p.ResourceChanges {
		rc := &p.ResourceChanges[i]
		p.byAddress[stripLastIndex(rc.Address)] = append(p.byAddress[stripLastIndex(rc.Address)], rc)
	}
	return &p, nil
}

// Has reports whether the plan takes the given action on the resource.
func (rc *ResourceChange) Has(action string) bool {
	for _, a := range rc.Change.Actions {
		if a == action {
			return true
		}
	}
	return false
}

// Side returns the before (0) or after (1) object; nil when the resource
// does not exist on that side.
func (rc *ResourceChange) Side(after int) map[string]any {
	if after == 0 {
		return rc.Change.Before
	}
	return rc.Change.After
}

// Exists reports whether the resource exists before and after the plan.
func (rc *ResourceChange) Exists() (before, after bool) {
	return rc.Change.Before != nil, rc.Change.After != nil
}

// Unknown reports whether any part of an attribute's value is not known
// until apply. A nested block with one unknown leaf counts as unknown:
// the tool cannot see what it grants.
func (rc *ResourceChange) Unknown(attr string) bool {
	v, ok := rc.Change.AfterUnknown[attr]
	return ok && containsTrue(v)
}

func containsTrue(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case []any:
		for _, e := range x {
			if containsTrue(e) {
				return true
			}
		}
	case map[string]any:
		for _, e := range x {
			if containsTrue(e) {
				return true
			}
		}
	}
	return false
}

// String returns an attribute as a string from the before or after
// object, and whether it was present as a string.
func String(m map[string]any, attr string) (string, bool) {
	if m == nil {
		return "", false
	}
	s, ok := m[attr].(string)
	return s, ok
}

// Strings returns an attribute that is a list of strings.
func Strings(m map[string]any, attr string) []string {
	if m == nil {
		return nil
	}
	list, ok := m[attr].([]any)
	if !ok {
		return nil
	}
	var out []string
	for _, e := range list {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// Blocks returns a nested block attribute as a list of objects.
func Blocks(m map[string]any, attr string) []map[string]any {
	if m == nil {
		return nil
	}
	switch v := m[attr].(type) {
	case []any:
		var out []map[string]any
		for _, e := range v {
			if o, ok := e.(map[string]any); ok {
				out = append(out, o)
			}
		}
		return out
	case map[string]any:
		return []map[string]any{v}
	}
	return nil
}

// Instances returns every instance of a resource, by its address without
// an instance index.
func (p *Plan) Instances(address string) []*ResourceChange {
	return p.byAddress[stripLastIndex(address)]
}

// References returns the resource instances an attribute of one resource
// instance refers to, resolved through the configuration. Resolved values
// lose this: an attachment's policy_arn is unknown until apply when the
// policy is created in the same plan, but the configuration still says
// which policy. References through variables and module outputs are not
// followed.
func (p *Plan) References(address, attr string) []*ResourceChange {
	if p.Configuration == nil {
		return nil
	}
	res, moduleAddr := p.configResource(address)
	if res == nil {
		return nil
	}
	expr, ok := res.Expressions[attr]
	if !ok {
		return nil
	}
	seen := map[string]bool{}
	var out []*ResourceChange
	for _, ref := range collectReferences(expr) {
		target := resourceReference(ref)
		if target == "" {
			continue
		}
		if moduleAddr != "" {
			target = moduleAddr + "." + target
		}
		if seen[target] {
			continue
		}
		seen[target] = true
		out = append(out, p.byAddress[target]...)
	}
	return out
}

// Configured reports whether the configuration sets an attribute on the
// resource. Optional computed attributes are unknown until apply whether
// or not anyone wrote them; only the ones actually configured can hide a
// value the tool needs.
func (p *Plan) Configured(address, attr string) bool {
	if p.Configuration == nil {
		return false
	}
	res, _ := p.configResource(address)
	if res == nil {
		return false
	}
	expr, ok := res.Expressions[attr]
	return ok && string(expr) != "null"
}

// configResource finds the configuration block behind a resource
// instance address, along with the instance's module address.
func (p *Plan) configResource(address string) (*ConfigResource, string) {
	tokens := splitAddress(address)
	mod := &p.Configuration.RootModule
	var modulePath []string
	for len(tokens) >= 2 && tokens[0].name == "module" {
		call, ok := mod.ModuleCalls[tokens[1].name]
		if !ok {
			return nil, ""
		}
		mod = &call.Module
		modulePath = append(modulePath, "module."+tokens[1].name+tokens[1].index)
		tokens = tokens[2:]
	}
	var want string
	switch {
	case len(tokens) == 3 && tokens[0].name == "data":
		want = "data." + tokens[1].name + "." + tokens[2].name
	case len(tokens) == 2:
		want = tokens[0].name + "." + tokens[1].name
	default:
		return nil, ""
	}
	for i := range mod.Resources {
		if mod.Resources[i].Address == want {
			return &mod.Resources[i], strings.Join(modulePath, ".")
		}
	}
	return nil, ""
}

// collectReferences gathers every "references" entry under an expression,
// including those inside nested blocks.
func collectReferences(raw json.RawMessage) []string {
	var out []string
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			if refs, ok := x["references"].([]any); ok {
				for _, r := range refs {
					if s, ok := r.(string); ok {
						out = append(out, s)
					}
				}
			}
			for k, e := range x {
				if k != "references" && k != "constant_value" {
					walk(e)
				}
			}
		case []any:
			for _, e := range x {
				walk(e)
			}
		}
	}
	var v any
	if err := json.Unmarshal(raw, &v); err == nil {
		walk(v)
	}
	return out
}

// resourceReference reduces a reference such as "aws_iam_policy.x.arn" or
// "aws_iam_policy.x[0]" to the resource address "aws_iam_policy.x", or ""
// when the reference is not to a managed resource in the same module.
func resourceReference(ref string) string {
	tokens := splitAddress(ref)
	if len(tokens) < 2 {
		return ""
	}
	switch tokens[0].name {
	case "var", "local", "module", "data", "each", "count", "path", "terraform", "self":
		return ""
	}
	return tokens[0].name + "." + tokens[1].name
}

type token struct {
	name  string
	index string // "[0]" or "[\"key\"]" if present
}

// splitAddress splits a resource address on dots, keeping bracketed
// index keys, which may themselves contain dots, with their token.
func splitAddress(addr string) []token {
	var out []token
	var cur strings.Builder
	var idx strings.Builder
	inIndex, inQuote := false, false
	flush := func() {
		if cur.Len() > 0 || idx.Len() > 0 {
			out = append(out, token{name: cur.String(), index: idx.String()})
		}
		cur.Reset()
		idx.Reset()
	}
	for i := 0; i < len(addr); i++ {
		c := addr[i]
		switch {
		case inIndex:
			idx.WriteByte(c)
			if c == '"' {
				inQuote = !inQuote
			} else if c == ']' && !inQuote {
				inIndex = false
			}
		case c == '[':
			inIndex = true
			idx.WriteByte(c)
		case c == '.':
			flush()
		default:
			cur.WriteByte(c)
		}
	}
	flush()
	return out
}

// stripLastIndex removes the trailing instance index of an address:
// module.svc["a"].aws_iam_role.x[0] becomes module.svc["a"].aws_iam_role.x.
func stripLastIndex(addr string) string {
	tokens := splitAddress(addr)
	if len(tokens) == 0 {
		return addr
	}
	var parts []string
	for i, t := range tokens {
		if i == len(tokens)-1 {
			parts = append(parts, t.name)
		} else {
			parts = append(parts, t.name+t.index)
		}
	}
	return strings.Join(parts, ".")
}
