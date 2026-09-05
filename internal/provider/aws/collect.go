package aws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"

	"github.com/IbiliAze/iamdiff/internal/model"
	"github.com/IbiliAze/iamdiff/internal/provider"
)

// Collect gathers everything that decides one principal's effective
// permissions: identity policies (attached, inline and, for users, via
// groups), the permissions boundary, and the service control policies at
// every level of the organisation above the account.
//
// The principal itself must be readable, or there is nothing to say.
// Every other source that cannot be read becomes a gap, so the result is
// partial rather than confidently incomplete (ADR-0003).
func (p *Provider) Collect(ctx context.Context, sel provider.Selector) (*provider.RawSet, error) {
	if len(sel.Refs) != 1 {
		return nil, fmt.Errorf("aws: collect takes exactly one principal, got %d", len(sel.Refs))
	}
	c, err := p.newClients(ctx)
	if err != nil {
		return nil, err
	}
	return collect(ctx, c, sel.Refs[0])
}

func collect(ctx context.Context, c clients, ref string) (*provider.RawSet, error) {
	ident, err := c.sts.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, fmt.Errorf("aws: sts:GetCallerIdentity: %w", err)
	}
	account := aws.ToString(ident.Account)
	pr, err := parsePrincipal(ref, account, partitionOf(aws.ToString(ident.Arn)))
	if err != nil {
		return nil, err
	}

	raw := &provider.RawSet{Principal: model.Principal{Provider: Name, Kind: pr.Kind, Ref: pr.ARN}}
	switch pr.Kind {
	case "role":
		err = collectRole(ctx, c.iam, pr.Name, raw)
	case "user":
		err = collectUser(ctx, c.iam, pr.Name, raw)
	}
	if err != nil {
		return nil, err
	}
	collectSCPs(ctx, c.org, account, raw)
	return raw, nil
}

func gap(raw *provider.RawSet, format string, args ...any) {
	raw.Gaps = append(raw.Gaps, fmt.Sprintf(format, args...))
}

// reason renders an API error the way a reader wants it: the error code
// when there is one, the message otherwise.
func reason(err error) string {
	var ae smithy.APIError
	if errors.As(err, &ae) {
		return ae.ErrorCode()
	}
	return err.Error()
}

func collectRole(ctx context.Context, api iamAPI, name string, raw *provider.RawSet) error {
	out, err := api.GetRole(ctx, &iam.GetRoleInput{RoleName: aws.String(name)})
	if err != nil {
		return fmt.Errorf("aws: iam:GetRole %s: %w", name, err)
	}
	// The trust policy says who may assume the role, not what the role
	// may do; it is deliberately not part of the effective set.
	if b := out.Role.PermissionsBoundary; b != nil && b.PermissionsBoundaryArn != nil {
		addManagedPolicy(ctx, api, raw, aws.ToString(b.PermissionsBoundaryArn), model.SourceBoundary)
	}

	attached := iam.NewListAttachedRolePoliciesPaginator(api, &iam.ListAttachedRolePoliciesInput{RoleName: aws.String(name)})
	for attached.HasMorePages() {
		page, err := attached.NextPage(ctx)
		if err != nil {
			gap(raw, "iam:ListAttachedRolePolicies %s: %s - attached policies not evaluated", name, reason(err))
			break
		}
		for _, ap := range page.AttachedPolicies {
			addManagedPolicy(ctx, api, raw, aws.ToString(ap.PolicyArn), model.SourceIdentity)
		}
	}

	inline := iam.NewListRolePoliciesPaginator(api, &iam.ListRolePoliciesInput{RoleName: aws.String(name)})
	for inline.HasMorePages() {
		page, err := inline.NextPage(ctx)
		if err != nil {
			gap(raw, "iam:ListRolePolicies %s: %s - inline policies not evaluated", name, reason(err))
			break
		}
		for _, policyName := range page.PolicyNames {
			doc, err := api.GetRolePolicy(ctx, &iam.GetRolePolicyInput{RoleName: aws.String(name), PolicyName: aws.String(policyName)})
			if err != nil {
				gap(raw, "iam:GetRolePolicy %s/%s: %s - policy not evaluated", name, policyName, reason(err))
				continue
			}
			addDocument(raw, model.SourceIdentity, policyName, aws.ToString(doc.PolicyDocument))
		}
	}
	return nil
}

func collectUser(ctx context.Context, api iamAPI, name string, raw *provider.RawSet) error {
	out, err := api.GetUser(ctx, &iam.GetUserInput{UserName: aws.String(name)})
	if err != nil {
		return fmt.Errorf("aws: iam:GetUser %s: %w", name, err)
	}
	if b := out.User.PermissionsBoundary; b != nil && b.PermissionsBoundaryArn != nil {
		addManagedPolicy(ctx, api, raw, aws.ToString(b.PermissionsBoundaryArn), model.SourceBoundary)
	}

	attached := iam.NewListAttachedUserPoliciesPaginator(api, &iam.ListAttachedUserPoliciesInput{UserName: aws.String(name)})
	for attached.HasMorePages() {
		page, err := attached.NextPage(ctx)
		if err != nil {
			gap(raw, "iam:ListAttachedUserPolicies %s: %s - attached policies not evaluated", name, reason(err))
			break
		}
		for _, ap := range page.AttachedPolicies {
			addManagedPolicy(ctx, api, raw, aws.ToString(ap.PolicyArn), model.SourceIdentity)
		}
	}

	inline := iam.NewListUserPoliciesPaginator(api, &iam.ListUserPoliciesInput{UserName: aws.String(name)})
	for inline.HasMorePages() {
		page, err := inline.NextPage(ctx)
		if err != nil {
			gap(raw, "iam:ListUserPolicies %s: %s - inline policies not evaluated", name, reason(err))
			break
		}
		for _, policyName := range page.PolicyNames {
			doc, err := api.GetUserPolicy(ctx, &iam.GetUserPolicyInput{UserName: aws.String(name), PolicyName: aws.String(policyName)})
			if err != nil {
				gap(raw, "iam:GetUserPolicy %s/%s: %s - policy not evaluated", name, policyName, reason(err))
				continue
			}
			addDocument(raw, model.SourceIdentity, policyName, aws.ToString(doc.PolicyDocument))
		}
	}

	groups := iam.NewListGroupsForUserPaginator(api, &iam.ListGroupsForUserInput{UserName: aws.String(name)})
	for groups.HasMorePages() {
		page, err := groups.NextPage(ctx)
		if err != nil {
			gap(raw, "iam:ListGroupsForUser %s: %s - group policies not evaluated", name, reason(err))
			break
		}
		for _, g := range page.Groups {
			collectGroup(ctx, api, aws.ToString(g.GroupName), raw)
		}
	}
	return nil
}

func collectGroup(ctx context.Context, api iamAPI, group string, raw *provider.RawSet) {
	attached := iam.NewListAttachedGroupPoliciesPaginator(api, &iam.ListAttachedGroupPoliciesInput{GroupName: aws.String(group)})
	for attached.HasMorePages() {
		page, err := attached.NextPage(ctx)
		if err != nil {
			gap(raw, "iam:ListAttachedGroupPolicies %s: %s - attached policies not evaluated", group, reason(err))
			break
		}
		for _, ap := range page.AttachedPolicies {
			addManagedPolicy(ctx, api, raw, aws.ToString(ap.PolicyArn), model.SourceGroup)
		}
	}
	inline := iam.NewListGroupPoliciesPaginator(api, &iam.ListGroupPoliciesInput{GroupName: aws.String(group)})
	for inline.HasMorePages() {
		page, err := inline.NextPage(ctx)
		if err != nil {
			gap(raw, "iam:ListGroupPolicies %s: %s - inline policies not evaluated", group, reason(err))
			break
		}
		for _, policyName := range page.PolicyNames {
			doc, err := api.GetGroupPolicy(ctx, &iam.GetGroupPolicyInput{GroupName: aws.String(group), PolicyName: aws.String(policyName)})
			if err != nil {
				gap(raw, "iam:GetGroupPolicy %s/%s: %s - policy not evaluated", group, policyName, reason(err))
				continue
			}
			addDocument(raw, model.SourceGroup, group+"/"+policyName, aws.ToString(doc.PolicyDocument))
		}
	}
}

// addManagedPolicy fetches the default version of a managed policy.
func addManagedPolicy(ctx context.Context, api iamAPI, raw *provider.RawSet, policyARN string, kind model.SourceKind) {
	pol, err := api.GetPolicy(ctx, &iam.GetPolicyInput{PolicyArn: aws.String(policyARN)})
	if err != nil {
		gap(raw, "iam:GetPolicy %s: %s - %s policy not evaluated", policyARN, reason(err), kind)
		return
	}
	ver, err := api.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{PolicyArn: aws.String(policyARN), VersionId: pol.Policy.DefaultVersionId})
	if err != nil {
		gap(raw, "iam:GetPolicyVersion %s: %s - %s policy not evaluated", policyARN, reason(err), kind)
		return
	}
	name := aws.ToString(pol.Policy.PolicyName)
	if name == "" {
		name = policyARN
	}
	addDocument(raw, kind, name, aws.ToString(ver.PolicyVersion.Document))
}

// addDocument decodes a policy document as the IAM API returns it. The
// documents are percent-encoded per RFC 3986 and the SDK does not decode
// them; PathUnescape is the right inverse because '+' is a literal plus,
// not a space.
func addDocument(raw *provider.RawSet, kind model.SourceKind, name, encoded string) {
	body, err := url.PathUnescape(encoded)
	if err != nil {
		gap(raw, "policy %s: cannot decode document: %v", name, err)
		return
	}
	if !json.Valid([]byte(body)) {
		gap(raw, "policy %s: document is not valid JSON", name)
		return
	}
	raw.Documents = append(raw.Documents, provider.Document{Kind: kind, Name: name, Body: json.RawMessage(body)})
}
