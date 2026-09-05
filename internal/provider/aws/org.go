package aws

import (
	"context"
	"errors"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/organizations/types"

	"github.com/IbiliAze/iamdiff/internal/model"
	"github.com/IbiliAze/iamdiff/internal/provider"
)

// collectSCPs reads the service control policies that apply to an
// account: those attached to the root, to every organisational unit on
// the path down, and to the account itself. Each attachment point is a
// layer of its own (ADR-0004).
//
// Organizations answers these calls only from the management account or
// a delegated administrator. Anywhere else they are denied, and the
// denial is recorded as a gap rather than raised as an error: the
// identity policies are still worth diffing, as long as the result says
// it is partial. An account outside any organisation has no guardrails
// and no gap.
func collectSCPs(ctx context.Context, api orgAPI, account string, raw *provider.RawSet) {
	if _, err := api.DescribeOrganization(ctx, &organizations.DescribeOrganizationInput{}); err != nil {
		var notInUse *types.AWSOrganizationsNotInUseException
		if errors.As(err, &notInUse) {
			return
		}
		gap(raw, "organizations:DescribeOrganization: %s - SCPs not evaluated", reason(err))
		return
	}

	roots, err := api.ListRoots(ctx, &organizations.ListRootsInput{})
	if err != nil {
		gap(raw, "organizations:ListRoots: %s - SCPs not evaluated", reason(err))
		return
	}
	enabled := false
	for _, r := range roots.Roots {
		for _, pt := range r.PolicyTypes {
			if pt.Type == types.PolicyTypeServiceControlPolicy && pt.Status == types.PolicyTypeStatusEnabled {
				enabled = true
			}
		}
	}
	if !enabled {
		// SCPs are not enforced in this organisation; there is no layer
		// to read and nothing missing.
		return
	}

	chain, err := parentChain(ctx, api, account)
	if err != nil {
		gap(raw, "organizations:ListParents %s: %s - SCPs not evaluated", account, reason(err))
		return
	}

	for i, target := range chain {
		pages := organizations.NewListPoliciesForTargetPaginator(api, &organizations.ListPoliciesForTargetInput{
			TargetId: aws.String(target),
			Filter:   types.PolicyTypeServiceControlPolicy,
		})
		for pages.HasMorePages() {
			page, err := pages.NextPage(ctx)
			if err != nil {
				gap(raw, "organizations:ListPoliciesForTarget %s: %s - SCPs at this level not evaluated", target, reason(err))
				break
			}
			for _, summary := range page.Policies {
				pol, err := api.DescribePolicy(ctx, &organizations.DescribePolicyInput{PolicyId: summary.Id})
				if err != nil {
					gap(raw, "organizations:DescribePolicy %s: %s - SCP not evaluated", aws.ToString(summary.Name), reason(err))
					continue
				}
				raw.Documents = append(raw.Documents, provider.Document{
					Kind:      model.SourceGuardrail,
					Name:      aws.ToString(summary.Name),
					Body:      []byte(aws.ToString(pol.Policy.Content)),
					Target:    target,
					Inherited: append([]string(nil), chain[:i+1]...),
				})
			}
		}
	}
}

// parentChain walks from the account up to the root and returns the
// path from the root down to the account.
func parentChain(ctx context.Context, api orgAPI, account string) ([]string, error) {
	chain := []string{account}
	child := account
	for range 64 { // an organisation nests at most five OUs deep
		out, err := api.ListParents(ctx, &organizations.ListParentsInput{ChildId: aws.String(child)})
		if err != nil {
			return nil, err
		}
		if len(out.Parents) == 0 {
			break
		}
		parent := out.Parents[0]
		chain = append([]string{aws.ToString(parent.Id)}, chain...)
		if parent.Type == types.ParentTypeRoot {
			break
		}
		child = aws.ToString(parent.Id)
	}
	return chain, nil
}
