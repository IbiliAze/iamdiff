package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// The SDK clients are used through the narrowest interfaces collection
// needs, so tests can stand in fakes and the real clients satisfy them
// without adapters. The paginators accept these same method sets.

type iamAPI interface {
	GetRole(context.Context, *iam.GetRoleInput, ...func(*iam.Options)) (*iam.GetRoleOutput, error)
	GetUser(context.Context, *iam.GetUserInput, ...func(*iam.Options)) (*iam.GetUserOutput, error)
	ListAttachedRolePolicies(context.Context, *iam.ListAttachedRolePoliciesInput, ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error)
	ListRolePolicies(context.Context, *iam.ListRolePoliciesInput, ...func(*iam.Options)) (*iam.ListRolePoliciesOutput, error)
	GetRolePolicy(context.Context, *iam.GetRolePolicyInput, ...func(*iam.Options)) (*iam.GetRolePolicyOutput, error)
	ListAttachedUserPolicies(context.Context, *iam.ListAttachedUserPoliciesInput, ...func(*iam.Options)) (*iam.ListAttachedUserPoliciesOutput, error)
	ListUserPolicies(context.Context, *iam.ListUserPoliciesInput, ...func(*iam.Options)) (*iam.ListUserPoliciesOutput, error)
	GetUserPolicy(context.Context, *iam.GetUserPolicyInput, ...func(*iam.Options)) (*iam.GetUserPolicyOutput, error)
	ListGroupsForUser(context.Context, *iam.ListGroupsForUserInput, ...func(*iam.Options)) (*iam.ListGroupsForUserOutput, error)
	ListAttachedGroupPolicies(context.Context, *iam.ListAttachedGroupPoliciesInput, ...func(*iam.Options)) (*iam.ListAttachedGroupPoliciesOutput, error)
	ListGroupPolicies(context.Context, *iam.ListGroupPoliciesInput, ...func(*iam.Options)) (*iam.ListGroupPoliciesOutput, error)
	GetGroupPolicy(context.Context, *iam.GetGroupPolicyInput, ...func(*iam.Options)) (*iam.GetGroupPolicyOutput, error)
	GetPolicy(context.Context, *iam.GetPolicyInput, ...func(*iam.Options)) (*iam.GetPolicyOutput, error)
	GetPolicyVersion(context.Context, *iam.GetPolicyVersionInput, ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error)
}

type orgAPI interface {
	DescribeOrganization(context.Context, *organizations.DescribeOrganizationInput, ...func(*organizations.Options)) (*organizations.DescribeOrganizationOutput, error)
	ListRoots(context.Context, *organizations.ListRootsInput, ...func(*organizations.Options)) (*organizations.ListRootsOutput, error)
	ListParents(context.Context, *organizations.ListParentsInput, ...func(*organizations.Options)) (*organizations.ListParentsOutput, error)
	ListPoliciesForTarget(context.Context, *organizations.ListPoliciesForTargetInput, ...func(*organizations.Options)) (*organizations.ListPoliciesForTargetOutput, error)
	DescribePolicy(context.Context, *organizations.DescribePolicyInput, ...func(*organizations.Options)) (*organizations.DescribePolicyOutput, error)
}

type stsAPI interface {
	GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

type clients struct {
	iam iamAPI
	org orgAPI
	sts stsAPI
}

// newClients builds real clients from the default credential chain. IAM
// and Organizations are global services; a region is still needed to
// sign requests, so one is supplied when the environment has none.
func (p *Provider) newClients(ctx context.Context) (clients, error) {
	opts := []func(*config.LoadOptions) error{config.WithDefaultRegion("us-east-1")}
	if p.cfg.Profile != "" {
		opts = append(opts, config.WithSharedConfigProfile(p.cfg.Profile))
	}
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return clients{}, fmt.Errorf("aws: load credentials: %w", err)
	}
	return clients{
		iam: iam.NewFromConfig(cfg),
		org: organizations.NewFromConfig(cfg),
		sts: sts.NewFromConfig(cfg),
	}, nil
}
