package aws

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"

	"github.com/IbiliAze/iamdiff/internal/model"
	"github.com/IbiliAze/iamdiff/internal/provider"
)

func denied(op string) error {
	return &smithy.GenericAPIError{Code: "AccessDenied", Message: "not authorized to perform " + op}
}

const (
	account    = "123456789012"
	readS3     = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`
	passRole   = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:PassRole","Resource":"*"}]}`
	fullAccess = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`
	denyIAM    = `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"iam:*","Resource":"*"}]}`
)

func encoded(doc string) *string { return aws.String(url.PathEscape(doc)) }

// fakeIAM answers from maps; deny lists operations that return
// AccessDenied.
type fakeIAM struct {
	roles    map[string]iamtypes.Role
	users    map[string]iamtypes.User
	attached map[string][]string          // "role/NAME" -> policy ARNs
	inline   map[string]map[string]string // "role/NAME" -> policy name -> document
	groups   map[string][]string          // user -> groups
	policies map[string]string            // policy ARN -> default document
	deny     map[string]bool
}

func (f *fakeIAM) check(op string) error {
	if f.deny[op] {
		return denied(op)
	}
	return nil
}

func (f *fakeIAM) GetRole(_ context.Context, in *iam.GetRoleInput, _ ...func(*iam.Options)) (*iam.GetRoleOutput, error) {
	if err := f.check("GetRole"); err != nil {
		return nil, err
	}
	r, ok := f.roles[*in.RoleName]
	if !ok {
		return nil, &smithy.GenericAPIError{Code: "NoSuchEntity"}
	}
	return &iam.GetRoleOutput{Role: &r}, nil
}

func (f *fakeIAM) GetUser(_ context.Context, in *iam.GetUserInput, _ ...func(*iam.Options)) (*iam.GetUserOutput, error) {
	u, ok := f.users[*in.UserName]
	if !ok {
		return nil, &smithy.GenericAPIError{Code: "NoSuchEntity"}
	}
	return &iam.GetUserOutput{User: &u}, nil
}

func (f *fakeIAM) attachedFor(key string) []iamtypes.AttachedPolicy {
	var out []iamtypes.AttachedPolicy
	for _, arn := range f.attached[key] {
		out = append(out, iamtypes.AttachedPolicy{PolicyArn: aws.String(arn), PolicyName: aws.String(arn[strings.LastIndex(arn, "/")+1:])})
	}
	return out
}

func (f *fakeIAM) inlineNames(key string) []string {
	var out []string
	for name := range f.inline[key] {
		out = append(out, name)
	}
	return out
}

func (f *fakeIAM) ListAttachedRolePolicies(_ context.Context, in *iam.ListAttachedRolePoliciesInput, _ ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error) {
	if err := f.check("ListAttachedRolePolicies"); err != nil {
		return nil, err
	}
	return &iam.ListAttachedRolePoliciesOutput{AttachedPolicies: f.attachedFor("role/" + *in.RoleName)}, nil
}

func (f *fakeIAM) ListRolePolicies(_ context.Context, in *iam.ListRolePoliciesInput, _ ...func(*iam.Options)) (*iam.ListRolePoliciesOutput, error) {
	return &iam.ListRolePoliciesOutput{PolicyNames: f.inlineNames("role/" + *in.RoleName)}, nil
}

func (f *fakeIAM) GetRolePolicy(_ context.Context, in *iam.GetRolePolicyInput, _ ...func(*iam.Options)) (*iam.GetRolePolicyOutput, error) {
	return &iam.GetRolePolicyOutput{PolicyDocument: encoded(f.inline["role/"+*in.RoleName][*in.PolicyName])}, nil
}

func (f *fakeIAM) ListAttachedUserPolicies(_ context.Context, in *iam.ListAttachedUserPoliciesInput, _ ...func(*iam.Options)) (*iam.ListAttachedUserPoliciesOutput, error) {
	return &iam.ListAttachedUserPoliciesOutput{AttachedPolicies: f.attachedFor("user/" + *in.UserName)}, nil
}

func (f *fakeIAM) ListUserPolicies(_ context.Context, in *iam.ListUserPoliciesInput, _ ...func(*iam.Options)) (*iam.ListUserPoliciesOutput, error) {
	return &iam.ListUserPoliciesOutput{PolicyNames: f.inlineNames("user/" + *in.UserName)}, nil
}

func (f *fakeIAM) GetUserPolicy(_ context.Context, in *iam.GetUserPolicyInput, _ ...func(*iam.Options)) (*iam.GetUserPolicyOutput, error) {
	return &iam.GetUserPolicyOutput{PolicyDocument: encoded(f.inline["user/"+*in.UserName][*in.PolicyName])}, nil
}

func (f *fakeIAM) ListGroupsForUser(_ context.Context, in *iam.ListGroupsForUserInput, _ ...func(*iam.Options)) (*iam.ListGroupsForUserOutput, error) {
	var groups []iamtypes.Group
	for _, g := range f.groups[*in.UserName] {
		groups = append(groups, iamtypes.Group{GroupName: aws.String(g)})
	}
	return &iam.ListGroupsForUserOutput{Groups: groups}, nil
}

func (f *fakeIAM) ListAttachedGroupPolicies(_ context.Context, in *iam.ListAttachedGroupPoliciesInput, _ ...func(*iam.Options)) (*iam.ListAttachedGroupPoliciesOutput, error) {
	return &iam.ListAttachedGroupPoliciesOutput{AttachedPolicies: f.attachedFor("group/" + *in.GroupName)}, nil
}

func (f *fakeIAM) ListGroupPolicies(_ context.Context, in *iam.ListGroupPoliciesInput, _ ...func(*iam.Options)) (*iam.ListGroupPoliciesOutput, error) {
	return &iam.ListGroupPoliciesOutput{PolicyNames: f.inlineNames("group/" + *in.GroupName)}, nil
}

func (f *fakeIAM) GetGroupPolicy(_ context.Context, in *iam.GetGroupPolicyInput, _ ...func(*iam.Options)) (*iam.GetGroupPolicyOutput, error) {
	return &iam.GetGroupPolicyOutput{PolicyDocument: encoded(f.inline["group/"+*in.GroupName][*in.PolicyName])}, nil
}

func (f *fakeIAM) GetPolicy(_ context.Context, in *iam.GetPolicyInput, _ ...func(*iam.Options)) (*iam.GetPolicyOutput, error) {
	if err := f.check("GetPolicy"); err != nil {
		return nil, err
	}
	if _, ok := f.policies[*in.PolicyArn]; !ok {
		return nil, &smithy.GenericAPIError{Code: "NoSuchEntity"}
	}
	arn := *in.PolicyArn
	return &iam.GetPolicyOutput{Policy: &iamtypes.Policy{
		Arn:              in.PolicyArn,
		PolicyName:       aws.String(arn[strings.LastIndex(arn, "/")+1:]),
		DefaultVersionId: aws.String("v3"),
	}}, nil
}

func (f *fakeIAM) GetPolicyVersion(_ context.Context, in *iam.GetPolicyVersionInput, _ ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error) {
	if *in.VersionId != "v3" {
		return nil, &smithy.GenericAPIError{Code: "NoSuchEntity", Message: "wrong version"}
	}
	return &iam.GetPolicyVersionOutput{PolicyVersion: &iamtypes.PolicyVersion{Document: encoded(f.policies[*in.PolicyArn])}}, nil
}

type fakeOrg struct {
	notInUse   bool
	scpEnabled bool
	parents    map[string]orgtypes.Parent // child -> parent
	attached   map[string][]string        // target -> policy ids
	policies   map[string][2]string       // id -> {name, content}
	deny       map[string]bool
}

func (f *fakeOrg) check(op string) error {
	if f.deny[op] {
		return denied(op)
	}
	return nil
}

func (f *fakeOrg) DescribeOrganization(context.Context, *organizations.DescribeOrganizationInput, ...func(*organizations.Options)) (*organizations.DescribeOrganizationOutput, error) {
	if f.notInUse {
		return nil, &orgtypes.AWSOrganizationsNotInUseException{Message: aws.String("not a member")}
	}
	if err := f.check("DescribeOrganization"); err != nil {
		return nil, err
	}
	return &organizations.DescribeOrganizationOutput{Organization: &orgtypes.Organization{Id: aws.String("o-x")}}, nil
}

func (f *fakeOrg) ListRoots(context.Context, *organizations.ListRootsInput, ...func(*organizations.Options)) (*organizations.ListRootsOutput, error) {
	if err := f.check("ListRoots"); err != nil {
		return nil, err
	}
	status := orgtypes.PolicyTypeStatusPendingDisable
	if f.scpEnabled {
		status = orgtypes.PolicyTypeStatusEnabled
	}
	return &organizations.ListRootsOutput{Roots: []orgtypes.Root{{
		Id:          aws.String("r-root"),
		PolicyTypes: []orgtypes.PolicyTypeSummary{{Type: orgtypes.PolicyTypeServiceControlPolicy, Status: status}},
	}}}, nil
}

func (f *fakeOrg) ListParents(_ context.Context, in *organizations.ListParentsInput, _ ...func(*organizations.Options)) (*organizations.ListParentsOutput, error) {
	if err := f.check("ListParents"); err != nil {
		return nil, err
	}
	p, ok := f.parents[*in.ChildId]
	if !ok {
		return &organizations.ListParentsOutput{}, nil
	}
	return &organizations.ListParentsOutput{Parents: []orgtypes.Parent{p}}, nil
}

func (f *fakeOrg) ListPoliciesForTarget(_ context.Context, in *organizations.ListPoliciesForTargetInput, _ ...func(*organizations.Options)) (*organizations.ListPoliciesForTargetOutput, error) {
	if err := f.check("ListPoliciesForTarget"); err != nil {
		return nil, err
	}
	var out []orgtypes.PolicySummary
	for _, id := range f.attached[*in.TargetId] {
		out = append(out, orgtypes.PolicySummary{Id: aws.String(id), Name: aws.String(f.policies[id][0])})
	}
	return &organizations.ListPoliciesForTargetOutput{Policies: out}, nil
}

func (f *fakeOrg) DescribePolicy(_ context.Context, in *organizations.DescribePolicyInput, _ ...func(*organizations.Options)) (*organizations.DescribePolicyOutput, error) {
	if err := f.check("DescribePolicy"); err != nil {
		return nil, err
	}
	p := f.policies[*in.PolicyId]
	return &organizations.DescribePolicyOutput{Policy: &orgtypes.Policy{Content: aws.String(p[1]), PolicySummary: &orgtypes.PolicySummary{Id: in.PolicyId, Name: aws.String(p[0])}}}, nil
}

type fakeSTS struct{}

func (fakeSTS) GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	return &sts.GetCallerIdentityOutput{Account: aws.String(account), Arn: aws.String("arn:aws:iam::" + account + ":user/ci")}, nil
}

func fixtureIAM() *fakeIAM {
	return &fakeIAM{
		roles: map[string]iamtypes.Role{
			"deploy": {
				RoleName:                 aws.String("deploy"),
				AssumeRolePolicyDocument: encoded(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}`),
				PermissionsBoundary:      &iamtypes.AttachedPermissionsBoundary{PermissionsBoundaryArn: aws.String("arn:aws:iam::" + account + ":policy/boundary")},
			},
			"plain": {RoleName: aws.String("plain")},
		},
		users: map[string]iamtypes.User{"ci": {UserName: aws.String("ci")}},
		attached: map[string][]string{
			"role/deploy": {"arn:aws:iam::" + account + ":policy/deploy-managed"},
			"group/devs":  {"arn:aws:iam::aws:policy/ReadOnlyAccess"},
		},
		inline: map[string]map[string]string{
			"role/deploy": {"extra": passRole},
			"user/ci":     {"own": readS3},
			"group/devs":  {"shared": passRole},
		},
		groups: map[string][]string{"ci": {"devs"}},
		policies: map[string]string{
			"arn:aws:iam::" + account + ":policy/deploy-managed": readS3,
			"arn:aws:iam::" + account + ":policy/boundary":       fullAccess,
			"arn:aws:iam::aws:policy/ReadOnlyAccess":             readS3,
		},
		deny: map[string]bool{},
	}
}

func fixtureOrg() *fakeOrg {
	return &fakeOrg{
		scpEnabled: true,
		parents: map[string]orgtypes.Parent{
			account:   {Id: aws.String("ou-prod"), Type: orgtypes.ParentTypeOrganizationalUnit},
			"ou-prod": {Id: aws.String("r-root"), Type: orgtypes.ParentTypeRoot},
		},
		attached: map[string][]string{"r-root": {"p-FullAWSAccess"}, "ou-prod": {"p-denyiam"}},
		policies: map[string][2]string{"p-FullAWSAccess": {"FullAWSAccess", fullAccess}, "p-denyiam": {"DenyIAM", denyIAM}},
		deny:     map[string]bool{},
	}
}

func collectWith(t *testing.T, iamf *fakeIAM, org *fakeOrg, ref string) *provider.RawSet {
	t.Helper()
	raw, err := collect(context.Background(), clients{iam: iamf, org: org, sts: fakeSTS{}}, ref)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	return raw
}

func docsOfKind(raw *provider.RawSet, kind model.SourceKind) []string {
	var out []string
	for _, d := range raw.Documents {
		if d.Kind == kind {
			out = append(out, d.Name)
		}
	}
	return out
}

func TestCollectRoleAttachedInlineBoundaryAndSCPs(t *testing.T) {
	raw := collectWith(t, fixtureIAM(), fixtureOrg(), "role/deploy")
	if raw.Principal.Ref != "arn:aws:iam::"+account+":role/deploy" || raw.Principal.Kind != "role" {
		t.Fatalf("principal = %+v", raw.Principal)
	}
	if got := docsOfKind(raw, model.SourceIdentity); strings.Join(got, ",") != "deploy-managed,extra" {
		t.Errorf("identity docs = %v", got)
	}
	if got := docsOfKind(raw, model.SourceBoundary); strings.Join(got, ",") != "boundary" {
		t.Errorf("boundary docs = %v", got)
	}
	if got := docsOfKind(raw, model.SourceGuardrail); strings.Join(got, ",") != "FullAWSAccess,DenyIAM" {
		t.Errorf("guardrail docs = %v", got)
	}
	for _, d := range raw.Documents {
		if strings.Contains(string(d.Body), "ec2.amazonaws.com") {
			t.Fatal("trust policy must not be collected")
		}
		if d.Kind == model.SourceGuardrail {
			switch d.Name {
			case "FullAWSAccess":
				if d.Target != "r-root" || strings.Join(d.Inherited, "/") != "r-root" {
					t.Errorf("root SCP target = %q inherited = %v", d.Target, d.Inherited)
				}
			case "DenyIAM":
				if d.Target != "ou-prod" || strings.Join(d.Inherited, "/") != "r-root/ou-prod" {
					t.Errorf("OU SCP target = %q inherited = %v", d.Target, d.Inherited)
				}
			}
		}
	}
	if len(raw.Gaps) != 0 {
		t.Fatalf("unexpected gaps: %v", raw.Gaps)
	}

	// And the whole thing evaluates: the OU deny removes iam:PassRole.
	set, err := newSeedProvider(t).Evaluate(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	allowed(t, set, key("s3:GetObject", "*"))
	notAllowed(t, set, key("iam:PassRole", "*"))
}

func TestCollectDecodesPercentEncodedDocuments(t *testing.T) {
	f := fixtureIAM()
	doc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/a+b c/*"}]}`
	f.inline["role/plain"] = map[string]string{"weird": doc}
	raw := collectWith(t, f, &fakeOrg{notInUse: true}, "role/plain")
	if len(raw.Documents) != 1 || string(raw.Documents[0].Body) != doc {
		t.Fatalf("decoded = %s", raw.Documents[0].Body)
	}
}

func TestCollectUserIncludesGroupPolicies(t *testing.T) {
	raw := collectWith(t, fixtureIAM(), &fakeOrg{notInUse: true}, "user/ci")
	if got := docsOfKind(raw, model.SourceIdentity); strings.Join(got, ",") != "own" {
		t.Errorf("identity docs = %v", got)
	}
	if got := docsOfKind(raw, model.SourceGroup); strings.Join(got, ",") != "ReadOnlyAccess,devs/shared" {
		t.Errorf("group docs = %v", got)
	}
	set, err := newSeedProvider(t).Evaluate(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	allowed(t, set, key("iam:PassRole", "*"))
}

func TestCollectAccessDeniedBecomesGap(t *testing.T) {
	f := fixtureIAM()
	f.deny["ListAttachedRolePolicies"] = true
	raw := collectWith(t, f, &fakeOrg{notInUse: true}, "role/deploy")
	if got := docsOfKind(raw, model.SourceIdentity); strings.Join(got, ",") != "extra" {
		t.Errorf("identity docs = %v", got)
	}
	if len(raw.Gaps) != 1 || !strings.Contains(raw.Gaps[0], "iam:ListAttachedRolePolicies deploy: AccessDenied") {
		t.Fatalf("gaps = %v", raw.Gaps)
	}

	f = fixtureIAM()
	f.deny["GetPolicy"] = true
	raw = collectWith(t, f, &fakeOrg{notInUse: true}, "role/deploy")
	joined := strings.Join(raw.Gaps, "\n")
	if !strings.Contains(joined, "boundary policy not evaluated") || !strings.Contains(joined, "identity policy not evaluated") {
		t.Fatalf("gaps = %v", raw.Gaps)
	}
}

func TestCollectMissingPrincipalIsAnError(t *testing.T) {
	_, err := collect(context.Background(), clients{iam: fixtureIAM(), org: &fakeOrg{notInUse: true}, sts: fakeSTS{}}, "role/nope")
	if err == nil || !strings.Contains(err.Error(), "iam:GetRole nope") {
		t.Fatalf("err = %v", err)
	}
}

func TestSCPDeniedIsGapNotError(t *testing.T) {
	org := fixtureOrg()
	org.deny["ListParents"] = true
	raw := collectWith(t, fixtureIAM(), org, "role/plain")
	if len(docsOfKind(raw, model.SourceGuardrail)) != 0 {
		t.Fatal("no SCP should be collected")
	}
	if len(raw.Gaps) != 1 || !strings.Contains(raw.Gaps[0], "organizations:ListParents") || !strings.Contains(raw.Gaps[0], "AccessDenied") {
		t.Fatalf("gaps = %v", raw.Gaps)
	}

	org = fixtureOrg()
	org.deny["DescribeOrganization"] = true
	raw = collectWith(t, fixtureIAM(), org, "role/plain")
	if len(raw.Gaps) != 1 || !strings.Contains(raw.Gaps[0], "organizations:DescribeOrganization") {
		t.Fatalf("gaps = %v", raw.Gaps)
	}
}

func TestOrgNotInUseOrSCPsDisabledIsComplete(t *testing.T) {
	for name, org := range map[string]*fakeOrg{
		"not in an organisation": {notInUse: true},
		"SCPs disabled at root":  {scpEnabled: false, deny: map[string]bool{}},
	} {
		raw := collectWith(t, fixtureIAM(), org, "role/plain")
		if len(raw.Gaps) != 0 || len(docsOfKind(raw, model.SourceGuardrail)) != 0 {
			t.Errorf("%s: gaps = %v, guardrails = %v", name, raw.Gaps, docsOfKind(raw, model.SourceGuardrail))
		}
	}
}

func TestParsePrincipal(t *testing.T) {
	cases := []struct {
		ref, kind, name, arn string
		wantErr              bool
	}{
		{"role/deploy", "role", "deploy", "arn:aws:iam::123456789012:role/deploy", false},
		{"user/ci", "user", "ci", "arn:aws:iam::123456789012:user/ci", false},
		{"role/service/deploy", "role", "deploy", "arn:aws:iam::123456789012:role/service/deploy", false},
		{"arn:aws:iam::123456789012:role/deploy", "role", "deploy", "arn:aws:iam::123456789012:role/deploy", false},
		{"arn:aws:iam::123456789012:user/path/ci", "user", "ci", "arn:aws:iam::123456789012:user/path/ci", false},
		{"deploy", "", "", "", true},
		{"group/devs", "", "", "", true},
		{"role/", "", "", "", true},
		{"arn:aws:iam::999999999999:role/deploy", "", "", "", true},
		{"arn:aws:s3:::bucket", "", "", "", true},
		{"arn:aws:iam::123456789012:group/devs", "", "", "", true},
	}
	for _, c := range cases {
		got, err := parsePrincipal(c.ref, account, "aws")
		if (err != nil) != c.wantErr {
			t.Errorf("parsePrincipal(%q): err = %v", c.ref, err)
			continue
		}
		if err == nil && (got.Kind != c.kind || got.Name != c.name || got.ARN != c.arn) {
			t.Errorf("parsePrincipal(%q) = %+v", c.ref, got)
		}
	}
	if got, _ := parsePrincipal("role/x", account, "aws-us-gov"); got.ARN != "arn:aws-us-gov:iam::123456789012:role/x" {
		t.Errorf("partition not honoured: %s", got.ARN)
	}
}

func TestCollectRejectsWrongNumberOfRefs(t *testing.T) {
	p := newSeedProvider(t)
	if _, err := p.Collect(context.Background(), provider.Selector{}); err == nil {
		t.Fatal("expected an error for zero refs")
	}
}
