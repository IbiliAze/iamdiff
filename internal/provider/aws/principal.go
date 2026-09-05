package aws

import (
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
)

// principalRef is a parsed reference to an IAM role or user.
type principalRef struct {
	Kind    string // role or user
	Name    string
	Account string
	ARN     string
}

// parsePrincipal accepts an IAM ARN, "role/NAME" or "user/NAME" (with an
// optional path), resolved against the caller's account and partition.
// A bare name is rejected: it does not say whether it is a role or a
// user, and guessing wrong would evaluate the wrong principal.
func parsePrincipal(ref, account, partition string) (principalRef, error) {
	if arn.IsARN(ref) {
		a, err := arn.Parse(ref)
		if err != nil {
			return principalRef{}, fmt.Errorf("aws: %w", err)
		}
		if a.Service != "iam" {
			return principalRef{}, fmt.Errorf("aws: %s is not an IAM principal", ref)
		}
		kind, name, err := splitResource(a.Resource)
		if err != nil {
			return principalRef{}, fmt.Errorf("aws: %s: %w", ref, err)
		}
		if account != "" && a.AccountID != account {
			return principalRef{}, fmt.Errorf("aws: %s belongs to account %s but the credentials are for %s; assume a role there first", ref, a.AccountID, account)
		}
		return principalRef{Kind: kind, Name: name, Account: a.AccountID, ARN: ref}, nil
	}
	kind, name, err := splitResource(ref)
	if err != nil {
		return principalRef{}, fmt.Errorf("aws: %w", err)
	}
	if partition == "" {
		partition = "aws"
	}
	return principalRef{
		Kind:    kind,
		Name:    name,
		Account: account,
		ARN:     fmt.Sprintf("arn:%s:iam::%s:%s", partition, account, ref),
	}, nil
}

func splitResource(res string) (kind, name string, err error) {
	kind, rest, ok := strings.Cut(res, "/")
	if !ok || rest == "" || (kind != "role" && kind != "user") {
		return "", "", fmt.Errorf("principal must be an ARN, role/NAME or user/NAME, got %q", res)
	}
	name = rest[strings.LastIndex(rest, "/")+1:]
	if name == "" {
		return "", "", fmt.Errorf("principal %q has no name", res)
	}
	return kind, name, nil
}

// partitionOf reads the partition out of an ARN, defaulting to "aws".
func partitionOf(s string) string {
	if a, err := arn.Parse(s); err == nil && a.Partition != "" {
		return a.Partition
	}
	return "aws"
}
