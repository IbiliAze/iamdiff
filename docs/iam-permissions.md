# Permissions needed by `iamdiff roles`, `collect` and `explain`

Live collection is read-only. It needs the actions below on the principal it
inspects; nothing else.

## Identity policies and permissions boundary

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "iam:GetRole",
      "iam:GetUser",
      "iam:ListAttachedRolePolicies",
      "iam:ListRolePolicies",
      "iam:GetRolePolicy",
      "iam:ListAttachedUserPolicies",
      "iam:ListUserPolicies",
      "iam:GetUserPolicy",
      "iam:ListGroupsForUser",
      "iam:ListAttachedGroupPolicies",
      "iam:ListGroupPolicies",
      "iam:GetGroupPolicy",
      "iam:GetPolicy",
      "iam:GetPolicyVersion"
    ],
    "Resource": "*"
  }]
}
```

`sts:GetCallerIdentity` is also called, to learn the account; it needs no
permission.

## Service control policies

SCPs are read from AWS Organizations, and the Organizations API only answers
from the **management account** or a **delegated administrator**. From a
member account these calls are denied; `iamdiff` records the gap, marks the
result partial and exits 4. That is deliberate (ADR-0003): an evaluation that
cannot see the guardrails cannot claim access did not widen.

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "organizations:DescribeOrganization",
      "organizations:ListRoots",
      "organizations:ListParents",
      "organizations:ListPoliciesForTarget",
      "organizations:DescribePolicy"
    ],
    "Resource": "*"
  }]
}
```

To evaluate from a member account, have an administrator export the SCPs once
with `iamdiff collect` from the management account, or pass them offline with
`iamdiff policy ... --guardrail LEVEL=FILE`.

## What is not read

Resource-based policies, session policies and resource control policies are
outside the model; they are documented non-goals rather than gaps, so a result
that says "complete" means complete with respect to identity policies, the
permissions boundary and service control policies.
