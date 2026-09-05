// Package severity ranks a permission change.
//
// Most of the signal comes free from the catalogue's own access levels.
// The curated high-risk list is the small opinionated part that gives
// the tool a point of view: roughly fifty actions per cloud where the
// access level understates the blast radius.
package severity

import (
	"path"
	"strings"

	"github.com/IbiliAze/iamdiff/internal/catalogue"
)

type Rank uint8

const (
	Low Rank = iota
	Medium
	High
)

func (r Rank) String() string {
	switch r {
	case High:
		return "HIGH"
	case Medium:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

// HighRisk is hand-curated. Each entry is an action whose catalogue
// access level does not convey how dangerous it is.
var HighRisk = []string{
	"iam:*",
	"sts:AssumeRole",
	"kms:ScheduleKeyDeletion",
	"kms:DisableKey",
	"organizations:LeaveOrganization",
	"ec2:TerminateInstances",
	"s3:PutBucketPolicy",
}

// Classify ranks an action using the curated list first, then the
// catalogue's access level.
func Classify(c catalogue.Catalogue, action string, extra []string) Rank {
	for _, p := range append(append([]string{}, HighRisk...), extra...) {
		if matches(p, action) {
			return High
		}
	}
	if c == nil {
		return Low
	}
	switch c.AccessLevel(action) {
	case catalogue.LevelPermissionsMgmt:
		return High
	case catalogue.LevelWrite:
		return Medium
	default:
		return Low
	}
}

func matches(pattern, action string) bool {
	ok, err := path.Match(strings.ToLower(pattern), strings.ToLower(action))
	return err == nil && ok
}
