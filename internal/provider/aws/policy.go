package aws

import (
	"encoding/json"
	"fmt"
)

// Document is an AWS policy document. Field types are deliberately
// permissive: AWS accepts a bare string or an array almost everywhere.
type Document struct {
	Version   string      `json:"Version"`
	Statement []Statement `json:"Statement"`
}

type Statement struct {
	Sid         string          `json:"Sid,omitempty"`
	Effect      string          `json:"Effect"`
	Action      StringOrSlice   `json:"Action,omitempty"`
	NotAction   StringOrSlice   `json:"NotAction,omitempty"`
	Resource    StringOrSlice   `json:"Resource,omitempty"`
	NotResource StringOrSlice   `json:"NotResource,omitempty"`
	Condition   json.RawMessage `json:"Condition,omitempty"`
}

// StringOrSlice accepts either a JSON string or an array of strings.
type StringOrSlice []string

func (s *StringOrSlice) UnmarshalJSON(b []byte) error {
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*s = []string{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return fmt.Errorf("aws: field must be a string or array of strings: %w", err)
	}
	*s = many
	return nil
}

// statements accepts a single statement object as well as an array,
// which AWS permits.
func parseDocument(b []byte) (*Document, error) {
	var d Document
	if err := json.Unmarshal(b, &d); err == nil {
		return &d, nil
	}
	var single struct {
		Version   string    `json:"Version"`
		Statement Statement `json:"Statement"`
	}
	if err := json.Unmarshal(b, &single); err != nil {
		return nil, fmt.Errorf("aws: parse policy document: %w", err)
	}
	return &Document{Version: single.Version, Statement: []Statement{single.Statement}}, nil
}
