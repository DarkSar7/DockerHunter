package types

type Candidate struct {
	Image    string `json:"image"`
	Tag      string `json:"tag"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	Variable string `json:"variable"`
	Value    string `json:"value"`
	Context  string `json:"context"`
	RawMatch string `json:"raw_match,omitempty"`
	// RuleName and RuleSensitive are set only after the signature-regex stage.
	RuleName      string `json:"rule_name,omitempty"`
	RuleSensitive bool   `json:"rule_sensitive,omitempty"`
}

type Finding struct {
	Image            string `json:"image"`
	Tag              string `json:"tag"`
	File             string `json:"file"`
	Line             int    `json:"line"`
	Variable         string `json:"variable"`
	Value            string `json:"value"`
	Context          string `json:"context"`
	RuleName         string `json:"rule_name,omitempty"`
	ValidationSource string `json:"validation_source,omitempty"`
	Confidence       string `json:"confidence,omitempty"`
}
