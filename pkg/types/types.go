package types

type Candidate struct {
	Image    string `json:"image"`
	Tag      string `json:"tag"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	Variable string `json:"variable"`
	Value    string `json:"value"`
	Context  string `json:"context"`
}

type Finding struct {
	Image    string `json:"image"`
	Tag      string `json:"tag"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	Variable string `json:"variable"`
	Value    string `json:"value"`
	Context  string `json:"context"`
}
