package monitor

type BuildVersion struct {
	Address string `json:"address"`
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Build   string `json:"build"`
	CI      string `json:"ci"`
}
