package procotol

//go:generate msgp
type RegistRequest struct {
	Name    string `msg:"name"`
	Version string `msg:"version"`
	Pid     int    `msg:"pid"`
}
