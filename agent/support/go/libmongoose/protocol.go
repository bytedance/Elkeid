package libmongoose

//go:generate msgp
// RegistRequest is used to describe the data structure of the plugin registration request
type RegistRequest struct {
	Pid     uint32 `msg:"pid"`
	Name    string `msg:"name"`
	Version string `msg:"version"`
}
type Data []map[string]string
type Task struct {
	ID      uint32 `msg:"id"`
	Content string `msg:"content"`
	Token   string `msg:"token"`
}
