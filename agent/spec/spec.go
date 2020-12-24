package spec

type Data []map[string]string

//go:generate msgp
type Task struct {
	ID      uint32 `msg:"id" json:"id"`
	Content string `msg:"content" json:"content"`
	Token   string `msg:"token" json:"token"`
}
