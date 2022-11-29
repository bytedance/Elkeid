package container

type State int32

const (
	CREATED State = 0
	RUNNING State = 1
	EXITED  State = 2
	UNKNOWN State = 3
)

var StateName = map[int32]string{
	0: "created",
	1: "running",
	2: "exited",
	3: "unknown",
}

var StateValue = map[string]int32{
	"created": 0,
	"running": 1,
	"exited":  2,
	"unknown": 3,
}
