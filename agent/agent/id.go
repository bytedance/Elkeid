package agent

import (
	"bytes"
	"context"
	"os"

	"github.com/google/uuid"
)

var (
	Context, Cancel            = context.WithCancel(context.Background())
	ID                         = ""
	WorkingDirectory, _        = os.Getwd()
	Product             string = "elkeid-agent"
	// from linker
	Version string
)

func fromUUIDFile(file string) (id uuid.UUID, err error) {
	var idBytes []byte
	idBytes, err = os.ReadFile(file)
	if err == nil {
		id, err = uuid.ParseBytes(bytes.TrimSpace(idBytes))
	}
	return
}
func fromIDFile(file string) (id []byte, err error) {
	id, err = os.ReadFile(file)
	if err == nil {
		id = bytes.TrimSpace(id)
	}
	return
}
func init() {
	if WorkingDirectory == "" {
		WorkingDirectory = "/var/run"
	}
	var ok bool
	if ID, ok = os.LookupEnv("SPECIFIED_AGENT_ID"); ok {
		return
	}
	defer func() {
		os.WriteFile("machine-id", []byte(ID), 0600)
	}()
	isid, err := fromIDFile("/var/lib/cloud/data/instance-id")
	if err == nil {
		ID = string(isid)
		return
	}
	pdid, err := fromUUIDFile("/sys/class/dmi/id/product_uuid")
	if err == nil {
		ID = pdid.String()
		return
	}
	mid, err := fromUUIDFile("/etc/machine-id")
	if err == nil {
		ID = mid.String()
		return
	}
	mid, err = fromUUIDFile("machine-id")
	if err == nil {
		ID = mid.String()
		return
	}
	ID = uuid.New().String()
}
