package agent

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"

	"github.com/google/uuid"
)

var (
	Context, Cancel            = context.WithCancel(context.Background())
	ID                         = ""
	WorkingDirectory, _        = os.Getwd()
	Product             string = "elkeid-agent"
	Control                    = filepath.Join(WorkingDirectory, "elkeidctl")
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
		if len(id) < 6 {
			err = errors.New("id too short")
			return
		}
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
	source := []byte{}
	isid, err := fromIDFile("/var/lib/cloud/data/instance-id")
	if err == nil {
		source = append(source, isid...)
	}
	pdid, err := fromIDFile("/sys/class/dmi/id/product_uuid")
	if err == nil {
		source = append(source, pdid...)
	}
	emac, err := fromIDFile("/sys/class/net/eth0/address")
	if err == nil {
		source = append(source, emac...)
	}
	if len(source) > 8 &&
		string(pdid) != "03000200-0400-0500-0006-000700080009" &&
		string(pdid) != "02000100-0300-0400-0005-000600070008" {
		pname, err := fromIDFile("/sys/class/dmi/id/product_name")
		if err == nil && len(pname) != 0 &&
			!bytes.Equal(pname, []byte("--")) &&
			!bytes.Equal(pname, []byte("unknown")) &&
			!bytes.Equal(pname, []byte("To be filled by O.E.M.")) &&
			!bytes.Equal(pname, []byte("OEM not specify")) &&
			!bytes.Equal(bytes.ToLower(pname), []byte("t.b.d")) {
			ID = uuid.NewSHA1(uuid.NameSpaceOID, source).String()
		}
		return
	}
	mid, err := fromUUIDFile("/etc/machine-id")
	if err == nil {
		ID = mid.String()
		return
	}
	if err.Error() == "invalid UUID format" {
		source, err := fromIDFile("/etc/machine-id")
		if err == nil {
			ID = uuid.NewSHA1(uuid.NameSpaceOID, source).String()
			return
		}
	}
	mid, err = fromUUIDFile("machine-id")
	if err == nil {
		ID = mid.String()
		return
	}
	ID = uuid.New().String()
}
