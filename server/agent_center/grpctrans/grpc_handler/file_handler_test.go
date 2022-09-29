package grpc_handler

import (
	"os"
	"testing"
)

func TestZipFile(t *testing.T) {
	err := zipFile("/111.zip",
		"~/main.go")
	if err != nil {
		t.Errorf("zipFile error %s", err.Error())
		return
	}
	in, err := os.ReadFile("~/111.zip")
	if err != nil {
		t.Errorf("ReadFile error %s", err.Error())
		return
	}
	out, err := unZipSingleFileFromMemory(in)
	if err != nil {
		t.Errorf("unZipSingleFileFromMemory error %s", err.Error())
		return
	}
	t.Logf("%s", string(out))
}
