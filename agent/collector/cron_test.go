package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGetFileName(t *testing.T) {
	file, _ := os.Open("/root/Workspace/mongoose_agent/collector/cron.go")
	t.Log(filepath.Base(file.Name()))
}
