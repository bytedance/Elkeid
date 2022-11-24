package static

import (
	"testing"

	_ "embed"
)

func TestReadFile(t *testing.T) {
	entries, err := FrontendFile.ReadDir("frontend/assets")
	if err != nil {
		t.Error(err)
	}
	for _, entry := range entries {
		t.Log(entry.Name())
	}
	ret, err := FrontendFile.ReadFile("frontend/index.html")
	if err != nil {
		t.Error(err)
	}
	t.Log(string(ret))
}
