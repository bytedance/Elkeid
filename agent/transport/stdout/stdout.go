package stdout

import (
	"encoding/json"
	"os"

	"github.com/bytedance/ByteDance-HIDS/agent/spec"
)

type Stdout struct {
}

func (so *Stdout) Send(d *spec.Data) error {
	content, err := json.Marshal(d)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(append(content, '\n'))
	if err != nil {
		return err
	}
	return nil
}

func (fo *Stdout) Receive() (spec.Task, error) {
	select {}
}

func (fo *Stdout) Close() {
}
