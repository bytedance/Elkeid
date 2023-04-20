package agent

import (
	"context"
	"os/exec"
	"path/filepath"

	"github.com/bytedance/Elkeid/agent/host"
	"github.com/bytedance/Elkeid/agent/proto"
	"github.com/bytedance/Elkeid/agent/utils"
	"github.com/google/uuid"
)

// 升级过程禁止被打断
// 不是并发安全的
func Update(config proto.Config) (err error) {
	dst := filepath.Join(WorkingDirectory, "tmp", uuid.New().String())
	err = utils.Download(context.Background(), dst, config)
	if err != nil {
		return
	}
	var cmd *exec.Cmd
	switch host.PlatformFamily {
	case "debian":
		cmd = exec.Command("dpkg", "-i", dst)
	// ref:https://docs.fedoraproject.org/ro/Fedora_Draft_Documentation/0.1/html/RPM_Guide/ch-command-reference.html
	case "rhel", "fedora", "suse":
		cmd = exec.Command("rpm", "-Uvh", dst)
	default:
		cmd = exec.Command(dst)
	}
	err = cmd.Run()
	return
}
