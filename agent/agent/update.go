package agent

import (
	"context"
	"os/exec"
	"path"

	"github.com/bytedance/Elkeid/agent/host"
	"github.com/bytedance/Elkeid/agent/proto"
	"github.com/bytedance/Elkeid/agent/utils"
)

// 升级过程禁止被打断
// 不是并发安全的
func Update(config proto.Config) (err error) {
	dst := path.Join("/tmp", Product+"-updater"+".pkg")
	err = utils.Download(context.Background(), dst, config)
	if err != nil {
		return
	}
	var cmd *exec.Cmd
	switch host.PlatformFamily {
	// 为了后续兼容性，先不合并debian与default分支
	case "debian":
		cmd = exec.Command("dpkg", "-i", dst)
	// ref:https://docs.fedoraproject.org/ro/Fedora_Draft_Documentation/0.1/html/RPM_Guide/ch-command-reference.html
	case "rhel":
		cmd = exec.Command("rpm", "-Uvh", dst)
	default:
		cmd = exec.Command("dpkg", "-i", dst)
	}
	err = cmd.Run()
	return
}
