package linux

import (
	"os/exec"
	"strings"
)

// GetSystemType get system type
func GetSystemType() string {
	cmd := exec.Command("cat", "/etc/issue")
	buf, _ := cmd.Output()
	cmdStr := string(buf)
	if strings.Contains(cmdStr, "Ubuntu") {
		return "ubuntu"
	} else if strings.Contains(cmdStr, "Debian") {
		return "debian"
	} else {
		return "centos"
	}
}
