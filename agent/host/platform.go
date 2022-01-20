package host

import (
	"github.com/shirou/gopsutil/v3/host"
)

var (
	Platform        string
	PlatformFamily  string
	PlatformVersion string
	KernelVersion   string
	Arch            string
)

func init() {
	KernelVersion, _ = host.KernelVersion()
	Platform, PlatformFamily, PlatformVersion, _ = host.PlatformInformation()
	Arch, _ = host.KernelArch()
}
