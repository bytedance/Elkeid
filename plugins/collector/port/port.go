package port

import (
	"strconv"
	"strings"
	"time"

	"github.com/bytedance/Elkeid/plugins/collector/process"
	"github.com/bytedance/Elkeid/plugins/collector/utils"
	mapset "github.com/deckarep/golang-set"
	"golang.org/x/sys/unix"
)

var (
	scanProto  = [2]int{unix.IPPROTO_UDP, unix.IPPROTO_TCP}
	scanFamily = [2]int{unix.AF_INET, unix.AF_INET6}
)

type Port struct {
	// from inet
	Family   string `mapstructure:"family"`
	Protocol string `mapstructure:"protocol"`
	State    string `mapstructure:"state"`
	Sport    string `mapstructure:"sport"`
	Dport    string `mapstructure:"dport"`
	Sip      string `mapstructure:"sip"`
	Dip      string `mapstructure:"dip"`
	Uid      string `mapstructure:"uid"`
	Inode    string `mapstructure:"inode"`
	Username string `mapstructure:"username"`
	// from process
	Pid     string `mapstructure:"pid"`
	Exe     string `mapstructure:"exe"`
	Comm    string `mapstructure:"comm"`
	Cmdline string `mapstructure:"cmdline"`
	Psm     string `mapstructure:"psm"`
	PodName string `mapstructure:"pod_name"`
}

func ListeningPorts() (ret []*Port, err error) {
	set := mapset.NewSet()
	pm := map[string]*Port{}
	for _, proto := range scanProto {
		sp := strconv.Itoa(int(proto))
		for _, family := range scanFamily {
			var resp []*inetDiagResp
			resp, err = inetDiag(uint8(family), uint8(proto))
			if err != nil {
				continue
			}
			for _, r := range resp {
				if !set.Contains(r.id.sport) {
					p := &Port{
						Family:   strconv.Itoa(int(r.family)),
						Protocol: sp,
						State:    strconv.Itoa(int(r.state)),
						Sport:    strconv.Itoa(int(r.id.sport)),
						Dport:    strconv.Itoa(int(r.id.dport)),
						Sip:      r.id.sip.String(),
						Dip:      r.id.dip.String(),
						Uid:      strconv.FormatUint(uint64(r.uid), 10),
						Inode:    strconv.FormatUint(uint64(r.inode), 10),
					}
					p.Username, _ = utils.GetUsername(p.Uid)
					pm[strconv.FormatUint(uint64(r.inode), 10)] = p
					set.Add(r.id.sport)
				}
			}
		}
	}
	if len(pm) == 0 {
		for _, proto := range scanProto {
			for _, family := range scanFamily {
				var ps []*Port
				ps, err = procNet(uint8(family), uint8(proto))
				if err != nil {
					continue
				}
				for _, p := range ps {
					if !set.Contains(p.Sport) {
						pm[p.Inode] = p
						set.Add(p.Sport)
					}
				}
			}
		}
	}
	if len(pm) == 0 && err != nil {
		return
	}
	procs, err := process.Processes(false)
	if err == nil {
		for _, p := range procs {
			time.Sleep(process.TraversalInterval)
			fds, err := p.Fds()
			if err != nil {
				continue
			}
			for _, fd := range fds {
				if strings.HasPrefix(fd, "socket:[") && strings.HasSuffix(fd, "]") {
					if port, ok := pm[fd[8:len(fd)-1]]; ok {
						port.Pid = p.Pid()
						port.Exe, _ = p.Exe()
						port.Cmdline, _ = p.Cmdline()
						port.Comm, _ = p.Comm()
						if envs, err := p.Envs(); err == nil {
							if p, ok := envs["POD_NAME"]; ok {
								port.PodName = p
							} else if p, ok := envs["MY_POD_NAME"]; ok {
								port.PodName = p
							}
							if p, ok := envs["LOAD_SERVICE_PSM"]; ok {
								port.Psm = p
							} else if p, ok := envs["TCE_PSM"]; ok {
								port.Psm = p
							} else if p, ok := envs["RUNTIME_PSM"]; ok {
								port.Psm = p
							}
						}
					}
				}
			}
		}
	}
	for _, v := range pm {
		if v.Pid != "" {
			ret = append(ret, v)
		}
	}
	return
}
