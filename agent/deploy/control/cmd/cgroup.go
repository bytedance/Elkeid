package cmd

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

var (
	ErrCGroupNotEnable    = errors.New("cgroup not enable")
	ErrMountPointNotExist = errors.New("mount point not exist")
	ErrReadOnly           = errors.New("read only")
)

type CGroup struct {
	cpuPath    string
	memoryPath string
	namedPath  string
	readOnly   bool
}

func (cgroup *CGroup) AddProc(pid int) (err error) {
	if cgroup.readOnly {
		return ErrReadOnly
	}
	err = retryingWriteFile(filepath.Join(cgroup.namedPath, "cgroup.procs"), []byte(strconv.Itoa(pid)), 0o0644)
	if err != nil {
		return
	}
	if cgroup.memoryPath != "" {
		err = retryingWriteFile(filepath.Join(cgroup.memoryPath, "cgroup.procs"), []byte(strconv.Itoa(pid)), 0o0644)
		if err != nil {
			return
		}
	}
	if cgroup.cpuPath != "" {
		err = retryingWriteFile(filepath.Join(cgroup.cpuPath, "cgroup.procs"), []byte(strconv.Itoa(pid)), 0o0644)
		if err != nil {
			return
		}
	}
	return
}
func (cgroup *CGroup) GetProcs(t string) (res []int, err error) {
	switch t {
	case "named":
		t = cgroup.namedPath
	case "cpu":
		t = cgroup.cpuPath
	case "memory":
		t = cgroup.memoryPath
	default:
		return nil, errors.New("invalid cgroup type")
	}
	var f *os.File
	f, err = os.Open(filepath.Join(t, "cgroup.procs"))
	if err != nil {
		return
	}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		pid, err := strconv.ParseInt(strings.TrimSpace(scanner.Text()), 10, 64)
		if err != nil {
			return nil, err
		}
		res = append(res, int(pid))
	}
	return
}
func LoadCGroup(path string) (*CGroup, error) {
	rootNamedPath, rootCPUPath, rootMemoryPath, cpu, memory, err := CheckCGroup()
	if err != nil {
		return nil, err
	}
	cgroup := &CGroup{
		namedPath: filepath.Join(rootNamedPath, path),
		readOnly:  true,
	}
	if memory {
		cgroup.memoryPath = filepath.Join(rootMemoryPath, path)
	}
	if cpu {
		cgroup.cpuPath = filepath.Join(rootCPUPath, path)
	}
	return cgroup, nil
}
func CheckCGroup() (rootNamedPath, rootCPUPath, rootMemoryPath string, cpu, memory bool, err error) {
	f, err := os.Open("/proc/cgroups")
	if err != nil {
		err = ErrCGroupNotEnable
		return
	}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(strings.TrimSpace(scanner.Text()))
		if len(fields) < 4 {
			err = fmt.Errorf("cgroups: bad entry %q", scanner.Text())
			return
		}
		if fields[0] == "cpu" && fields[3] == "1" {
			cpu = true
		}
		if fields[0] == "memory" && fields[3] == "1" {
			memory = true
		}
	}
	f.Close()
	f, err = os.Open("/proc/self/mountinfo")
	if err != nil {
		err = ErrMountPointNotExist
		return
	}
	scanner = bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(strings.TrimSpace(scanner.Text()))
		if len(fields) < 10 {
			f.Close()
			err = fmt.Errorf("mountinfo: bad entry %q", scanner.Text())
			return
		}
		if fields[len(fields)-3] == "cgroup" {
			subsystems := strings.Split(fields[len(fields)-1], ",")
			for _, s := range subsystems {
				if s == "cpu" {
					rootCPUPath = fields[4]
				}
				if s == "memory" {
					rootMemoryPath = fields[4]
				}
				if s == "name=all" {
					rootNamedPath = fields[4]
				}
			}
		}
	}
	f.Close()
	return
}
func NewCGroup(path string) (*CGroup, error) {
	if path == "" {
		return nil, errors.New("path must not be empty")
	}
	rootNamedPath, rootCPUPath, rootMemoryPath, cpu, memory, err := CheckCGroup()
	if err != nil {
		return nil, err
	}
	cgroup := &CGroup{
		readOnly: false,
	}
	if rootNamedPath == "" {
		rootNamedPath = filepath.Join(cgroupPath, "named")
		err := os.MkdirAll(rootNamedPath, 0o0700)
		if err != nil {
			return nil, err
		}
		cmd := exec.Command("mount", "-t", "cgroup", "-o", "none,name=all", "cgroup", rootNamedPath)
		cmd.Env = append(cmd.Env, "PATH:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin")
		out, err := cmd.CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("mount named cgroup failed: %w: %v", err, string(out))
		}
	}
	cgroup.namedPath = filepath.Join(rootNamedPath, path)
	if path != "/" {
		if _, err := os.Stat(cgroup.namedPath); errors.Is(err, os.ErrNotExist) {
			err = os.MkdirAll(cgroup.namedPath, 0o700)
			if err != nil {
				return nil, err
			}
		} else if err != nil {
			return nil, err
		}
	}

	if cpu {
		cpuPath := ""
		if rootCPUPath == "" {
			rootCPUPath = filepath.Join(cgroupPath, "cpu")
			err := os.MkdirAll(rootCPUPath, 0o0700)
			if err == nil {
				cmd := exec.Command("mount", "-t", "cgroup", "-o", "cpu", "cgroup", rootCPUPath)
				cmd.Env = append(cmd.Env, "PATH:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin")
				out, err := cmd.CombinedOutput()
				if err == nil {
					cpuPath = filepath.Join(rootCPUPath, path)
				} else {
					fmt.Fprintf(os.Stderr, "mount cpu cgroup failed: %v: %v\n", err, string(out))
				}
			} else {
				fmt.Fprintf(os.Stderr, "mount cpu cgroup failed: %v\n", err)
			}
		} else {
			cpuPath = filepath.Join(rootCPUPath, path)
		}
		if cpuPath != "" {
			if _, err := os.Stat(cpuPath); errors.Is(err, os.ErrNotExist) && path != "/" {
				err = os.MkdirAll(cpuPath, 0o700)
				if err == nil {
					content, err := os.ReadFile(filepath.Join(cpuPath, "cpu.cfs_period_us"))
					if err == nil {
						period, err := strconv.ParseInt(strings.TrimSpace(string(content)), 10, 64)
						if err == nil {
							quota := period / 10
							if quota < 10000 {
								quota = 10000
							}
							err = retryingWriteFile(filepath.Join(cgroup.cpuPath, "cpu.cfs_quota_us"), []byte(strconv.FormatInt(quota, 10)), 0o0644)
							if err == nil {
								cgroup.cpuPath = cpuPath
							} else {
								fmt.Fprintf(os.Stderr, "set sub cpu cgroup's cpu.cfs_quota_us failed: %v\n", err)
							}
						} else {
							fmt.Fprintf(os.Stderr, "parse sub cpu cgroup's cpu.cfs_period_us failed: %v\n", err)
						}
					} else {
						fmt.Fprintf(os.Stderr, "read sub cpu cgroup's cpu.cfs_period_us failed: %v\n", err)
					}
				} else {
					fmt.Fprintf(os.Stderr, "create sub cpu cgroup failed: %v\n", err)
				}
			} else if err != nil && path != "/" {
				fmt.Fprintf(os.Stderr, "stat sub cpu cgroup failed: %v\n", err)
			} else {
				cgroup.cpuPath = cpuPath
			}
		}
	}

	if memory {
		memoryPath := ""
		if rootMemoryPath == "" {
			rootMemoryPath = filepath.Join(cgroupPath, "memory")
			err := os.MkdirAll(rootMemoryPath, 0o0700)
			if err == nil {
				cmd := exec.Command("mount", "-t", "cgroup", "-o", "memory", "cgroup", rootMemoryPath)
				cmd.Env = append(cmd.Env, "PATH:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin")
				out, err := cmd.CombinedOutput()
				if err == nil {
					memoryPath = filepath.Join(rootMemoryPath, path)
				} else {
					fmt.Fprintf(os.Stderr, "mount memory cgroup failed: %v: %v\n", err, string(out))
				}
			} else {
				fmt.Fprintf(os.Stderr, "mount memory cgroup failed: %v\n", err)
			}
		} else {
			memoryPath = filepath.Join(rootMemoryPath, path)
		}
		if memoryPath != "" {
			if _, err := os.Stat(memoryPath); path != "/" && errors.Is(err, os.ErrNotExist) && path != "/" {
				err = os.MkdirAll(memoryPath, 0o700)
				if err == nil {
					err = retryingWriteFile(filepath.Join(memoryPath, "memory.limit_in_bytes"), []byte(strconv.FormatInt(262144000, 10)), 0o0644)
					if err == nil {
						cgroup.memoryPath = memoryPath
					} else {
						fmt.Fprintf(os.Stderr, "set sub memory cgroup's memory.limit_in_bytes failed: %v\n", err)
					}
				} else {
					fmt.Fprintf(os.Stderr, "create sub memory cgroup failed: %v\n", err)
				}
			} else if err != nil {
				fmt.Fprintf(os.Stderr, "stat sub memory cgroup failed: %v\n", err)
			} else {
				cgroup.memoryPath = memoryPath
			}
		}
	}
	return cgroup, nil
}
func retryingWriteFile(path string, data []byte, mode os.FileMode) error {
	// Retry writes on EINTR; see:
	//    https://github.com/golang/go/issues/38033
	for {
		err := os.WriteFile(path, data, mode)
		if err == nil {
			return nil
		} else if !errors.Is(err, syscall.EINTR) {
			return err
		}
	}
}
