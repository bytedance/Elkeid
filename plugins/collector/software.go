package main

import (
	"bufio"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/bytedance/Elkeid/plugins/collector/engine"
	"github.com/bytedance/Elkeid/plugins/collector/process"
	"github.com/bytedance/Elkeid/plugins/collector/rpm"
	"github.com/bytedance/Elkeid/plugins/collector/zip"
	plugins "github.com/bytedance/plugins"
	mapset "github.com/deckarep/golang-set"
	"github.com/karrick/godirwalk"
	"github.com/mitchellh/mapstructure"
)

const (
	MaxRecursionLevel = 3
)

var (
	VersionReg = regexp.MustCompile(`-[0-9]`)
)

type SoftwareHandler struct{}

func (h *SoftwareHandler) Name() string {
	return "software"
}
func (h *SoftwareHandler) DataType() int {
	return 5055
}

type Software struct {
	Name    string `mapstructure:"name"`
	Version string `mapstructure:"sversion"`
	// dpkg rpm pypi jar
	Type string `mapstructure:"type"`
	// dpkg
	Source string `mapstructure:"source"`
	Status string `mapstructure:"status"`
	// rpm
	Vendor           string `mapstructure:"vendor"`
	ComponentVersion string `mapstructure:"component_version"`
	// jar
	Pid     string `mapstructure:"pid"`
	PodName string `mapstructure:"pod_name"`
	Psm     string `mapstructure:"psm"`

	PackageSeq string `mapstructure:"package_seq"`
}

func parsePypiName(name string) (ret *Software, err error) {
	ret = &Software{
		Type: "pypi",
	}
	n := strings.TrimSuffix(strings.TrimSuffix(name, ".egg-info"), ".dist-info")
	fileds := strings.SplitN(n, "-", 3)
	switch len(fileds) {
	case 1:
		ret.Name = fileds[0]
	case 2:
		ret.Name = fileds[0]
		ret.Version = fileds[1]
	case 3:
		ret.Name = fileds[0]
		ret.Version = fileds[1]
		ret.ComponentVersion = fileds[2]
	default:
		err = errors.New("unknown format")
	}
	return
}
func parseJarFilename(fn string) (n, v string) {
	index := VersionReg.FindStringIndex(fn)
	if len(index) == 0 {
		n = fn
		v = ""
	} else {
		n = fn[:(index[0])]
		v = fn[(index[0] + 1):]
	}
	return
}
func findJar(c *plugins.Client, rec *plugins.Record, r *zip.Reader, n string) {
	// filename
	name, version := parseJarFilename(filepath.Base(n[:len(n)-4]))
	r.WalkFiles(func(f *zip.File) {
		if strings.HasSuffix(f.Name, ".jar") {
			rec.Data.Fields["name"], rec.Data.Fields["sversion"] = parseJarFilename(filepath.Base(f.Name[:len(f.Name)-4]))
			rec.Data.Fields["path"] = filepath.Join(r.Name(), f.Name)
			rec.Timestamp = time.Now().Unix()
			c.SendRecord(rec)
		}
		// 补全jar包版本
		if version == "" && f.Name == "META-INF/MANIFEST.MF" {
			if r, err := f.Open(); err == nil {
				for sc := bufio.NewScanner(r); sc.Scan(); {
					if strings.HasPrefix(sc.Text(), "Implementation-Version:") {
						version = strings.TrimSpace(sc.Text()[len("Implementation-Version:"):])
						break
					}
					r.Close()
				}
			}
		}
	})
	rec.Data.Fields["name"] = name
	rec.Data.Fields["sversion"] = version
	rec.Data.Fields["path"] = r.Name()
	rec.Timestamp = time.Now().Unix()
	c.SendRecord(rec)
}

func (h *SoftwareHandler) Handle(c *plugins.Client, cache *engine.Cache, seq string) {
	// scan dpkg
	if f, err := os.Open("/var/lib/dpkg/status"); err == nil {
		s := bufio.NewScanner(io.LimitReader(f, 25*1024*1024))
		s.Split(func(data []byte, atEOF bool) (advance int, token []byte, err error) {
			if atEOF && len(data) == 0 {
				return 0, nil, nil
			}
			if i := strings.Index(string(data), "\nPackage: "); i >= 0 {
				return i + 1, data[0:i], nil
			}
			if atEOF {
				return len(data), data, nil
			}
			return
		})
		for s.Scan() {
			lines := strings.Split(s.Text(), "\n")
			s := &Software{
				Type: "dpkg",
			}
			for _, line := range lines {
				fields := strings.SplitN(line, ": ", 2)
				if len(fields) != 2 {
					continue
				}
				switch fields[0] {
				case "Package":
					s.Name = fields[1]
				case "Version":
					s.Version = fields[1]
				case "Source":
					s.Source = fields[1]
				case "Status":
					s.Status = fields[1]
				}
			}
			r := &plugins.Record{
				DataType:  int32(h.DataType()),
				Timestamp: time.Now().Unix(),
				Data: &plugins.Payload{
					Fields: make(map[string]string, 12),
				},
			}
			mapstructure.Decode(s, &r.Data.Fields)
			r.Data.Fields["package_seq"] = seq
			c.SendRecord(r)
		}
		f.Close()
	}
	// scan rpm
	if db, err := rpm.OpenDatabase(); err == nil {
		db.WalkPackages(func(p rpm.Package) {
			c.SendRecord(&plugins.Record{
				DataType:  int32(h.DataType()),
				Timestamp: time.Now().Unix(),
				Data: &plugins.Payload{
					Fields: map[string]string{
						"type":        "rpm",
						"package_seq": seq,
						"name":        p.Name,
						"sversion":    p.Version,
						"source_rpm":  p.SourceRpm,
						"vendor":      p.Vendor,
					},
				},
			})
		})
	}
	// scan pypi
	dirs := mapset.NewSet()
	godirwalk.Walk("/usr", &godirwalk.Options{
		FollowSymbolicLinks: false,
		Callback: func(osPathname string, directoryEntry *godirwalk.Dirent) error {
			if strings.HasSuffix(directoryEntry.Name(), ".pth") {
				if f, err := os.Open(osPathname); err == nil {
					r := bufio.NewScanner(io.LimitReader(f, 1024*1024))
					for r.Scan() {
						d := r.Text()
						if filepath.IsAbs(d) && strings.HasPrefix(d, "/usr") && (strings.Contains(d, "site-packages") || strings.Contains(d, "dist-packages")) {
							dirs.Add(d)
						}
					}
					f.Close()
				}
			}
			if strings.HasSuffix(directoryEntry.Name(), ".egg-info") || strings.HasSuffix(directoryEntry.Name(), ".dist-info") {
				if s, err := parsePypiName(directoryEntry.Name()); err == nil {
					r := &plugins.Record{
						DataType:  int32(h.DataType()),
						Timestamp: time.Now().Unix(),
						Data: &plugins.Payload{
							Fields: make(map[string]string, 12),
						},
					}
					mapstructure.Decode(s, &r.Data.Fields)
					r.Data.Fields["package_seq"] = seq
					c.SendRecord(r)
				}
			}
			return nil
		},
	})
	dirs.Each(func(path interface{}) bool {
		godirwalk.Walk(path.(string), &godirwalk.Options{
			FollowSymbolicLinks: false,
			Callback: func(path string, de *godirwalk.Dirent) error {
				if strings.HasSuffix(de.Name(), ".egg-info") || strings.HasSuffix(de.Name(), ".dist-info") {
					if s, err := parsePypiName(de.Name()); err == nil {
						r := &plugins.Record{
							DataType:  int32(h.DataType()),
							Timestamp: time.Now().Unix(),
							Data: &plugins.Payload{
								Fields: make(map[string]string, 12),
							},
						}
						mapstructure.Decode(s, &r.Data.Fields)
						r.Data.Fields["package_seq"] = seq
						c.SendRecord(r)
					}
				}
				return nil
			}})
		return false
	})
	// scan jar
	procs, err := process.Processes(false)
	if err != nil {
		return
	}
	for _, p := range procs {
		time.Sleep(process.TraversalInterval)
		if cm, err := p.Comm(); err == nil && cm == "java" {
			var podName, psm, containerID, containerName, cmdline string
			if pns, err := p.Namespace("pid"); err == nil && process.PnsDiffWithRpns(pns) {
				if envs, err := p.Envs(); err == nil {
					if p, ok := envs["POD_NAME"]; ok {
						podName = p
					} else if p, ok := envs["MY_POD_NAME"]; ok {
						podName = p
					}
					if p, ok := envs["LOAD_SERVICE_PSM"]; ok {
						psm = p
					} else if p, ok := envs["TCE_PSM"]; ok {
						psm = p
					} else if p, ok := envs["RUNTIME_PSM"]; ok {
						psm = p
					}
				}
				if m, ok := cache.Get(5056, "pns"+pns); ok {
					containerID = m["container_id"]
					containerName = m["container_name"]
				}
			}
			cmdline, _ = p.Cmdline()
			rec := &plugins.Record{
				DataType:  int32(h.DataType()),
				Timestamp: time.Now().Unix(),
				Data: &plugins.Payload{
					Fields: map[string]string{
						"type":           "jar",
						"psm":            psm,
						"pod_name":       podName,
						"container_id":   containerID,
						"container_name": containerName,
						"cmdline":        cmdline,
						"pid":            p.Pid(),
						"package_seq":    seq,
					},
				},
			}
			if fs, err := p.Fds(); err == nil {
				set := mapset.NewSet()
				for _, fn := range fs {
					if filepath.Ext(fn) == ".jar" {
						if set.Contains(fn) ||
							(filepath.Base(fn) != "rt.jar" &&
								(strings.Contains(fn, "jdk") || strings.Contains(fn, "jre"))) {
							continue
						}
						if r, err := zip.OpenReader(filepath.Join("/proc", p.Pid(), "root", fn)); err == nil {
							findJar(c, rec, r, fn)
							r.Close()
						}
						set.Add(fn)
					}
				}
			}
		}
	}
}
