package main

import (
	"bufio"
	"io"
	"os"
	"strings"
	"time"

	"github.com/bytedance/Elkeid/plugins/collector/engine"
	"github.com/bytedance/Elkeid/plugins/collector/utils"
	plugins "github.com/bytedance/plugins"
	mapset "github.com/deckarep/golang-set"
	"github.com/karrick/godirwalk"
	"github.com/mitchellh/mapstructure"
)

var SearchDir = []string{
	"/etc/systemd/system.control", "/run/systemd/system.control", "/run/systemd/transient",
	"/run/systemd/generator.early", "/etc/systemd/system", "/run/systemd/system",
	"/run/systemd/generator", "/usr/local/lib/systemd/system", "/usr/lib/systemd/system", "/run/systemd/generator.late"}

type ServiceHandler struct{}

func (h *ServiceHandler) Name() string {
	return "service"
}
func (h *ServiceHandler) DataType() int {
	return 5054
}

type Service struct {
	Name       string `mapstructure:"name"`
	Type       string `mapstructure:"type"`
	Command    string `mapstructure:"command"`
	Restart    string `mapstructure:"restart"`
	WorkingDir string `mapstructure:"working_dir"`
	Checksum   string `mapstructure:"checksum"`
	BusName    string `mapstructure:"bus_name"`
}

func (s *Service) SetDefault() {
	if s.Command != "" && s.Type == "" && s.BusName == "" {
		s.Type = "simple"
	} else if s.Command == "" && s.Type == "" {
		s.Type = "oneshot"
	} else if s.Type == "" && s.BusName != "" {
		s.Type = "dbus"
	}
}
func (h *ServiceHandler) Handle(c *plugins.Client, cache *engine.Cache, seq string) {
	set := mapset.NewSet()
	for _, dir := range SearchDir {
		godirwalk.Walk(dir, &godirwalk.Options{
			Callback: func(path string, de *godirwalk.Dirent) error {
				if strings.HasSuffix(de.Name(), ".service") && (de.IsRegular() || de.IsSymlink()) && !set.Contains(de.Name()) {
					if f, err := os.Open(path); err == nil {
						set.Add(de.Name())
						defer f.Close()
						s := bufio.NewScanner(io.LimitReader(f, 1024*1024))
						u := &Service{Name: de.Name(), Restart: "false"}
						for s.Scan() {
							fields := strings.Split(s.Text(), "=")
							if len(fields) != 2 {
								continue
							}
							switch strings.TrimSpace(fields[0]) {
							case "Type":
								u.Type = strings.TrimSpace(fields[1])
							case "ExecStart":
								u.Command = strings.TrimSpace(fields[1])
							case "Restart":
								if u.Restart == "no" {
									u.Restart = "false"
								} else {
									u.Restart = "true"
								}
							case "WorkingDirectory":
								u.WorkingDir = strings.TrimSpace(fields[1])
							}
						}
						u.Checksum, _ = utils.GetMd5(path, "")
						u.SetDefault()
						rec := &plugins.Record{
							DataType:  int32(h.DataType()),
							Timestamp: time.Now().Unix(),
							Data: &plugins.Payload{
								Fields: make(map[string]string, 7),
							},
						}
						mapstructure.Decode(u, &rec.Data.Fields)
						rec.Data.Fields["package_seq"] = seq
						c.SendRecord(rec)
					}
				}
				return nil
			},
			FollowSymbolicLinks: false})
	}
}
