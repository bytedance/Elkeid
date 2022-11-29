package main

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bytedance/Elkeid/plugins/collector/engine"
	"github.com/bytedance/Elkeid/plugins/collector/utils"
	plugins "github.com/bytedance/plugins"
	"github.com/karrick/godirwalk"
	"github.com/mitchellh/mapstructure"
)

type CronHandler struct{}

func (h *CronHandler) Name() string {
	return "cron"
}
func (h *CronHandler) DataType() int {
	return 5053
}

type Crontab struct {
	Path     string `mapstructure:"path"`
	Username string `mapstructure:"username"`
	Schedule string `mapstructure:"schedule"`
	Command  string `mapstructure:"command"`
	Checksum string `mapstructure:"checksum"`
}

func parseCrontab(wu bool, path string) (ret []*Crontab, err error) {
	var f *os.File
	f, err = os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	md5, _ := utils.GetMd5(path, "")
	r := bufio.NewScanner(io.LimitReader(f, 1024*1024))
	for r.Scan() {
		line := strings.TrimSpace(r.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		c := &Crontab{
			Checksum: md5,
			Path:     path,
		}
		fields := strings.Fields(line)
		if strings.HasPrefix(line, "@") {
			if wu {
				if len(fields) < 3 {
					continue
				}
				c.Schedule = fields[0]
				c.Username = fields[1]
				c.Command = strings.Join(fields[2:], " ")
			} else {
				if len(fields) < 2 {
					continue
				}
				c.Username = f.Name()
				c.Schedule = fields[0]
				c.Command = strings.Join(fields[1:], " ")
			}
		} else {
			if wu {
				if len(fields) < 7 {
					continue
				}
				c.Schedule = strings.Join(fields[:5], " ")
				c.Username = fields[5]
				c.Command = strings.Join(fields[6:], " ")
			} else {
				if len(fields) < 6 {
					continue
				}
				c.Username = filepath.Base(f.Name())
				c.Schedule = strings.Join(fields[:5], " ")
				c.Command = strings.Join(fields[5:], " ")
			}
		}
		ret = append(ret, c)
	}
	return
}

func (h *CronHandler) Handle(c *plugins.Client, cache *engine.Cache, seq string) {
	godirwalk.Walk("/var/spool/cron", &godirwalk.Options{
		Callback: func(osPathname string, directoryEntry *godirwalk.Dirent) error {
			if ok, err := directoryEntry.IsDirOrSymlinkToDir(); err == nil && !ok {
				if cs, err := parseCrontab(false, osPathname); err == nil {
					for _, ct := range cs {
						rec := &plugins.Record{
							DataType:  int32(h.DataType()),
							Timestamp: time.Now().Unix(),
							Data: &plugins.Payload{
								Fields: make(map[string]string, 7),
							},
						}
						mapstructure.Decode(ct, &rec.Data.Fields)
						rec.Data.Fields["package_seq"] = seq
						c.SendRecord(rec)
					}
				}
			}
			return nil
		},
		FollowSymbolicLinks: false,
	})
	godirwalk.Walk("/etc/cron.d", &godirwalk.Options{
		Callback: func(osPathname string, directoryEntry *godirwalk.Dirent) error {
			if ok, err := directoryEntry.IsDirOrSymlinkToDir(); err == nil && !ok {
				if cs, err := parseCrontab(true, osPathname); err == nil {
					for _, ct := range cs {
						rec := &plugins.Record{
							DataType:  int32(h.DataType()),
							Timestamp: time.Now().Unix(),
							Data: &plugins.Payload{
								Fields: make(map[string]string, 7),
							},
						}
						mapstructure.Decode(ct, &rec.Data.Fields)
						rec.Data.Fields["package_seq"] = seq
						c.SendRecord(rec)
					}
				}
			}
			return nil
		},
		FollowSymbolicLinks: false,
	})
}
