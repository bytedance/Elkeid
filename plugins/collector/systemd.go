package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"os"
	"strings"
	"time"

	"github.com/bytedance/plugins"
	"github.com/karrick/godirwalk"
	"go.uber.org/zap"
)

type SystemdUnit struct {
	Name             string `json:"name"`
	Type             string `json:"type"`
	Command          string `json:"command"`
	Restart          bool   `json:"restart"`
	WorkingDirectory string `json:"working_directory"`
	Checksum         string `json:"checksum"`
}

var SearchDir = []string{
	"/etc/systemd/system.control", "/run/systemd/system.control", "/run/systemd/transient",
	"/run/systemd/generator.early", "/etc/systemd/system", "/run/systemd/system",
	"/run/systemd/generator", "/usr/local/lib/systemd/system", "/usr/lib/systemd/system", "/run/systemd/generator.late"}

func GetSystemdUnit() {
	units := []SystemdUnit{}
	for _, dir := range SearchDir {
		if len(units) >= MaxPackageNum {
			break
		}
		godirwalk.Walk(dir, &godirwalk.Options{
			Callback: func(path string, de *godirwalk.Dirent) error {
				if (de.IsRegular() || de.IsSymlink()) && strings.HasSuffix(de.Name(), ".service") {
					f, err := os.Open(path)
					if err == nil {
						s := bufio.NewScanner(io.LimitReader(f, 1024*1024))
						unit := SystemdUnit{Name: de.Name(), Restart: false}
						for s.Scan() {
							fields := strings.Split(s.Text(), "=")
							if len(fields) != 2 {
								continue
							}
							switch strings.TrimSpace(fields[0]) {
							case "Type":
								unit.Type = strings.TrimSpace(fields[1])
							case "ExecStart":
								unit.Command = strings.TrimSpace(fields[1])
							case "Restart":
								unit.Restart = !(strings.TrimSpace(fields[1]) == "no")
							case "WorkingDirectory":
								unit.WorkingDirectory = strings.TrimSpace(fields[1])
							}
						}
						unit.Checksum, _ = GetMd5ByPath(path)
						units = append(units, unit)
						f.Close()
					}
				}
				return nil
			}})
	}
	zap.S().Infof("scan systemd done, total units: %v\n", len(units))
	data, _ := json.Marshal(units)
	rec := &plugins.Record{
		DataType:  5010,
		Timestamp: time.Now().Unix(),
		Data: &plugins.Payload{
			Fields: map[string]string{"data": string(data)},
		},
	}
	Client.SendRecord(rec)
}

func init() {
	go func() {
		rand.Seed(time.Now().UnixNano())
		time.Sleep(time.Second * time.Duration(rand.Intn(600)))
		GetSystemdUnit()
		time.Sleep(time.Hour)
		SchedulerMu.Lock()
		Scheduler.AddFunc(fmt.Sprintf("%d %d * * *", rand.Intn(60), rand.Intn(6)), GetSystemdUnit)
		SchedulerMu.Unlock()
	}()
}
