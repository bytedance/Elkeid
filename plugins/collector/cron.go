package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bytedance/plugins"
	"github.com/karrick/godirwalk"
	"go.uber.org/zap"
)

type Cron struct {
	Path     string `json:"path"`
	Username string `json:"username"`
	Schedule string `json:"schedule"`
	Command  string `json:"command"`
	Runparts string `json:"runparts"`
	Checksum string `json:"checksum"`
}

func parse(withUser bool, path string, file *os.File) (crons []Cron) {
	r := bufio.NewScanner(io.LimitReader(file, 1024*1024))
	checksum, _ := GetMd5ByPath(path)
	for r.Scan() {
		line := r.Text()
		if line != "" && strings.TrimSpace(line)[0] == '#' {
			continue
		} else if strings.Contains(line, "@reboot") {
			fields := strings.Fields(line)
			cron := Cron{
				Schedule: "@reboot",
				Path:     path,
				Checksum: checksum,
			}
			if len(fields) >= 2 {
				if withUser {
					cron.Username = file.Name()
					cron.Command = strings.Join(fields[1:], " ")
					runParts := false
					for _, field := range fields[1:] {
						if field == "run-parts" {
							runParts = true
							continue
						}
						if runParts && strings.HasPrefix(field, "/") {
							dir, err := os.ReadDir(field)
							if err != nil {
								continue
							}
							for _, entry := range dir {
								if entry.Type().Perm()&0111 != 0 {
									if cron.Runparts != "" {
										cron.Runparts += ","
									}
									cron.Runparts += entry.Name()
								}
							}
							break
						}
					}
				} else if len(fields) >= 3 {
					cron.Username = fields[1]
					cron.Command = strings.Join(fields[2:], " ")
					runParts := false
					for _, field := range fields[2:] {
						if field == "run-parts" {
							runParts = true
							continue
						}
						if runParts && strings.HasPrefix(field, "/") {
							dir, err := os.ReadDir(field)
							if err != nil {
								continue
							}
							for _, entry := range dir {
								if entry.Type().Perm()&0111 != 0 {
									if cron.Runparts != "" {
										cron.Runparts += ","
									}
									cron.Runparts += entry.Name()
								}
							}
							break
						}
					}
				}
			}
			crons = append(crons, cron)
		} else {
			fields := strings.Fields(line)
			if len(fields) >= 6 {
				cron := Cron{
					Schedule: strings.Join(fields[0:5], " "),
					Path:     path,
					Checksum: checksum,
				}
				if withUser {
					cron.Username = filepath.Base(file.Name())
					cron.Command = strings.Join(fields[5:], " ")
					runParts := false
					for _, field := range fields[5:] {
						if field == "run-parts" {
							runParts = true
							continue
						}
						if runParts && strings.HasPrefix(field, "/") {
							dir, err := os.ReadDir(field)
							if err != nil {
								continue
							}
							for _, entry := range dir {
								if entry.Type().Perm()&0111 != 0 {
									if cron.Runparts != "" {
										cron.Runparts += ","
									}
									cron.Runparts += entry.Name()
								}
							}
							break
						}
					}
				} else if len(fields) >= 7 {
					cron.Username = fields[5]
					cron.Command = strings.Join(fields[6:], " ")
					runParts := false
					for _, field := range fields[6:] {
						if field == "run-parts" {
							runParts = true
							continue
						}
						if runParts && strings.HasPrefix(field, "/") {
							dir, err := os.ReadDir(field)
							if err != nil {
								continue
							}
							for _, entry := range dir {
								info, err := entry.Info()
								if err != nil {
									continue
								}
								if info.Mode().Perm()&0111 != 0 {
									if cron.Runparts != "" {
										cron.Runparts += ","
									}
									cron.Runparts += entry.Name()
								}
							}
							break
						}
					}
				}
				crons = append(crons, cron)
			}
		}
	}
	return
}

func GetCron() {
	crons := []Cron{}
	zap.S().Info("scanning crontab")
	godirwalk.Walk("/var/spool/cron", &godirwalk.Options{
		Callback: func(path string, de *godirwalk.Dirent) error {
			if de.IsRegular() || de.IsSymlink() {
				f, err := os.Open(path)
				if err != nil {
					return nil
				}
				crons = append(crons, parse(true, path, f)...)
				f.Close()
			}
			return nil
		}})
	godirwalk.Walk("/etc/cron.d", &godirwalk.Options{
		Callback: func(path string, de *godirwalk.Dirent) error {
			if de.IsRegular() || de.IsSymlink() {
				f, err := os.Open(path)
				if err != nil {
					return nil
				}
				crons = append(crons, parse(false, path, f)...)
				f.Close()
			}
			return nil
		}})
	if f, e := os.Open("/etc/crontab"); e == nil {
		crons = append(crons, parse(false, "/etc/crontab", f)...)
		f.Close()
	}
	zap.S().Infof("scan crontab done, total: %v\n", len(crons))
	data, _ := json.Marshal(crons)
	rec := &plugins.Record{
		DataType:  5003,
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
		GetCron()
		time.Sleep(time.Hour)
		SchedulerMu.Lock()
		Scheduler.AddFunc(fmt.Sprintf("%d %d * * *", rand.Intn(60), rand.Intn(6)), GetCron)
		// Scheduler.AddFunc("@every 3m", GetCron)
		SchedulerMu.Unlock()
	}()
}
