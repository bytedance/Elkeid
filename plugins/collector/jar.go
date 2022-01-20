package main

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/bytedance/plugins"
	"go.uber.org/zap"
)

type Jar struct {
	Name    string `json:"name"`
	Source  string `json:"source"`
	Version string `json:"version"`
}

var (
	VersionReg = regexp.MustCompile(`-[0-9]+\.`)
)

const (
	MaxJarNum = 10000
)

func FormatPids(pids []int) string {
	if len(pids) == 0 {
		return ""
	} else {
		base := " [PID:"
		for index, pid := range pids {
			if index == 0 {
				base += " " + strconv.Itoa(pid)
			} else {
				base += ", " + strconv.Itoa(pid)
			}
		}
		return base + "]"
	}
}

func GetJar() {
	pids, err := GetPids()
	jarMap := map[string][]int{}
	if err == nil {
		for _, pid := range pids {
			exe, err := GetProcessExe(pid)
			if err == nil && strings.Contains(exe, "java") {
				files, err := GetProcessOpenedFiles(pid)
				if err == nil {
					for _, file := range files {
						if strings.HasSuffix(file, ".jar") && !strings.Contains(file, "jre/lib") {
							name := filepath.Base(file[:len(file)-4])
							jarMap[name] = append(jarMap[name], pid)
						}
					}
				}
			}
			time.Sleep(time.Duration(ProcessScanIntervalMillSec) * time.Millisecond)
		}
	}
	jars := []Jar{}
	for k, v := range jarMap {
		if len(jars) >= MaxJarNum {
			break
		}
		jar := Jar{}
		index := VersionReg.FindStringIndex(k)
		if len(index) == 0 {
			jar.Name = k + FormatPids(v)
			jar.Source = k
		} else {
			jar.Version = k[(index[0] + 1):]
			jar.Source = k[:(index[0])]
			jar.Name = k[:(index[0])] + FormatPids(v)
		}
		jars = append(jars, jar)
	}
	zap.S().Infof("scan jar done, total: %v\n", len(jars))
	data, _ := json.Marshal(jars)
	rec := &plugins.Record{
		DataType:  5011,
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
		GetJar()
		time.Sleep(time.Hour)
		SchedulerMu.Lock()
		Scheduler.AddFunc(fmt.Sprintf("%d * * * *", rand.Intn(60)), GetJar)
		// Scheduler.AddFunc("@every 3m", GetJar)
		SchedulerMu.Unlock()
	}()
}
