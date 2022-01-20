package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"time"

	"github.com/bytedance/plugins"
	"go.uber.org/zap"
)

func parseDebList() (debs []map[string]string, err error) {
	var f *os.File
	debs = []map[string]string{}
	f, err = os.Open("/var/lib/dpkg/status")
	if err != nil {
		return
	}
	defer f.Close()
	s := bufio.NewScanner(f)
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
		if len(debs) >= MaxPackageNum {
			break
		}
		deb := map[string]string{}
		lines := strings.Split(s.Text(), "\n")
		for _, line := range lines {
			fields := strings.SplitN(line, ": ", 2)
			if len(fields) == 2 {
				key := strings.ReplaceAll(strings.ToLower(fields[0]), "-", "_")
				if key == "package" {
					key = "name"
				}
				switch key {
				case "name", "status", "maintainer", "architecture", "multi_arch", "source", "version":
					deb[key] = strings.TrimSpace(fields[1])
				}
			}
		}
		debs = append(debs, deb)
	}
	return
}

func GetDeb() {
	debs, _ := parseDebList()
	zap.S().Infof("scan deb done, total: %v\n", len(debs))
	data, _ := json.Marshal(debs)
	rec := &plugins.Record{
		DataType:  5004,
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
		GetDeb()
		time.Sleep(time.Hour)
		SchedulerMu.Lock()
		Scheduler.AddFunc(fmt.Sprintf("%d %d * * *", rand.Intn(60), rand.Intn(6)), GetDeb)
		// Scheduler.AddFunc("@every 3m", GetDeb)
		SchedulerMu.Unlock()
	}()
}
