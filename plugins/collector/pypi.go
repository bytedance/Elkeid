package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bytedance/plugins"
	mapset "github.com/deckarep/golang-set"
	"github.com/karrick/godirwalk"
	"go.uber.org/zap"
)

type Pypi struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Pyversion string `json:"pyversion"`
}

const (
	MaxPackageNum = 5000
)

func parsePypi(name string) (pkg Pypi, err error) {
	n := strings.TrimSuffix(strings.TrimSuffix(name, ".egg-info"), ".dist-info")
	fileds := strings.SplitN(n, "-", 3)
	switch len(fileds) {
	case 1:
		pkg = Pypi{Name: fileds[0]}
	case 2:
		pkg = Pypi{Name: fileds[0], Version: fileds[1]}
	case 3:
		pkg = Pypi{Name: fileds[0], Version: fileds[1], Pyversion: fileds[2]}
	}
	if pkg.Name == "" {
		err = errors.New("invalid format")
	}
	return
}

func GetPypi() {
	var pypis []Pypi
	dirs := mapset.NewSet()
	zap.S().Info("scanning pypi")
	godirwalk.Walk("/usr", &godirwalk.Options{
		FollowSymbolicLinks: false,
		Callback: func(path string, de *godirwalk.Dirent) error {
			if strings.HasSuffix(de.Name(), ".pth") {
				f, err := os.Open(path)
				if err == nil {
					r := bufio.NewScanner(io.LimitReader(f, 2*1024*1024))
					for r.Scan() {
						text := r.Text()
						if filepath.IsAbs(text) && !strings.HasPrefix(text, "/usr") && (strings.Contains(text, "site-packages") || strings.Contains(text, "dist-packages")) {
							dirs.Add(text)
						}
					}
					f.Close()
				}
			}
			if strings.HasSuffix(de.Name(), ".egg-info") || strings.HasSuffix(de.Name(), ".dist-info") {
				pypi, err := parsePypi(de.Name())
				if err == nil {
					pypis = append(pypis, pypi)
				}
			}
			return nil
		}})
	dirs.Each(func(path interface{}) bool {
		if len(pypis) >= MaxPackageNum {
			return true
		}
		godirwalk.Walk(path.(string), &godirwalk.Options{
			FollowSymbolicLinks: false,
			Callback: func(path string, de *godirwalk.Dirent) error {
				if strings.HasSuffix(de.Name(), ".egg-info") || strings.HasSuffix(de.Name(), ".dist-info") {
					pkg, err := parsePypi(de.Name())
					if err == nil {
						pypis = append(pypis, pkg)
					}
				}
				return nil
			}})
		return false
	})
	zap.S().Infof("scan pypi done, total: %v\n", len(pypis))
	data, _ := json.Marshal(pypis)
	rec := &plugins.Record{
		DataType:  5006,
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
		GetPypi()
		time.Sleep(time.Hour)
		SchedulerMu.Lock()
		Scheduler.AddFunc(fmt.Sprintf("%d %d * * *", rand.Intn(60), rand.Intn(6)), GetPypi)
		SchedulerMu.Unlock()
	}()
}
