package main

import (
	"bufio"
	"io"
	"os"
	"strings"

	"github.com/karrick/godirwalk"
)

type SystemdUnit struct {
	Name      string `json:"name"`
	Type      string `json:"type"`
	ExecStart string `json:"exec_start"`
	Restart   string `json:"restart"`
}

var SearchDir = []string{
	"/etc/systemd/system.control", "/run/systemd/system.control", "/run/systemd/transient",
	"/run/systemd/generator.early", "/etc/systemd/system", "/run/systemd/system",
	"/run/systemd/generator", "/usr/local/lib/systemd/system", "/usr/lib/systemd/system", "/run/systemd/generator.late"}

func GetSystemdUnit() (units []SystemdUnit, err error) {
	for _, dir := range SearchDir {
		godirwalk.Walk(dir, &godirwalk.Options{FollowSymbolicLinks: false, Callback: func(path string, de *godirwalk.Dirent) error {
			if de.IsRegular() {
				f, err := os.Open(path)
				if err == nil {
					s := bufio.NewScanner(io.LimitReader(f, 1024*1024))
					unit := SystemdUnit{Name: de.Name()}
					for s.Scan() {
						fields := strings.Split(s.Text(), "=")
						if len(fields) != 2 {
							continue
						}
						switch strings.TrimSpace(fields[0]) {
						case "Type":
							unit.Type = strings.TrimSpace(fields[1])
						case "ExecStart":
							unit.ExecStart = strings.TrimSpace(fields[1])
						case "Restart":
							unit.Restart = strings.TrimSpace(fields[1])
						}
					}
					f.Close()
				}
			}
			return nil
		}})
	}
	return
}
