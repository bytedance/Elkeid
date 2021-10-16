package main

import (
	"bufio"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/karrick/godirwalk"
)

type Cron struct {
	Minute     string `json:"minute"`
	Hour       string `json:"hour"`
	DayOfMonth string `json:"day_of_month"`
	Month      string `json:"month"`
	DayOfWeek  string `json:"day_of_week"`
	User       string `json:"user"`
	Command    string `json:"command"`
	Path       string `json:"path"`
}

func parse(withUser bool, path string, file *os.File) (crons []Cron) {
	r := bufio.NewScanner(io.LimitReader(file, 1024*1024))
	for r.Scan() {
		line := r.Text()
		if line != "" && strings.TrimSpace(line)[0] == '#' {
			continue
		} else if strings.Contains(line, "@reboot") {
			fields := strings.Fields(line)
			cron := Cron{
				Minute:     "@reboot",
				Hour:       "@reboot",
				DayOfMonth: "@reboot",
				Month:      "@reboot",
				DayOfWeek:  "@reboot",
				Path:       path,
			}
			if len(fields) >= 2 {
				if withUser {
					cron.User = file.Name()
					cron.Command = strings.Join(fields[1:], " ")
				} else if len(fields) >= 3 {
					cron.User = fields[1]
					cron.Command = strings.Join(fields[2:], " ")
				}
			}
			crons = append(crons, cron)
		} else {
			fields := strings.Fields(line)
			if len(fields) >= 6 {
				cron := Cron{
					Minute:     fields[0],
					Hour:       fields[1],
					DayOfMonth: fields[2],
					Month:      fields[3],
					DayOfWeek:  fields[4],
					Path:       path,
				}
				if withUser {
					cron.User = filepath.Base(file.Name())
					cron.Command = strings.Join(fields[5:], " ")
				} else if len(fields) >= 7 {
					cron.User = fields[5]
					cron.Command = strings.Join(fields[6:], " ")
				}
				crons = append(crons, cron)
			}
		}
	}
	return
}

func GetCron(rootfs string) (crons []Cron, err error) {
	godirwalk.Walk(rootfs+"/var/spool/cron", &godirwalk.Options{Callback: func(path string, de *godirwalk.Dirent) error {
		if de.IsRegular() {
			f, err := os.Open(path)
			if err != nil {
				return nil
			}
			crons = append(crons, parse(true, path, f)...)
			f.Close()
		}
		return nil
	}})
	godirwalk.Walk(rootfs+"/etc/cron.d", &godirwalk.Options{Callback: func(path string, de *godirwalk.Dirent) error {
		if de.IsRegular() {
			f, err := os.Open(path)
			if err != nil {
				return nil
			}
			crons = append(crons, parse(false, path, f)...)
			f.Close()
		}
		return nil
	}})
	if f, e := os.Open(rootfs + "/etc/crontab"); e == nil {
		crons = append(crons, parse(false, rootfs+"/etc/crontab", f)...)
		f.Close()
	}
	if len(crons) == 0 {
		err = errors.New("crontab is empty")
	}
	return
}
