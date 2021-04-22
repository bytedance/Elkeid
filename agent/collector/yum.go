package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"

	"github.com/karrick/godirwalk"
)

func GetYumConfig() (config map[string]string, err error) {
	config = make(map[string]string)
	sourcesList := []string{}
	var f *os.File
	f, err = os.Open("/etc/yum.conf")
	if err == nil {
		s := bufio.NewScanner(io.LimitReader(f, 1024*1024))
		for s.Scan() {
			fields := strings.Split(s.Text(), "=")
			if len(fields) == 2 && strings.TrimSpace(fields[0]) == "baseurl" {
				sourcesList = append(sourcesList, strings.TrimSpace(fields[1]))
			}
		}
		f.Close()
	}
	godirwalk.Walk("/etc/yum.repos.d", &godirwalk.Options{FollowSymbolicLinks: false, Callback: func(path string, de *godirwalk.Dirent) error {
		if de.IsRegular() {
			f, err := os.Open(path)
			if err == nil {
				s := bufio.NewScanner(io.LimitReader(f, 1024*1024))
				for s.Scan() {
					fields := strings.Split(s.Text(), "=")
					if len(fields) == 2 && strings.TrimSpace(fields[0]) == "baseurl" {
						sourcesList = append(sourcesList, strings.TrimSpace(fields[1]))
					}
				}
				f.Close()
			}
		}
		return nil
	}})
	if len(sourcesList) > 0 {
		encodedSourceList, err := json.Marshal(sourcesList)
		if err == nil {
			config["sources"] = string(encodedSourceList)
		}
	} else {
		err = errors.New("Yum config is empty")
	}
	return
}
