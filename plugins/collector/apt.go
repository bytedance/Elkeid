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

func GetAptConfig() (config map[string]string, err error) {
	config = make(map[string]string)
	sourcesList := []string{}
	var f *os.File
	f, err = os.Open("/etc/apt/sources.list")
	if err == nil {
		s := bufio.NewScanner(io.LimitReader(f, 1024*1024))
		for s.Scan() {
			if !strings.HasPrefix(s.Text(), "#") {
				sourcesList = append(sourcesList, strings.TrimSpace(s.Text()))
			}
		}
		f.Close()
	}
	godirwalk.Walk("/etc/apt/sources.list.d", &godirwalk.Options{FollowSymbolicLinks: false, Callback: func(path string, de *godirwalk.Dirent) error {
		if de.IsRegular() {
			f, err := os.Open(path)
			if err == nil {
				s := bufio.NewScanner(io.LimitReader(f, 1024*1024))
				for s.Scan() {
					if !strings.HasPrefix(s.Text(), "#") {
						sourcesList = append(sourcesList, strings.TrimSpace(s.Text()))
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
		err = errors.New("Apt config is empty")
	}
	return
}
