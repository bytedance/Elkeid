package main

import (
	"bufio"
	"errors"
	"io"
	"os"
	"strings"
)

type DebPackage struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Version string `json:"version"`
}

func GetDebPackage(rootfs string) (packages []DebPackage, err error) {
	var f *os.File
	f, err = os.Open(rootfs + "/var/lib/dpkg/status")
	if err != nil {
		return
	}
	defer f.Close()
	s := bufio.NewScanner(io.LimitReader(f, 10*1024*1024))
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
		pkg := DebPackage{}
		lines := strings.Split(s.Text(), "\n")
		for _, line := range lines {
			fields := strings.SplitN(line, ": ", 2)
			if len(fields) == 2 {
				switch fields[0] {
				case "Package":
					pkg.Name = fields[1]
				case "Status":
					pkg.Status = fields[1]
				case "Version":
					pkg.Version = fields[1]
				}
			}
		}
		packages = append(packages, pkg)
	}
	if len(packages) == 0 {
		err = errors.New("deb packages is empty")
	}
	return
}
