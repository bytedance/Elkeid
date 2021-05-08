package main

import (
	"bufio"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	mapset "github.com/deckarep/golang-set"
	"github.com/karrick/godirwalk"
)

type PypiPackage struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Pyversion string `json:"pyversion"`
}

func parsePypiPackage(name string) (pkg PypiPackage, err error) {
	n := strings.TrimSuffix(strings.TrimSuffix(name, ".egg-info"), ".dist-info")
	fileds := strings.SplitN(n, "-", 3)
	switch len(fileds) {
	case 1:
		pkg = PypiPackage{Name: fileds[0]}
	case 2:
		pkg = PypiPackage{Name: fileds[0], Version: fileds[1]}
	case 3:
		pkg = PypiPackage{Name: fileds[0], Version: fileds[1], Pyversion: fileds[2]}
	}
	if pkg.Name == "" {
		err = errors.New("Invalid format")
	}
	return
}

func GetPypiPackage(rootfs string) (packages []PypiPackage, err error) {
	dirs := mapset.NewSet()
	godirwalk.Walk(rootfs+"/usr", &godirwalk.Options{FollowSymbolicLinks: false, Callback: func(path string, de *godirwalk.Dirent) error {
		if strings.HasSuffix(de.Name(), ".pth") {
			f, err := os.Open(path)
			if err == nil {
				r := bufio.NewScanner(io.LimitReader(f, 2*1024*1024))
				for r.Scan() {
					text := r.Text()
					if filepath.IsAbs(text) && !strings.HasPrefix(text, rootfs+"/usr") && (strings.Contains(text, "site-packages") || strings.Contains(text, "dist-packages")) {
						dirs.Add(text)
					}
				}
				f.Close()
			}
		}
		if strings.HasSuffix(de.Name(), ".egg-info") || strings.HasSuffix(de.Name(), ".dist-info") {
			pkg, err := parsePypiPackage(de.Name())
			if err == nil {
				packages = append(packages, pkg)
			}
		}
		return nil
	}})
	dirs.Each(func(path interface{}) bool {
		godirwalk.Walk(path.(string), &godirwalk.Options{FollowSymbolicLinks: false, Callback: func(path string, de *godirwalk.Dirent) error {
			if strings.HasSuffix(de.Name(), ".egg-info") || strings.HasSuffix(de.Name(), ".dist-info") {
				pkg, err := parsePypiPackage(de.Name())
				if err == nil {
					packages = append(packages, pkg)
				}
			}
			return nil
		}})
		return false
	})
	if len(packages) == 0 {
		err = errors.New("Empty packages")
	}
	return
}
