package config

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"time"

	"github.com/bytedance/Elkeid/agent/plugin"
	"github.com/fsnotify/fsnotify"
	"go.uber.org/config"
	"go.uber.org/zap"
)

var ConfigPath = ""

type cfg struct {
	Name    string
	Version string
	Path    string
	SHA256  string
}

func parseConfig() error {
	f, err := os.Open("config.yaml")
	if err != nil {
		return err
	}
	defer f.Close()
	config, err := config.NewYAML(config.Source(f))
	if err != nil {
		return err
	}
	var plugins []cfg
	err = config.Get("plugins").Populate(&plugins)
	if err != nil {
		return err
	}
	s, err := plugin.GetServer()
	if err != nil {
		return err
	}
	for _, c := range plugins {
		p, ok := s.Get(c.Name)
		if !ok || p.Version() != c.Version {
			zap.S().Infof("Update config:%+v", c)
			s.Delete(c.Name)
			f, e := os.Open(c.Path)
			if err == nil {
				hasher := sha256.New()
				io.Copy(hasher, f)
				checksum := hasher.Sum(nil)
				f.Close()
				if hex.EncodeToString(checksum) != c.SHA256 {
					zap.S().Error("Checksum doesn't match")
					continue
				}
			} else {
				zap.S().Error(e)
				continue
			}
			new, err := plugin.NewPlugin(c.Name, c.Version, c.SHA256, c.Path)
			if err != nil {
				zap.S().Error(err)
				continue
			}
			s.Insert(c.Name, new)
			if err := new.Run(); err != nil {
				zap.S().Error(err)
				s.Delete(c.Name)
			} else {
				go func(n string) {
					time.Sleep(time.Second * 30)
					if !new.Connected() {
						zap.S().Errorf("Plugin seems to be dead:%v", new)
						s.Delete(n)
					}
				}(c.Name)
			}
		}
	}
	loadedPlugins := s.PluginList()
	for _, name := range loadedPlugins {
		del := true
		for _, c := range plugins {
			if name == c.Name {
				del = false
				break
			}
		}
		if del {
			zap.S().Infof("Delete plugin:%v", name)
			s.Delete(name)
		}
	}
	return nil
}
func Watcher() {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		zap.S().Error(err)
	}
	err = watcher.Add("config.yaml")
	if err == nil {
		err := parseConfig()
		if err != nil {
			zap.S().Error(err)
		}
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if event.Op&fsnotify.Write == fsnotify.Write {
					err := parseConfig()
					if err != nil {
						zap.S().Error(err)
					}
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					zap.S().Error(err)
					return
				}
			}
		}
	} else {
		zap.S().Error(err)
	}
}
