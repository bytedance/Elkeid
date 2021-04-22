package main

import (
	"bufio"
	"io"
	"os"
	"strings"
)

func GetSshdConfig() (config map[string]string, err error) {
	var f *os.File
	f, err = os.Open("/etc/ssh/sshd_config")
	if err != nil {
		return
	}
	defer f.Close()
	config = make(map[string]string)
	config["pubkey_authentication"] = "yes"
	config["passwd_authentication"] = "yes"
	s := bufio.NewScanner(io.LimitReader(f, 1024*1024))
	for s.Scan() {
		fields := strings.Fields(s.Text())
		if len(fields) != 2 {
			continue
		}
		switch strings.TrimSpace(fields[0]) {
		case "PasswordAuthentication":
			config["passwd_authentication"] = strings.TrimSpace(fields[1])
		case "PubkeyAuthentication":
			config["pubkey_authentication"] = strings.TrimSpace(fields[1])
		}
	}
	return
}
