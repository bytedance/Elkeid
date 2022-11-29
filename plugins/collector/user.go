package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	_ "embed"

	"github.com/GehirnInc/crypt"
	_ "github.com/GehirnInc/crypt/sha256_crypt"
	_ "github.com/GehirnInc/crypt/sha512_crypt"
	"github.com/bytedance/Elkeid/plugins/collector/engine"
	"github.com/bytedance/Elkeid/plugins/collector/utils"
	plugins "github.com/bytedance/plugins"
	"github.com/mitchellh/mapstructure"
	"go.uber.org/zap"
)

type UserHandler struct{}

func (*UserHandler) Name() string {
	return "user"
}
func (*UserHandler) DataType() int {
	return 5052
}

type utmp struct {
	Typ int16
	// alignment
	_    [2]byte
	Pid  int32
	Line [32]byte
	Id   [4]byte
	User [32]byte
	Host [256]byte
	Exit struct {
		Termination int16
		Exit        int16
	}
	Session int32
	Time    struct {
		Sec  int32
		Usec int32
	}
	Addr [16]byte
	// Reserved member
	Unused [20]byte
}

func maskPassword(pwd string) string {
	mpwd := []byte(pwd)
	switch len(pwd) {
	case 0:
		return ""
	case 1:
		return "*"
	case 2, 3:
		mpwd[1] = '*'
		return string(mpwd)
	case 4:
		mpwd[1] = '*'
		mpwd[2] = '*'
		return string(mpwd)
	default:
		for i := 2; i < len(mpwd)-2; i++ {
			mpwd[i] = '*'
		}
		return string(mpwd)
	}
}

type User struct {
	Username            string `mapstructure:"username"`
	Password            string `mapstructure:"password"`
	Uid                 string `mapstructure:"uid"`
	Gid                 string `mapstructure:"gid"`
	Groupname           string `mapstructure:"groupname"`
	Info                string `mapstructure:"info"`
	Home                string `mapstructure:"home"`
	Shell               string `mapstructure:"shell"`
	LastLoginTime       string `mapstructure:"last_login_time"`
	LastLoginIP         string `mapstructure:"last_login_ip"`
	WeakPassword        string `mapstructure:"weak_password"`
	WeakPasswordContent string `mapstructure:"weak_password_content"`
	Sudoers             string `mapstructure:"sudoers"`
}

//go:embed weak_password
var weakPassword string

func verifyWeak(hashed string) (string, string) {
	fields := strings.Split(hashed, "$")
	if len(fields) < 4 {
		return "true", "not valid format"
	}
	method := fields[1]
	if method == "1" {
		return "true", "weak algorithm"
	}
	var crypter crypt.Crypter
	switch method {
	case "5":
		crypter = crypt.SHA256.New()
	case "6":
		crypter = crypt.SHA512.New()
	default:
		return "false", ""
	}
	salt := fields[2]
	lines := bufio.NewScanner(strings.NewReader(weakPassword))
	for lines.Scan() {
		pw, err := crypter.Generate([]byte(lines.Text()), []byte("$"+method+"$"+salt))
		if err != nil {
			continue
		}
		if pw == hashed {
			return "true", maskPassword(lines.Text())
		}

	}
	return "false", ""
}

func (h *UserHandler) Handle(c *plugins.Client, cache *engine.Cache, seq string) {
	f, err := os.Open("/etc/passwd")
	if err != nil {
		zap.S().Error(err)
	}
	m := map[string]*User{}
	s := bufio.NewScanner(f)
	for s.Scan() {
		fields := strings.Split(s.Text(), ":")
		if len(fields) == 0 {
			continue
		}
		padding := len(fields)
		for i := 0; i < 7-padding; i++ {
			fields = append(fields, "")
		}
		u := &User{
			Username: fields[0],
			Password: fields[1],
			Uid:      fields[2],
			Gid:      fields[3],
			Info:     fields[4],
			Home:     fields[5],
			Shell:    fields[6],
		}
		u.Groupname, _ = utils.GetGroupname(fields[3])
		m[fields[0]] = u
	}
	f.Close()
	// maybe should read /var/log/wtmp* ?
	f, err = os.Open("/var/log/wtmp")
	if err == nil {
		for {
			l := &utmp{}
			if er := binary.Read(f, binary.LittleEndian, l); er == nil {
				username := bytes.TrimRight(l.User[:], "\x00")
				ip := bytes.TrimRight(l.Addr[:], "\x00")
				if u, ok := m[string(username)]; ok {
					u.LastLoginIP = net.IP(ip).String()
					u.LastLoginTime = strconv.FormatInt(int64(l.Time.Sec), 10)
				}
			} else {
				break
			}
		}
		f.Close()
	}
	f, err = os.Open("/etc/shadow")
	if err == nil {
		s := bufio.NewScanner(f)
		for s.Scan() {
			fields := strings.Split(s.Text(), ":")
			if len(fields) < 2 {
				continue
			}
			if u, ok := m[fields[0]]; ok {
				if strings.Contains(fields[1], "*") || strings.Contains(fields[1], "!") {
					u.WeakPassword, u.WeakPasswordContent = "false", ""
				} else {
					u.WeakPassword, u.WeakPasswordContent = verifyWeak(fields[1])
				}
			}
		}
	}
	for _, u := range m {
		cmd := exec.Command("sudo", "-l", "-U", u.Username)
		output, err := cmd.CombinedOutput()
		if err == nil {
			if i := bytes.Index(output, []byte("may run the following commands")); i > 0 {
				output = output[i:]
				if i := bytes.IndexByte(output, ':'); i > 0 && len(output) > i+1 {
					output = output[i+1:]
					u.Sudoers = string(bytes.TrimSpace(output))
				}
			}
		}
		rec := &plugins.Record{
			DataType:  int32(h.DataType()),
			Timestamp: time.Now().Unix(),
			Data: &plugins.Payload{
				Fields: make(map[string]string, 12),
			},
		}
		mapstructure.Decode(u, &rec.Data.Fields)
		rec.Data.Fields["package_seq"] = seq
		c.SendRecord(rec)
	}
}
