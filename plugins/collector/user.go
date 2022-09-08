package main

import (
	"bufio"
	_ "embed"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/user"
	"strconv"
	"strings"
	"time"

	"github.com/GehirnInc/crypt"
	_ "github.com/GehirnInc/crypt/sha256_crypt"
	_ "github.com/GehirnInc/crypt/sha512_crypt"
	"github.com/bytedance/plugins"
)

//go:embed weak_password
var weakPassword string

func verifyWeak(hashed string) bool {
	fields := strings.Split(hashed, "$")
	if len(fields) < 4 {
		return true
	}
	method := fields[1]
	if method == "1" {
		return true
	}
	var crypter crypt.Crypter
	switch method {
	case "5":
		crypter = crypt.SHA256.New()
	case "6":
		crypter = crypt.SHA512.New()
	default:
		return false
	}
	salt := fields[2]
	lines := bufio.NewScanner(strings.NewReader(weakPassword))
	for lines.Scan() {
		pw, err := crypter.Generate([]byte(lines.Text()), []byte("$"+method+"$"+salt))
		if err != nil {
			continue
		}
		if pw == hashed {
			return true
		}

	}
	return false
}

type Utmp struct {
	Type int16
	// alignment
	_      [2]byte
	Pid    int32
	Device [32]byte
	Id     [4]byte
	User   [32]byte
	Host   [256]byte
	Exit   struct {
		Termination int16
		Exit        int16
	}
	Session int32
	Time    struct {
		Sec  int32
		Usec int32
	}
	AddrV6 [16]byte
	// Reserved member
	Reserved [20]byte
}
type User struct {
	Username      string `json:"username"`
	Password      string `json:"password"`
	UID           uint32 `json:"uid"`
	GID           uint32 `json:"gid"`
	GroupName     string `json:"group_name"`
	Info          string `json:"info"`
	HomeDir       string `json:"home_dir"`
	Shell         string `json:"shell"`
	LastLoginTime uint64 `json:"last_login_time"`
	LastLoginIP   net.IP `json:"last_login_ip"`
	WeakPassword  bool   `json:"weak_password"`
}

func GetUser() {
	rec := &plugins.Record{
		DataType:  5002,
		Timestamp: time.Now().Unix(),
	}
	userMap := make(map[string]*User, 30)
	var passwd *os.File
	passwd, err := os.Open("/etc/passwd")
	if err != nil {
		return
	}
	defer passwd.Close()
	passwdScanner := bufio.NewScanner(passwd)
	for passwdScanner.Scan() {
		line := passwdScanner.Text()
		fields := strings.Split(line, ":")
		/*fields是切片,在for遍历中使用append,fields长度将动态增长,6-len(fields)结果会变,
		使用变量接收6-len(fields)值
		*/
		count := 6 - len(fields)
		for i := 0; i < count; i++ {
			fields = append(fields, "")
		}
		if len(fields) < 7 { //避免发生越界panic
			continue
		}
		u := User{Username: fields[0], Password: fields[1], Info: fields[4], HomeDir: fields[5], Shell: fields[6]}
		uid, _ := strconv.ParseUint(fields[2], 10, 32)
		gid, _ := strconv.ParseUint(fields[3], 10, 32)
		u.UID = uint32(uid)
		u.GID = uint32(gid)
		group, err := user.LookupGroupId(fields[3])
		if err == nil {
			u.GroupName = group.Name
		}
		userMap[fields[0]] = &u
	}
	wtmp, err := os.Open("/var/log/wtmp")
	if err == nil {
		defer wtmp.Close()
		for {
			u := Utmp{}
			e := binary.Read(wtmp, binary.LittleEndian, &u)
			if e != nil {
				break
			}
			username := strings.TrimRight(string(u.User[:]), "\x00")
			ip := strings.TrimRight(string(u.Host[:]), "\x00")
			user, ok := userMap[username]
			if ok {
				user.LastLoginIP = net.ParseIP(ip)
				user.LastLoginTime = uint64(u.Time.Sec)
			}
		}
	}
	shadow, err := os.Open("/etc/shadow")
	if err == nil {
		defer shadow.Close()
		shadowScanner := bufio.NewScanner(shadow)
		for shadowScanner.Scan() {
			line := shadowScanner.Text()
			fields := strings.Split(line, ":")
			if len(fields) < 2 {
				continue
			}
			user, ok := userMap[fields[0]]
			if ok {
				if strings.Contains(fields[1], "*") || strings.Contains(fields[1], "!") {
					continue
				}
				user.WeakPassword = verifyWeak(fields[1])
			}
		}
	}
	users := []User{}
	for _, user := range userMap {
		users = append(users, *user)
	}
	data, _ := json.Marshal(users)
	rec.Data = &plugins.Payload{
		Fields: map[string]string{"data": string(data)},
	}
	Client.SendRecord(rec)
}
func init() {
	go func() {
		rand.Seed(time.Now().UnixNano())
		time.Sleep(time.Second * time.Duration(rand.Intn(600)))
		GetUser()
		time.Sleep(time.Hour)
		SchedulerMu.Lock()
		Scheduler.AddFunc(fmt.Sprintf("%d * * * *", rand.Intn(60)), GetUser)
		SchedulerMu.Unlock()
	}()
}
