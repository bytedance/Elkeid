package plugin

import (
	"errors"
	"net"
	"os"
	"os/exec"
	"path"
	"strconv"
	"syscall"
	"time"

	"github.com/prometheus/procfs"
	"github.com/tinylib/msgp/msgp"
	"go.uber.org/atomic"
	"go.uber.org/zap"
)

// The time to wait before forcing the plug-in to kill,
// this is to leave the necessary time for the plugin to the clean environment normally
const exitTimeout = 1 * time.Second

// Plugin contains the process, socket, metadata and other information of a plugin
type Plugin struct {
	name       string
	version    string
	checksum   string
	cmd        *exec.Cmd
	conn       net.Conn
	runtimePID int
	pgid       int
	IO         uint64
	CPU        float64
	reader     *msgp.Reader
	exited     atomic.Value
	Counter    atomic.Uint64
}

// Name func returns the name of the plugin
func (p *Plugin) Name() string {
	return p.name
}

// Version func returns the version of the plugin
func (p *Plugin) Version() string {
	return p.version
}

// Checksum func returns the checksum of the plugin
func (p *Plugin) Checksum() string {
	return p.checksum
}

// PID func returns the real run pid of the plugin
func (p *Plugin) PID() int {
	return p.runtimePID
}

// Close func is used to close this plugin,
// when closing it will kill all processes under the same process group
func (p *Plugin) Close(timeout bool) {
	p.exited.Store(true)
	if p.conn != nil {
		p.conn.Close()
	}
	if timeout {
		time.Sleep(exitTimeout)
	}
	if p.pgid != 0 {
		syscall.Kill(-p.pgid, syscall.SIGKILL)
	}
	if p.cmd != nil && p.cmd.Process != nil {
		p.cmd.Process.Kill()
	}
}

// Receive func is used to read data from the socket connection of plugin
func (p *Plugin) Receive() (*PluginData, error) {
	data := &PluginData{}
	err := data.DecodeMsg(p.reader)
	p.Counter.Add(uint64(len(*data)))
	return data, err
}

// Send func is used to send tasks to this plugin
func (p *Plugin) Send(t Task) error {
	w := msgp.NewWriter(p.conn)
	err := t.EncodeMsg(w)
	if err != nil {
		return err
	}
	err = w.Flush()
	return err
}

func (p *Plugin) Run() error {
	if p.cmd == nil {
		return errors.New("Plugin cmd is nil")
	}
	err := p.cmd.Start()
	if err != nil {
		return err
	}
	go p.cmd.Wait()
	if p.cmd.Process == nil {
		return errors.New("Plugin cmd process is nil")
	}
	pgid, err := syscall.Getpgid(p.cmd.Process.Pid)
	if err != nil {
		return err
	}
	p.pgid = pgid
	return nil
}

func (p *Plugin) Connected() bool {
	return p.conn != nil
}

// Connect func is used to verify the connection request,
// if the pgid is inconsistent, an error will be returned
// Note that it is necessary to call Server's Delete func to clean up after this func returns error
func (p *Plugin) Connect(req RegistRequest, conn net.Conn) error {
	if p.conn != nil {
		return errors.New("The same plugin has been connected, it may be a malicious attack")
	}
	reqPgid, err := syscall.Getpgid(int(req.Pid))
	if err != nil {
		return errors.New("Cann't get req process which pid is " + strconv.FormatUint(uint64(req.Pid), 10))
	}
	cmdPgid, err := syscall.Getpgid(p.cmd.Process.Pid)
	if err != nil {
		return errors.New("Cann't get cmd process which pid is " + strconv.FormatUint(uint64(p.cmd.Process.Pid), 10))
	}
	if reqPgid != cmdPgid {
		return errors.New("Pgid does not match")
	}
	p.runtimePID = int(req.Pid)
	proc, err := procfs.NewProc(p.runtimePID)
	if err == nil {
		procIO, err := proc.IO()
		if err == nil {
			p.IO = procIO.ReadBytes + procIO.WriteBytes
		}
		procStat, err := proc.Stat()
		if err == nil {
			p.CPU = procStat.CPUTime()
		}
	}
	p.conn = conn
	p.version = req.Version
	p.name = req.Name
	p.reader = msgp.NewReaderSize(conn, 8*1024)

	return nil
}

// NewPlugin func creates a new plugin instance
func NewPlugin(name, version, checksum, runPath string) (*Plugin, error) {
	var err error
	dir, file := path.Split(runPath)
	zap.S().Infof("Plugin work directory: %s", dir)
	c := exec.Command(runPath)
	c.Dir = dir
	c.Stderr, err = os.OpenFile(dir+file+".stderr", os.O_RDWR|os.O_CREATE, 0700)
	if err != nil {
		return nil, err
	}
	c.Stdin = nil
	c.Stdout, err = os.OpenFile(dir+file+".stdout", os.O_RDWR|os.O_CREATE, 0700)
	if err != nil {
		return nil, err
	}
	c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pgid: 0}
	exited := atomic.Value{}
	exited.Store(false)
	p := Plugin{cmd: c, name: name, version: version, checksum: checksum, exited: exited}
	return &p, nil
}
