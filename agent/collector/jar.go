import (
	"fmt"
	"github.com/shirou/gopsutil/process"
	log "github.com/sirupsen/logrus"
	"lucci-agent/agent/beat"
	"lucci-agent/agent/util"
	"os"
	"strings"
	"time"
)

/*
===============================================================================
1. check logic
===============================================================================
Bootstrap classes of your JVM
/WEB-INF/classes of your web application
/WEB-INF/lib/*.jar of your web application
System class loader classes (described above)
Common class loader classes (described above)

===============================================================================
2. todo
===============================================================================
ref https://stackoverflow.com/questions/264828/controlling-the-classpath-in-a-servlet
*/

// all Jar
type JarObject struct {
	ProcessID      int32    `json:"process_id"`
	ProcessExe     string   `json:"process_exe"`
	ProcessCmdline string   `json:"process_cmdline"`
	JarPath        []string `json:"jar_path"`
	Image          string   `json:"image"`
}
type JarObjectList struct {
	Jars []JarObject `json:"jars"`
}

// danger jar
type DangerJarObject struct {
	ProcessID      int32    `json:"process_id"`
	ProcessExe     string   `json:"process_exe"`
	ProcessCmdline string   `json:"process_cmdline"`
	DangerJarPath  []string `json:"danger_jar_path"`
	Image          string   `json:"image"`
}
type DangerJarObjectList struct {
	DangerJars []DangerJarObject `json:"danger_jars"`
}

// getProcInodes returnes fd of the pid.
func getProcInodes(pid int32, max int) (ret []string, danger_jar []string, err error) {
	dir := fmt.Sprintf("/proc/%d/fd", pid)
	f, err := os.Open(dir)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	files, err := f.Readdir(max)
	if err != nil {
		return nil, nil, err
	}
	for _, fd := range files {
		time.Sleep(100 * time.Millisecond)
		inodePath := fmt.Sprintf("/proc/%d/fd/%s", pid, fd.Name())
		inode, err := os.Readlink(inodePath)
		if err != nil {
			continue
		}
		if strings.HasSuffix(inode, ".jar") {
			if jarIsDanger(inode) {
				danger_jar = append(danger_jar, inode)
			}
			ret = append(ret, inode)
		}
	}
	return ret, danger_jar, nil
}

func jarIsDanger(inode string) (ret bool) {
	if strings.Contains(inode, "/fastjson") {
		return true
	}
	if strings.Contains(inode, "/struts2-") {
		return true
	}
	if strings.Contains(inode, "/spring") {
		return true
	}
	if strings.Contains(inode, "/shiro-") {
		return true
	}
	if strings.Contains(inode, "/jackson-") {
		return true
	}
	if strings.Contains(inode, "/commons-fileupload-") {
		return true
	}
	if strings.Contains(inode, "/log4j-") {
		return true
	}
	if strings.Contains(inode, "/jenkins-") {
		return true
	}
	if strings.Contains(inode, "/solr-") {
		return true
	}
	if strings.Contains(inode, "/xstream-") {
		return true
	}
	// TODO: 验证weblogic
	if strings.Contains(inode, "weblogic-") {
		return true
	}
	// TODO: 验证jboss
	if strings.Contains(inode, "jboss-") {
		return true
	}
	return false
}

// 可能会有遗漏，但是准确性高
func GetProcJarList(b *beat.Beat) (jarObjectList JarObjectList, dangerJarObjectList DangerJarObjectList) {
	processes, err := process.Processes()
	if err != nil {
		log.Error(err)
		return jarObjectList, dangerJarObjectList
	}
	for _, p := range processes {
		name, err := p.Name()
		if err != nil {
			continue
		}
		if name == "java" {
			jarObject := JarObject{}
			dangerJarObject := DangerJarObject{}

			jarObject.ProcessID = p.Pid
			dangerJarObject.ProcessID = p.Pid

			exe, err := p.Exe()
			if err != nil {
				continue
			}

			jarObject.ProcessExe = exe
			dangerJarObject.ProcessExe = exe

			cmdline, err := p.Cmdline()
			if err != nil {
				continue
			}

			jarObject.ProcessCmdline = cmdline
			dangerJarObject.ProcessCmdline = cmdline

			pidString := util.GetDockerContainerID(p.Pid)
			jarObject.Image = b.GetDockerImage(pidString)
			dangerJarObject.Image = b.GetDockerImage(pidString)

			jarObject.JarPath, dangerJarObject.DangerJarPath, err = getProcInodes(p.Pid, 1000)
			if err == nil {
				if len(jarObject.JarPath) > 0 {
					jarObjectList.Jars = append(jarObjectList.Jars, jarObject)
				}
				if len(dangerJarObject.DangerJarPath) > 0 {
					dangerJarObjectList.DangerJars = append(dangerJarObjectList.DangerJars, dangerJarObject)
				}
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	return jarObjectList, dangerJarObjectList
}
