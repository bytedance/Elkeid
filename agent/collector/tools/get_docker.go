package main

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/prometheus/procfs"
)

type container struct {
	pids    []int
	podName string
}

// caculate huge file md5
func HashFileMd5(filePath string) (string, error) {
	//Initialize variable returnMD5String now in case an error has to be returned
	var returnMD5String string
	//Open the passed argument and check for any error
	file, err := os.Open(filePath)
	defer file.Close()
	if err != nil {
		return returnMD5String, err
	}
	//Tell the program to call the following function when the current function returns
	//Open a new hash interface to write to
	hash := md5.New()
	//Copy the file in the hash interface and check for any error
	//if _, err := io.Copy(hash, file); err != nil {
	//	return returnMD5String, err
	//}
	// calculate the file size
	info, _ := file.Stat()
	filesize := info.Size()
	const filechunk = 8192 // we settle for 8KB
	blocks := uint64(math.Ceil(float64(filesize) / float64(filechunk)))
	for i := uint64(0); i < blocks; i++ {
		time.Sleep(100 * time.Millisecond)
		blocksize := int(math.Min(filechunk, float64(filesize-int64(i*filechunk))))
		buf := make([]byte, blocksize)
		file.Read(buf)
		io.WriteString(hash, string(buf)) // append into the hash
	}
	time.Sleep(200 * time.Millisecond)
	//Get the 16 bytes hash
	hashInBytes := hash.Sum(nil)[:16]
	//Convert the bytes to a string
	returnMD5String = hex.EncodeToString(hashInBytes)
	return returnMD5String, nil
}

func main() {
	nsMapping := make(map[string]*container)
	self, err := procfs.Self()
	var mountNsInode, pidNsInode uint32
	if err != nil {
		return
	}
	nss, err := self.Namespaces()
	if err != nil {
		return
	}
	for _, ns := range nss {
		if ns.Type == "mnt" {
			mountNsInode = ns.Inode
		} else if ns.Type == "pid" {
			pidNsInode = ns.Inode
		}
	}
	if mountNsInode == 0 || pidNsInode == 0 {
		return
	}
	innerNsMapping := make(map[string]*container)
	procs, err := procfs.AllProcs()
	if err != nil {
		return
	}
	for _, proc := range procs {
		nss, err := proc.Namespaces()
		if err != nil {
			continue
		}
		var procMountNsInode, procPidNsInode uint32
		for _, ns := range nss {
			if ns.Type == "mnt" {
				procMountNsInode = ns.Inode
			} else if ns.Type == "pid" {
				procPidNsInode = ns.Inode
			}
		}
		var podName string
		envs, err := proc.Environ()
		for _, env := range envs {
			fields := strings.Split(env, "=")
			if len(fields) == 2 && (strings.TrimSpace(fields[0]) == "POD_NAME" || strings.TrimSpace(fields[0]) == "MY_POD_NAME") {
				podName = strings.TrimSpace(fields[1])
			}
		}
		if procMountNsInode != 0 && procPidNsInode != 0 && procMountNsInode != mountNsInode && procPidNsInode != pidNsInode && podName != "" {
			key := strconv.FormatUint(uint64(procMountNsInode), 10) + "|" + strconv.FormatUint(uint64(procPidNsInode), 10)
			ct, ok := innerNsMapping[key]
			if ok {
				ct.pids = append(innerNsMapping[key].pids, proc.PID)
			} else {
				innerNsMapping[key] = &container{podName: podName}
			}
		}
	}
	nsMapping = innerNsMapping
	for k, v := range nsMapping {
		fmt.Println(k, *v)
	}
}
