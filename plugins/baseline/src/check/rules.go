package check

import (
	"bufio"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

/* This file is a baseline check rule file, and all rule function parameters are constrained as follows:
The parameter is unique: [] string. Then in the function, determine the length of the array and define the actual meaning of each element
Return value:
	1. value： return value
	2. err： error
*/

// CommandCheck Get command line result
// 1. Command statement 2. Special parameters (ignore_exit ignore the error, the error is considered passed)
func CommandCheck(param []string) (result interface{}, err error) {
	var special string
	switch len(param) {
	case 1:
	case 2:
		special = param[1]
	default:
		errStr := fmt.Sprintf("%d:command_check params num error", ErrorConfigWrite)
		return "", errors.New(errStr)
	}
	command := param[0]
	argArray := strings.Split(command, " ")

	cmd := exec.Command(argArray[0], argArray[1:]...)
	buf, err := cmd.Output() // Ignore cmd error
	if err != nil {
		if special == "ignore_exit" {
			return true, nil
		} else {
			return false, nil
		}
	}
	return string(buf), err
}

// IfFileExist Determine if the file exists
// 1. File absolute path
func IfFileExist(param []string) (result interface{}, err error) {
	switch len(param) {
	case 1:
	default:
		errStr := fmt.Sprintf("%d:if_file_exist params num error", ErrorConfigWrite)
		return "", errors.New(errStr)
	}
	filePath := param[0]
	_, err = os.Stat(filePath)
	if err != nil {
		return false, nil
	} else {
		return true, nil
	}
}

// ResultMatchFunc Traverse the file line, match
// 1. The absolute path of the file
// 2. The flag of the line
// 3. Comment character of the file (optional parameter), if the line is commented, it will be considered not to pass
type ResultMatchFunc func(RuleStruct, interface{}) (bool, error)

func FileLineCheck(ruleStruct RuleStruct, resultMatch ResultMatchFunc) (result bool, err error) {
	// Determine if there are prerequisites
	switch ruleStruct.Require {
	case "":
		break
	case "allow_ssh_passwd":
		if IfAllowSshPasswd() {
			break
		} else {
			return true, nil
		}
	}

	note := "#"
	flag := ""

	filePath := ruleStruct.Param[0]
	if len(ruleStruct.Param) >= 2 {
		flag = ruleStruct.Param[1]
	}
	if len(ruleStruct.Param) >= 3 {
		note = ruleStruct.Param[2]
	}

	if file, err := os.Open(filePath); err != nil {
		if strings.Contains(err.Error(), "no such") {
			// Errors where the file does not exist are not reported
			err = nil
		} else {
			errStr := fmt.Sprintf("%d:open file %s Error %s", ErrorFile, filePath, err.Error())
			return false, errors.New(errStr)
		}
	} else {
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			// If the line is commented, skip
			line := strings.TrimSpace(scanner.Text())
			if len(line) > len(note) && note == line[:len(note)] {
				continue
			}

			// If flag exists, only rows of flag are matched
			if flag != "" {
				if !strings.Contains(line, flag) {
					continue
				}
			}

			// Match whether it hits
			ifPass, _ := resultMatch(ruleStruct, scanner.Text())
			if ifPass {
				return true, nil
			}
		}
	}
	return false, nil
}

// FilePermission Determine file permissions
// 1. The absolute path of the file
// 2. File permissions (chmod out of base 8)
func FilePermission(ruleStruct RuleStruct) (result int, err error) {
	if len(ruleStruct.Param) < 1 {
		return 0, fmt.Errorf("FilePermission param length need at least 1")
	}
	filePath := ruleStruct.Param[0]
	var fileNeedMode int
	// validate the result
	switch ruleStruct.Result.(type) {
	case int:
		fileNeedMode = ruleStruct.Result.(int)
	case string:
		fileNeedMode, err = strconv.Atoi(ruleStruct.Result.(string))
		if err != nil {
			return 0, fmt.Errorf("%d:rule is int, but get other type", ErrorConfigWrite)
		}
	default:
		return 0, fmt.Errorf("%d:rule is int, but get other type", ErrorConfigWrite)
	}

	fileInfo, err := os.Stat(filePath)
	if err != nil {
		if strings.Contains(err.Error(), "no such file") {
			return fileNeedMode, nil
		}
		return
	}

	return strconv.Atoi(strconv.FormatInt(int64(fileInfo.Mode()), 8))
}

// FileUserGroup Determine the file user group
// 1. The absolute path of the file
// 2. File user id: groupId
func FileUserGroup(param []string) (result bool, err error) {
	if len(param) < 2 {
		return false, fmt.Errorf("FileUserGroup param length need at least 2")
	}
	filePath := param[0]
	res := strings.Split(param[1], ":")
	if len(res) != 2 {
		return false, fmt.Errorf("file_user_group rule wrong!")
	}
	userNeedId := res[0]
	groupNeedId := res[1]

	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return
	}
	userRealId := strconv.FormatUint(uint64(fileInfo.Sys().(*syscall.Stat_t).Uid), 10)
	groupRealId := strconv.FormatUint(uint64(fileInfo.Sys().(*syscall.Stat_t).Gid), 10)

	if userNeedId == userRealId && groupNeedId == groupRealId {
		return true, err
	}

	return false, err
}

// FileMd5Check Determine whether the file MD5 is consistent
// 1. The absolute path of the file
// 2. File MD5
func FileMd5Check(param []string) (result bool, err error) {
	if len(param) < 2 {
		return false, fmt.Errorf("file_md5_check param length need at least 2")
	}

	filePath := param[0]
	fileMd5 := param[1]
	file, err := os.Open(filePath)
	if err != nil {
		return false, fmt.Errorf("file_md5_check : no file find %s", filePath)
	}
	fileContentByte, err := ioutil.ReadAll(file)
	if err != nil {
		return false, err
	}

	hash := md5.New()
	hash.Write(fileContentByte)
	if fileMd5 == hex.EncodeToString(hash.Sum(nil)) {
		return true, nil
	} else {
		return false, nil
	}
}

// FuncCheck Special baseline rules
// 1. Baseline rule identification
func FuncCheck(param []string) (result interface{}, err error) {
	if len(param) < 1 {
		errStr := fmt.Sprintf("%d:command_check params num error", ErrorConfigWrite)
		return "", errors.New(errStr)
	}

	var funcRes bool
	switch param[0] {
	case "Ensure no duplicate user names exist":
		funcRes = IfDuplicateUser()
	}
	return funcRes, nil
}

// IfDuplicateUser Check if duplicate username does not exist
func IfDuplicateUser() bool {
	file, _ := os.Open("/etc/passwd")
	scanner := bufio.NewScanner(file)
	userSet := make(map[string]string, 0)
	for scanner.Scan() {
		// If the line is commented, skip
		index := strings.Index(scanner.Text(), ":")
		if index != -1 {
			username := scanner.Text()[:index]
			if _, ok := userSet[username]; ok {
				fmt.Println(username)
				return false
			} else {
				userSet[username] = ""
			}
		}
	}
	return true
}

// IfAllowSshPasswd Determine whether the ssh password login is turned open
func IfAllowSshPasswd() bool {
	file, _ := os.Open("/etc/ssh/sshd_config")
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// If the line is commented, skip
		if len(line) > 2 && "#" == line[:1] {
			continue
		}
		if strings.Contains(line, "PasswordAuthentication") {
			if strings.Contains(line, "yes") {
				return true
			}
		}
	}
	return false
}
