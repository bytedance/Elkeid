package main

import "C"

import (
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"plugin"
	"time"
	"unsafe"
)

//go:linkname FirstModuleData runtime.firstmoduledata
var FirstModuleData interface{}

//export GetFirstModuleData
func GetFirstModuleData() uintptr {
    return uintptr(unsafe.Pointer(&FirstModuleData))
}

func execTest()  {
	_ = exec.Command("ls").Run()
}

func fileTest()  {
	_, _ = os.Create("/tmp/test")
	_ = os.Rename("/tmp/test", "/tmp/test1")
	_, _ = ioutil.ReadDir("/tmp/")
	_ = os.Remove("/tmp/test1")
}

func dialTest()  {
	_, _ = net.Dial("tcp", "baidu.com:80")

	tcpAddr, err := net.ResolveTCPAddr("tcp4", "baidu.com:80")
	if err == nil {
		_, _ = net.DialTCP("tcp", nil, tcpAddr)
	}

	udpAddr, err := net.ResolveUDPAddr("udp", "8.8.8.8:53")
	if err == nil {
		_, _ = net.DialUDP("udp", nil, udpAddr)
	}

	ipAddr, err := net.ResolveIPAddr("ip", "baidu.com")
	if err == nil {
		_, _ = net.DialIP("ip4:icmp", nil, ipAddr)
	}

	unixAddr, err := net.ResolveUnixAddr("unix", "/tmp/test")
	if err == nil {
		_, _ = net.DialUnix("unix", nil, unixAddr)
	}
}

func lookupTest()  {
	_, _ = net.LookupAddr("www.baidu.com")
	_, _ = net.LookupCNAME("www.baidu.com")
	_, _ = net.LookupHost("www.baidu.com")
	_, _ = net.LookupPort("tcp", "http")
	_, _ = net.LookupTXT("www.baidu.com")
	_, _ = net.LookupIP("www.baidu.com")
	_, _ = net.LookupMX("www.baidu.com")
	_, _ = net.LookupNS("www.baidu.com")
}

func pluginTest()  {
	_, _ = plugin.Open("/tmp/test")
}

//export GOStart
func GOStart() {
    for {
		execTest()
		fileTest()
		dialTest()
		lookupTest()
		pluginTest()

        time.Sleep(time.Second * 10)
    }
}

func main() {
	GOStart()
}