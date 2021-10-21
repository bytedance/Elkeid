package socket

import (
	"net"

	"go.uber.org/zap"
)

type Socket struct {
	DPort     uint16 `json:"dport"`
	SPort     uint16 `json:"sport"`
	DIP       net.IP `json:"dip"`
	SIP       net.IP `json:"sip"`
	Interface uint32 `json:"interface"`
	Family    uint8  `json:"family"`
	State     uint8  `json:"state"`
	UID       uint32 `json:"uid"`
	Username  string `json:"username"`
	Inode     uint32 `json:"inode"`
	PID       int32  `json:"pid"`
	Argv      string `json:"argv"`
	Comm      string `json:"comm"`
	Type      uint8  `json:"type"`
}

func GetSocket(disableProc bool) (sockets []Socket, err error) {
	zap.S().Info("Try netlink...")
	sockets, err = netlinkGetSocket(disableProc)
	if err != nil {
		zap.S().Info("Try netstat...")
		sockets, err = netstatGetSocket(disableProc)
		if err != nil {
			zap.S().Error(err)
		}
	}
	return
}
