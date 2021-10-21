package socket

import "testing"

func TestNetstat(t *testing.T) {
	netstat, err := netstatGetSocket(true)
	t.Logf("%+v %+v", len(netstat), err)
	netlink, err := netlinkGetSocket(true)
	t.Logf("%+v %+v", len(netlink), err)
}
