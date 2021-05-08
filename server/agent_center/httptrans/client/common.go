package client

import (
	"github.com/bytedance/Elkeid/server/agent_center/common"
	"math/rand"
	"time"
)

func init() {
	rand.Seed(time.Now().Unix())
}

func getRandomManageAddr() string {
	return common.ManageAddrs[rand.Intn(len(common.ManageAddrs))]

}
