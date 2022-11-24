package kube

import (
	"fmt"
	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/bytedance/Elkeid/server/manager/infra/mongodb"
	. "github.com/bytedance/mockey"
	"testing"
)

func TestMain(m *testing.M) {
	var err error
	infra.MongoDatabase = "admin"
	if infra.MongoClient, err = mongodb.NewMongoClient("mongodb://127.0.0.1:27017/admin?authSource=admin"); err != nil {
		fmt.Println("NewMongoClient", err.Error())
		panic(-1)
	}
	m.Run()
}

func TestUpdateKubeStatus(t *testing.T) {
	Mock(getActiveCluster).Return([]string{"11111-111111-11111"}, nil).Build()
	err := updateKubeStatus()
	if err != nil {
		t.Errorf("getSSHLog error%s", err.Error())
	}
}
