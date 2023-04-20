package dbtask

import (
	"context"
	"fmt"
	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/bytedance/Elkeid/server/manager/infra/mongodb"
	"github.com/rs/xid"
	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/bson"
	"testing"
	"time"
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

func TestHubAssetAsyncWrite(t *testing.T) {
	w := hubAssetWriter{}
	w.Init()
	go w.Run()

	seq := fmt.Sprintf("seq-%s", xid.New().String())
	tests := []map[string]interface{}{
		{"id": 1, "agent_id": "test_agent_id", "package_seq": seq, "data_type": "5051", "in_ipv4_list": "127.0.0.1,127.0.0.2", "in_ipv6_list": "127.0.0.1,127.0.0.2"},
		{"id": 2, "agent_id": "test_agent_id", "package_seq": seq, "data_type": "5051", "in_ipv4_list": "127.0.0.1,127.0.0.2", "in_ipv6_list": "127.0.0.1,127.0.0.2"},
		{"id": 3, "agent_id": "test_agent_id", "package_seq": seq, "data_type": "5051", "in_ipv4_list": "127.0.0.1,127.0.0.2", "in_ipv6_list": "127.0.0.1,127.0.0.2"},
		{"id": 4, "agent_id": "test_agent_id", "package_seq": seq, "data_type": "5051", "in_ipv4_list": "127.0.0.1,127.0.0.2", "in_ipv6_list": "127.0.0.1,127.0.0.2"},
		{"id": 5, "agent_id": "test_agent_id", "package_seq": seq, "data_type": "5051", "in_ipv4_list": "127.0.0.1,127.0.0.2", "in_ipv6_list": "127.0.0.1,127.0.0.2"},
	}
	for _, vv := range tests {
		w.Add(vv)
	}

	time.Sleep(10 * time.Second)
	col := infra.MongoClient.Database(infra.MongoDatabase).Collection("agent_asset_5051")
	c, err := col.CountDocuments(context.Background(), bson.M{"agent_id": "test_agent_id"})
	if err != nil {
		t.Errorf("CountDocuments error %s", err.Error())
		return
	}

	assert.EqualValues(t, c, len(tests)+1)
}
