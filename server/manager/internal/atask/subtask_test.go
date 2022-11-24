package atask

import (
	"encoding/json"
	"github.com/bytedance/Elkeid/server/manager/internal/dbtask"
	. "github.com/bytedance/mockey"
	"testing"
)

func TestPushSubTask(t *testing.T) {
	dbMocker := Mock(dbtask.SubTaskUpdateAsyncWrite).To(func(value interface{}) {
		b, _ := json.Marshal(value)
		t.Logf("result: %s", string(b))
	}).Build()

	RegistryResFunc("5100", ResFuncOld) //5100: 主动触发资产数据扫描
	RegistryResFunc("8010", ResFuncOld) //8010: 基线扫描
	RegistryResFunc("6000", nil)

	testCases := []struct {
		name string
		data map[string]interface{}
	}{
		{"test_5100", map[string]interface{}{"token": "11111", "data_type": "5100", "status": "succeed", "msg": "No such file or directory"}},
		{"test_5101", map[string]interface{}{"token": "22222", "data_type": "5101", "status": "succeed", "msg": `{"Name":"test":"Version":"1","Result":"true"}`}},
		{"test_8010", map[string]interface{}{"token": "33333", "data_type": "8010", "status": "succeed", "msg": "No such file or directory"}},
		{"test_6000", map[string]interface{}{"token": "44444", "data_type": "6000", "status": "succeed", "msg": "No such file or directory"}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			PushSubTask(tc.data)
		})
	}
	dbMocker.UnPatch()
}
