package v6

import (
	"time"

	"github.com/bytedance/Elkeid/server/manager/biz/common"
	"github.com/gin-gonic/gin"
)

type LicenseDetailResp struct {
	Company string            `json:"company_name"`
	Status  LicenseDetailInfo `json:"status"`
}
type LicenseOverviewResp struct {
	Company string              `json:"company_name"`
	Status  LicenseOverviewInfo `json:"status"`
}
type LicenseDetailInfo struct {
	HUB   LicenseDetailInfoItem `json:"hub"`
	Trace LicenseDetailInfoItem `json:"trace"`
	K8s   LicenseDetailInfoItem `json:"k8s"`
	Rule  LicenseDetailInfoItem `json:"rule"`
	Rasp  LicenseDetailInfoItem `json:"rasp"`
}
type LicenseOverviewInfo struct {
	HUB   bool `json:"hub"`
	Trace bool `json:"trace"`
	K8s   bool `json:"k8s"`
	Rule  bool `json:"rule"`
	Rasp  bool `json:"rasp"`
}
type LicenseDetailInfoItem struct {
	Status    string `json:"status"`
	Expired   int64  `json:"expire_time"`
	AllCores  int    `json:"all_cores"`
	UsedCores int    `json:"used_cores"`
}

func LicenseDetail(c *gin.Context) {
	status := "activated"
	expired := time.Now().Unix() + 99999
	cores := 0
	HUBInfo := LicenseDetailInfoItem{
		Status:    status,
		Expired:   expired,
		AllCores:  200,
		UsedCores: cores,
	}
	HIDSInfo := LicenseDetailInfoItem{
		Status:    status,
		Expired:   expired,
		AllCores:  200,
		UsedCores: 0,
	}
	TraceInfo := LicenseDetailInfoItem{
		Status:    status,
		Expired:   expired,
		AllCores:  200,
		UsedCores: 0,
	}
	CloudNativeInfo := LicenseDetailInfoItem{
		Status:    status,
		Expired:   expired,
		AllCores:  200,
		UsedCores: 0,
	}
	RASPInfo := LicenseDetailInfoItem{
		Status:    status,
		Expired:   expired,
		AllCores:  200,
		UsedCores: 0,
	}
	info := LicenseDetailInfo{
		HUB:   HUBInfo,
		Trace: TraceInfo,
		K8s:   CloudNativeInfo,
		Rule:  HIDSInfo,
		Rasp:  RASPInfo,
	}
	resp := LicenseDetailResp{
		Company: "Elkeid Open Source",
		Status:  info,
	}
	common.CreateResponse(c, common.SuccessCode, resp)
	return
}
func LicenseOverview(c *gin.Context) {
	info := LicenseOverviewInfo{
		HUB:   true,
		Trace: true,
		K8s:   true,
		Rule:  true,
		Rasp:  true,
	}
	resp := LicenseOverviewResp{
		Company: "Elkeid Open Source",
		Status:  info,
	}
	common.CreateResponse(c, common.SuccessCode, resp)
}
