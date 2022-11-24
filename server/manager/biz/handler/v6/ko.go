package v6

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/bytedance/Elkeid/server/manager/biz/common"
	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/bytedance/Elkeid/server/manager/infra/def"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"github.com/bytedance/Elkeid/server/manager/internal/asset_center"
	"github.com/bytedance/Elkeid/server/manager/internal/atask"
	"github.com/bytedance/Elkeid/server/manager/internal/monitor"
	"github.com/gin-gonic/gin"
	"github.com/levigross/grequests"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

const (
	RedisKoVersionKey = "mutex_ko_%s"
)

func getAgentFirstHeartbeatTime(ctx context.Context, agentID string) (int64, error) {
	var hostInfo asset_center.AgentBasicInfo
	hostCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentHeartBeatCollection)
	err := hostCol.FindOne(ctx, bson.M{"agent_id": agentID}).Decode(&hostInfo)
	if err != nil {
		// 不存在心跳
		if err == mongo.ErrNoDocuments {
			return 0, nil
		} else {
			return 0, err
		}
	}
	return hostInfo.FirstHeartbeatTime, nil
}

func uploadFileToNginx(ctx context.Context, downloadUrl string, uploadPath string) error {
	opts := grequests.RequestOptions{
		InsecureSkipVerify: true,
	}
	resp, err := grequests.Get(downloadUrl, &opts)
	if err != nil {
		ylog.Errorf("Http download "+downloadUrl+" failed: ", err.Error())
		return err
	}
	content := resp.Bytes()

	for _, client := range infra.TosClients {
		object := fmt.Sprintf(uploadPath)
		r := bytes.NewReader(content)
		_, err = client.PutObject(ctx, object, int64(len(content)), r)
		if err != nil {
			return err
		}
	}
	return nil
}

func rebootRecentAgent(ctx context.Context, agentID string) error {
	first, err := getAgentFirstHeartbeatTime(ctx, agentID)
	if err != nil {
		ylog.Errorf("RebootAgentForMissedKo", "Get Agent "+agentID+" First Heartbeat Time failed: %s", err.Error())
		return err
	}

	if first != 0 && time.Now().Unix()-first > 20*60 {
		ylog.Infof("RebootAgentForMissedKo", "Dont reboot Agent "+agentID+", first heartbeat time is %d", first)
		return nil
	}

	taskMsg := def.AgentTaskMsg{
		Name:     "elkeid-agent",
		Data:     "{}",
		DataType: 1060,
	}
	_, err = atask.SendFastTask(agentID, &taskMsg, false, 60, nil)
	// 此时心跳未写入心跳表中，等待3min后重试一次，若失败，3min后再重试一次
	if err != nil && err.Error() == mongo.ErrNoDocuments.Error() {
		ylog.Infof("RebootAgentForMissedKo", "Failed to reboot Agent "+agentID+", after 3 min retry 2 times")
		go func() {
			time.Sleep(time.Minute * 3)
			_, err = atask.SendFastTask(agentID, &taskMsg, false, 60, nil)
			if err != nil {
				time.Sleep(time.Minute * 3)
				_, _ = atask.SendFastTask(agentID, &taskMsg, false, 60, nil)
			}
		}()
	}
	return err
}

func SendAgentDriverKoMissedMsg(c *gin.Context) {
	ctx := context.Background()
	if !monitor.Config.AcceptInformationCollected {
		ylog.Infof("MissedKo", "information collected list not accept")
		common.CreateResponse(c, common.SuccessCode, "not support")
		return
	}

	type HubReq struct {
		AgentID       string `json:"agent_id"`
		Arch          string `json:"arch"`
		KernelVersion string `json:"kernel_version"`
		KmodVersion   string `json:"kmod_version"`
	}
	var req HubReq
	err := c.Bind(&req)
	if err != nil {
		ylog.Errorf("MissedKo", "req bind error: %s", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	if req.AgentID == "" || req.Arch == "" || req.KmodVersion == "" || req.KernelVersion == "" {
		ylog.Errorf("MissedKo", "req is null, %s|%s|%s|", req.AgentID, req.Arch, req.KmodVersion, req.KernelVersion)
		common.CreateResponse(c, common.ParamInvalidErrorCode, "param is null")
		return
	}
	common.CreateResponse(c, common.SuccessCode, "success")

	// 异步获取ko，不堵塞hub plugin
	go func() {
		completeName := fmt.Sprintf("hids_driver_%s_%s_%s", req.KmodVersion, req.KernelVersion, req.Arch)
		lockSuccess, err := infra.Grds.SetNX(context.Background(), fmt.Sprintf(RedisKoVersionKey, completeName), time.Now(), time.Minute*10).Result()
		if err != nil || !lockSuccess {
			rebootErr := rebootRecentAgent(ctx, req.AgentID)
			if rebootErr != nil {
				ylog.Errorf("RebootAgentForMissedKo", "Failed reboot for Agent "+req.AgentID+" "+rebootErr.Error())
			}
			ylog.Infof("MissedKo", "Skip reboot agent for %s", req.AgentID)
			return
		}

		getUrl := fmt.Sprintf("%s?arch=%s&kmod_version=%s&kernel_version=%s&id=%s&email=%s",
			monitor.Config.Report.KoUrl,
			req.Arch, req.KmodVersion, req.KernelVersion, url.QueryEscape(monitor.Config.Report.Uid), url.QueryEscape(monitor.Config.Report.Email))

		opts := grequests.RequestOptions{
			InsecureSkipVerify: true,
		}
		resp, err := grequests.Get(getUrl, &opts)
		if err != nil {
			ylog.Errorf("GetKoDownAddress", err.Error())
			return
		}

		const (
			RespCodeSuccess = iota + 1
		)
		type FetchResponse struct {
			Code        int    `json:"code"`
			Message     string `json:"message"`
			KoAddress   string `json:"ko_address"`
			SignAddress string `json:"sign_address"`
		}
		fetchResp := FetchResponse{}
		err = resp.JSON(&fetchResp)
		if err != nil {
			ylog.Errorf("DecodeKoResp", err.Error())
			return
		}

		if fetchResp.Code == RespCodeSuccess {
			ylog.Infof("ko", fetchResp.KoAddress)
			ylog.Infof("sign", fetchResp.SignAddress)
		} else {
			ylog.Infof("MissedKo", "response code is no success, code %d", fetchResp.Code)
			return
		}

		upKoErr := uploadFileToNginx(ctx, fetchResp.KoAddress, fmt.Sprintf("/agent/component/driver/ko/"+completeName+".ko"))
		if upKoErr != nil {
			ylog.Infof("Upload Ko failed: ", upKoErr.Error())
		}

		upSignErr := uploadFileToNginx(ctx, fetchResp.SignAddress, fmt.Sprintf("/agent/component/driver/ko/"+completeName+".sign"))
		if upSignErr != nil {
			ylog.Infof("Upload Sign failed: ", upSignErr.Error())
		}
		rebootErr := rebootRecentAgent(ctx, req.AgentID)
		if rebootErr != nil {
			ylog.Errorf("RebootAgentForMissedKo", "Failed reboot for Agent "+req.AgentID+" "+rebootErr.Error())
		}
	}()
	return
}
