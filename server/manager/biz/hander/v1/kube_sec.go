package v1

import (
	"fmt"
	"github.com/bytedance/Elkeid/server/manager/biz/common"
	"github.com/bytedance/Elkeid/server/manager/biz/midware"
	"github.com/bytedance/Elkeid/server/manager/distribute/job"
	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"github.com/gin-gonic/gin"
	"github.com/levigross/grequests"
	"strings"
	"time"
)

const KubeSecTimeOut = 5

func ProxyK8sRequest(c *gin.Context) {
	var r *grequests.Response
	var err error

	option := midware.KsAuthRequestOption()
	option.RequestBody = c.Request.Body
	option.Headers = map[string]string{"Content-Type": "application/json"}
	option.RequestTimeout = KubeSecTimeOut * time.Second
	rawUrl := fmt.Sprintf("https://%s/kubesec/api/v1/%s", infra.K8sSecAddr, strings.TrimPrefix(c.Request.URL.Path, "/api/v1/kubesec/"))

	switch c.Request.Method {
	case job.HttpMethodGet:
		r, err = grequests.Get(rawUrl, option)
	case job.HttpMethodPost:
		r, err = grequests.Post(rawUrl, option)
	default:
		common.CreateResponse(c, common.UnknownErrorCode, fmt.Sprintf("%s not support", c.Request.Method))
		return
	}
	if err != nil {
		common.CreateResponse(c, common.RemoteServerError, err.Error())
		return
	}
	ylog.Debugf("ProxyK8sRequest", "url:%s code:%d response:%s", rawUrl, r.StatusCode, r.String())
	c.Data(r.RawResponse.StatusCode, "application/json", r.Bytes())
}
