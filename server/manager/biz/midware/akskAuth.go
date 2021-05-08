package midware

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/bytedance/Elkeid/server/manager/biz/common"
	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/gin-gonic/gin"
	"github.com/levigross/grequests"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func getSecKec(ak string) string {
	sk, ok := infra.InnerAuth[ak]
	if !ok {
		return ""
	}
	return sk
}

func sha256byteArr(in []byte) string {
	if in == nil || len(in) == 0 {
		return ""
	}
	h := sha256.New()
	h.Write(in)
	return hex.EncodeToString(h.Sum(nil))
}

func generateSign(method, url, query, ak, timestamp, sk string, requestBody []byte) string {
	return hmacSha256(fmt.Sprintf(`%s\n%s\n%s\n%s\n%s\n%s`, method, url, query, ak, timestamp, sha256byteArr(requestBody)), sk)
}

func hmacSha256(data string, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

func formatURLPath(in string) string {
	in = strings.TrimSpace(in)
	if strings.HasSuffix(in, "/") {
		return in[:len(in)-1]
	}
	return in
}

func AKSKAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		var (
			ak, sk, sign, timeStamp, serverSign string
			iTime, timeDiff                     int64
			err                                 error
			requestBody                         []byte
		)

		ak = c.Request.Header.Get("AccessKey")
		sign = c.Request.Header.Get("Signature")
		timeStamp = c.Request.Header.Get("TimeStamp")
		if ak == "" || sign == "" || timeStamp == "" {
			abort(c, "header missed: AccessKey|Signature|TimeStamp")
			return
		}

		//check time
		iTime, err = strconv.ParseInt(timeStamp, 10, 64)
		if err != nil {
			abort(c, fmt.Sprintf(`TimeStamp Error %s`, err.Error()))
			return
		}
		timeDiff = time.Now().Unix() - iTime
		if timeDiff >= 60 || timeDiff <= -60 {
			abort(c, "timestamp error")
			return
		}

		//check signature
		sk = getSecKec(ak)
		if sk == "" {
			abort(c, "User not exist")
			return
		}
		requestBody, err = ioutil.ReadAll(c.Request.Body)
		if err != nil {
			abort(c, err.Error())
			return
		}
		c.Request.Body.Close()
		c.Request.Body = ioutil.NopCloser(bytes.NewBuffer(requestBody))

		serverSign = generateSign(c.Request.Method, formatURLPath(c.Request.URL.Path), c.Request.URL.RawQuery, ak, timeStamp, sk, requestBody)
		if serverSign != sign {
			abort(c, "signature error")
			return
		}
		c.Next()
		return
	}
}

func abort(c *gin.Context, reason string) {
	c.Abort()
	common.CreateResponse(c, common.AuthFailedErrorCode, reason)
	return
}

func beforeRequestFuncWithKey(req *http.Request, ak, sk string) error {
	var (
		timestamp   = fmt.Sprintf(`%d`, time.Now().Unix())
		err         error
		requestBody []byte
	)

	if req.Body != nil {
		requestBody, err = ioutil.ReadAll(req.Body)
		if err != nil {
			return err
		}
		//Reset after reading
		req.Body.Close()
		req.Body = ioutil.NopCloser(bytes.NewBuffer(requestBody))
	} else {
		requestBody = []byte{}
	}
	sign := generateSign(req.Method, formatURLPath(req.URL.Path), req.URL.RawQuery, ak, timestamp, sk, requestBody)
	req.Header.Add("AccessKey", ak)
	req.Header.Add("Signature", sign)
	req.Header.Add("TimeStamp", timestamp)
	return nil
}

func innerBeforeRequestFunc(req *http.Request) error {
	for k, v := range infra.InnerAuth {
		beforeRequestFuncWithKey(req, k, v)
		return nil
	}
	return nil
}

func sdBeforeRequestFunc(req *http.Request) error {
	beforeRequestFuncWithKey(req, infra.SdAK, infra.SdSK)
	return nil
}

func svrBeforeRequestFunc(req *http.Request) error {
	beforeRequestFuncWithKey(req, infra.SvrAK, infra.SvrSK)
	return nil
}

func SvrAuthRequestOption() *grequests.RequestOptions {
	option := &grequests.RequestOptions{
		InsecureSkipVerify: true,
		BeforeRequest:      svrBeforeRequestFunc,
	}
	return option
}

func SdAuthRequestOption() *grequests.RequestOptions {
	option := &grequests.RequestOptions{
		InsecureSkipVerify: true,
		BeforeRequest:      sdBeforeRequestFunc,
	}
	return option
}

func InnerAuthRequestOption() *grequests.RequestOptions {
	option := &grequests.RequestOptions{
		InsecureSkipVerify: true,
		BeforeRequest:      innerBeforeRequestFunc,
	}
	return option
}
