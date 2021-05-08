package midware

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/bytedance/Elkeid/server/service_discovery/common"
	"github.com/gin-gonic/gin"
	"github.com/levigross/grequests"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"
)

var (
	AK string
	SK string
)

func init() {
	for k, v := range common.AuthKeys {
		AK = k
		SK = v
		break
	}
}

func getSecKec(ak string) string {
	sk, ok := common.AuthKeys[ak]
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
	//fmt.Println("hmacSha256", data, secret)
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

func beforeRequestFunc(req *http.Request) error {
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
		req.Body.Close()
		req.Body = ioutil.NopCloser(bytes.NewBuffer(requestBody))
	} else {
		requestBody = []byte{}
	}
	sign := generateSign(req.Method, formatURLPath(req.URL.Path), req.URL.RawQuery, AK, timestamp, SK, requestBody)
	req.Header.Add("AccessKey", AK)
	req.Header.Add("Signature", sign)
	req.Header.Add("TimeStamp", timestamp)
	return nil
}

func formatURLPath(in string) string {
	in = strings.TrimSpace(in)
	if strings.HasSuffix(in, "/") {
		return in[:len(in)-1]
	}
	return in
}

func AuthRequestOption() *grequests.RequestOptions {
	option := &grequests.RequestOptions{
		InsecureSkipVerify: true,
		BeforeRequest:      beforeRequestFunc,
	}
	return option
}

func AKSKAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		var (
			ak, sk, sign, timeStamp, serverSign string
			iTime, timeDiff                     int64
			err                                 error
			requestBody                         []byte
		)

		ak = strings.ToLower(c.Request.Header.Get("AccessKey"))
		sign = c.Request.Header.Get("Signature")
		timeStamp = c.Request.Header.Get("TimeStamp")
		if ak == "" || sign == "" || timeStamp == "" {
			abort(c, "header missed: AccessKey|Signature|TimeStamp")
			return
		}

		//check_time
		iTime, err = strconv.ParseInt(timeStamp, 10, 64)
		if err != nil {
			abort(c, fmt.Sprintf(`TimeStamp Error %s`, err.Error()))
			return
		}
		timeDiff = time.Now().Unix() - iTime
		if timeDiff >= 60 || timeDiff <= -60 {
			abort(c, "TimeStamp Error")
			return
		}

		//check_sign
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
			abort(c, "Signature Error")
			return
		}
		c.Next()
		return
	}
}

func abort(c *gin.Context, reason string) {
	c.Abort()
	c.JSON(http.StatusForbidden, gin.H{"code": -1, "msg": "auth failed", "data": reason})
	return
}
