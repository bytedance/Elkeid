package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"github.com/levigross/grequests"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

var (
	sHelp      bool
	url        string
	ak         string
	sk         string
	operType   string
	resetCount int
)

// -url https://127.0.0.1:9986/conn/stat -ak xxxx -sk xxxxxxxxxxxxx -
func init() {
	flag.BoolVar(&sHelp, "h", false, "help")

	flag.StringVar(&url, "url", "", "url")
	flag.StringVar(&ak, "ak", "", "ak")
	flag.StringVar(&sk, "sk", "", "sk")
	flag.StringVar(&operType, "type", "", "reset/stats")
	flag.IntVar(&resetCount, "count", 0, "")
}

func uSage() {
	_, _ = fmt.Fprintf(os.Stderr, `Usage: httpACTools -url https://1.1.1.1:9986/conn/stat -ak xxx -sk xxxx -type reset -count 10`)
	flag.PrintDefaults()
}

func main() {
	flag.Parse()
	if sHelp {
		uSage()
		return
	}

	switch operType {
	case "reset":
		reset(resetCount)
	case "stats":
	default:
		fmt.Printf("operation type %s is not support(reset/stats)\n", operType)
	}
}

const (
	ConnResetRandom = "random"
)

type ResetRequest struct {
	IDList []string `json:"id_list"`
	Type   string   `json:"type" binding:"required" `
	Count  int      `json:"count"`
}

func reset(count int) {
	body := ResetRequest{
		Type:  ConnResetRandom,
		Count: count,
	}

	option := svrAuthRequestOption()
	option.JSON = body
	option.RequestTimeout = 60 * time.Second
	resp, err := grequests.Post(url, option)
	if err != nil {
		ylog.Errorf("PostTask", "error: %s, %s", err.Error(), url)
		return
	}
	if !resp.Ok {
		ylog.Errorf("PostTask", "response code is %d, %s", resp.StatusCode, url)
		return
	}

	fmt.Println(resp.String())
}

func svrAuthRequestOption() *grequests.RequestOptions {
	option := &grequests.RequestOptions{
		InsecureSkipVerify: true,
		BeforeRequest:      svrBeforeRequestFunc,
	}
	return option
}

func svrBeforeRequestFunc(req *http.Request) error {
	return beforeRequestFuncWithKey(req, ak, sk)
}

func beforeRequestFuncWithKey(req *http.Request, ak, sk string) error {
	var (
		timestamp   = fmt.Sprintf(`%d`, time.Now().Unix())
		err         error
		requestBody []byte
	)

	if req.Body != nil {
		requestBody, err = io.ReadAll(req.Body)
		if err != nil {
			ylog.Errorf("beforeRequestFuncWithKey", "ioutil.ReadAll error %s", err.Error())
			return err
		}
		//Reset after reading
		_ = req.Body.Close()
		req.Body = io.NopCloser(bytes.NewBuffer(requestBody))
	} else {
		requestBody = []byte{}
	}
	sign := generateSign(req.Method, formatURLPath(req.URL.Path), req.URL.RawQuery, ak, timestamp, sk, requestBody)
	req.Header.Add("AccessKey", ak)
	req.Header.Add("Signature", sign)
	req.Header.Add("TimeStamp", timestamp)
	return nil
}

func generateSign(method, url, query, ak, timestamp, sk string, requestBody []byte) string {
	return hmacSha256(fmt.Sprintf(`%s\n%s\n%s\n%s\n%s\n%s`, method, url, query, ak, timestamp, sha256byteArr(requestBody)), sk)
}

func hmacSha256(data string, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

func sha256byteArr(in []byte) string {
	if in == nil || len(in) == 0 {
		return ""
	}
	h := sha256.New()
	h.Write(in)
	return hex.EncodeToString(h.Sum(nil))
}

func formatURLPath(in string) string {
	in = strings.TrimSpace(in)
	if strings.HasSuffix(in, "/") {
		return in[:len(in)-1]
	}
	return in
}
