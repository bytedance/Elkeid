package midware

import (
	"context"
	"crypto/sha1"
	"errors"
	"fmt"
	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"github.com/bytedance/Elkeid/server/manager/internal/login"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"github.com/rs/xid"
	"io"
	"net/http"
	"strings"
	"time"
)

var whiteUrlList = []string{
	"/api/v6/investigate/file/DownloadFileByToken",
	"/api/v1/agent/heartbeat/join",
	"/api/v1/agent/heartbeat/evict",
	"/api/v1/user/login",
	"/api/v1/user/sso_url",
	"/api/v1/user/sso_logout",
	"/api/v1/user/sso_token",
	"/api/v1/agent/updateSubTask",
	"/api/v1/agent/subTask/update",
	"/api/v6/shared/Upload",
	"/api/v1/agent/queryInfo",
	"/api/v6/kube/inner/cluster/list",
	"/api/v6/component/GetComponentInstances",
	"/api/v6/user/getCaptcha",
	"/api/v6/systemRouter/InsertAlert"}

type AuthClaims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

const (
	JWTExpireMinute = 720
)

var APITokenSecret = []byte(infra.Secret)

func CreateToken(payload jwt.Claims, secret []byte) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, payload)

	tokenString, err := token.SignedString(secret)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func VerifyToken(tokenString string, secret []byte) (*jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("parser failed")
		}

		return secret, nil
	})

	if err != nil {
		ylog.Errorf("VerifyToken", err.Error())
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return &claims, nil
	}
	return nil, errors.New("verify token failed")
}

func checkPassword(password, salt, hash string) bool {
	t := sha1.New()
	_, err := io.WriteString(t, password+salt)
	if err != nil {
		return false
	}
	if fmt.Sprintf("%x", t.Sum(nil)) == hash {
		return true
	}
	return false
}

func GenPassword(password, salt string) string {
	t := sha1.New()
	_, err := io.WriteString(t, password+salt)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%x", t.Sum(nil))
}

func CheckUser(username, password string) (*login.User, error) {
	u := login.GetUser(username)
	if u == nil {
		return nil, errors.New("user not found")
	}

	if !checkPassword(password, u.Salt, u.Password) {
		return u, errors.New("verify password failed")
	}
	return u, nil
}

func GeneralJwtToken(userName string) (string, error) {
	return CreateToken(AuthClaims{
		Username: userName,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(JWTExpireMinute * time.Minute).Unix(),
		},
	}, APITokenSecret)
}

func GeneralSession() string {
	return fmt.Sprintf("seesion-%s-%s", xid.New(), xid.New())
}

func TokenAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !infra.ApiAuth {
			c.Next()
			return
		}

		//whitelist
		if strings.HasPrefix(c.Request.URL.Path, "/api/v1/agent/getConfig/") {
			c.Next()
			return
		}

		//url_whitelist
		if infra.Contains(whiteUrlList, c.Request.URL.Path) {
			c.Next()
			return
		}

		token := c.GetHeader("token")
		if token == "" {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		var userName string
		if strings.HasPrefix(token, "seesion-") {
			userName = infra.Grds.Get(context.Background(), token).Val()
			if userName == "" {
				c.AbortWithStatus(http.StatusUnauthorized)
				return
			}

			err := infra.Grds.Expire(context.Background(), token, time.Duration(login.GetLoginSessionTimeoutMinute())*time.Minute).Err()
			if err != nil {
				ylog.Errorf("TokenAuth", "Expire error %s", err.Error())
			}
		} else {
			//jwt
			payload, err := VerifyToken(token, APITokenSecret)
			if err != nil {
				ylog.Errorf("AuthRequired", err.Error())
				c.AbortWithStatus(http.StatusUnauthorized)
				return
			}

			if payload == nil {
				c.AbortWithStatus(http.StatusUnauthorized)
				return
			}

			currentUser, ok := (*payload)["username"]
			if currentUser == "" || !ok {
				c.AbortWithStatus(http.StatusUnauthorized)
				return
			}
			userName = currentUser.(string)
		}

		c.Header("user", userName)
		c.Set("user", userName)
		c.Next()
		return
	}
}
