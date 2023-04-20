package v6

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/x/bsonx"

	"github.com/bytedance/Elkeid/server/manager/biz/common"
	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/mongo/gridfs"
)

type DownloadReq struct {
	FileName string `form:"file_name" json:"file_name" bson:"file_name" binding:"required"`
}

func Download(ctx *gin.Context) {
	var fileName string
	var ok bool
	fileName = ctx.GetString("FileName")
	if fileName == "" {
		fileName, ok = ctx.Params.Get("FileName")
	} else {
		ok = true
	}
	if !ok {
		ctx.AbortWithStatus(400)
	} else {
		bucket, err := gridfs.NewBucket(infra.MongoClient.Database(infra.MongoDatabase))
		if err != nil {
			common.CreateResponse(ctx, common.DBOperateErrorCode, err.Error())
			return
		}
		ctx.Writer.Header().Set("Content-type", "application/octet-stream")
		ctx.Writer.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%v\"", fileName))
		_, err = bucket.DownloadToStreamByName(fileName, ctx.Writer)
		if err != nil {
			ylog.Errorf("bucket.DownloadToStreamByName error", "file %s error %s", fileName, err.Error())
			ctx.AbortWithStatus(404)
		}
	}
}

type UploadRuleInfo struct {
	UploadName  string
	Md5         string
	UploadAt    int64
	StorageName string
}

const (
	uploadDir = "./upload"
)

func Upload(c *gin.Context) {
	//获取哈希，校验是否上传成功
	fHash := c.PostForm("hash")
	if fHash == "" {
		common.CreateResponse(c, common.ParamInvalidErrorCode, "no file hash")
		return
	}
	ylog.Infof("Upload", "upload hash: %s", fHash)

	//查询是否上传过，去重
	infoCollection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.FileInfoCollection)
	uploadInfo := UploadRuleInfo{}
	filter := bson.D{{Key: "md5", Value: fHash}}
	err := infoCollection.FindOne(c, filter).Decode(&uploadInfo)
	if err == nil {
		ylog.Infof("UPLOAD", "mongo find one error: %v", err)
		common.CreateResponse(c, common.SuccessCode, uploadInfo.StorageName)
		return
	}

	//生成上传时间
	uploadAt := time.Now().UnixNano() / (1000 * 1000 * 1000)
	//接受上传文件
	uploadFile, fHandler, err := c.Request.FormFile("file")
	if err != nil {
		common.CreateResponse(c, common.UnknownErrorCode, err.Error())
		return
	}
	//记得关闭文件
	defer func() {
		_ = uploadFile.Close()
	}()

	//校验md5
	md5Handler := md5.New()
	if _, err := io.Copy(md5Handler, uploadFile); err != nil {
		common.CreateResponse(c, common.UnknownErrorCode, fmt.Sprintf("md5 check error: %v", err))
		return
	}
	md5Hex := hex.EncodeToString(md5Handler.Sum(nil))
	if md5Hex != fHash {
		common.CreateResponse(c, common.UnknownErrorCode, "md5 check failed")
		return
	}
	//保存文件

	_ = os.Mkdir(uploadDir, os.ModePerm)
	storageName := fmt.Sprintf("upload-%d-%s.zip", uploadAt, fHash)
	dstPath := fmt.Sprintf("%s/%s", uploadDir, storageName)
	if err := c.SaveUploadedFile(fHandler, dstPath); err != nil {
		common.CreateResponse(c, common.UnknownErrorCode, fmt.Sprintf("save file error: %v", err))
		return
	}

	//文件以二进制方式存入DB
	if err := GridFSUpload(dstPath, storageName); err != nil {
		common.CreateResponse(c, common.UnknownErrorCode, fmt.Sprintf("pload file to db error:  %v", err))
		return
	}

	//上传信息存入DB
	uploadInfo = UploadRuleInfo{StorageName: storageName, UploadAt: uploadAt, Md5: fHash, UploadName: fHandler.Filename}
	if _, err := infoCollection.InsertOne(c, uploadInfo); err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, fmt.Sprintf("save upload info to db error: %v", err))
		return
	}
	common.CreateResponse(c, common.SuccessCode, storageName)
}

func GridFSUpload(filePath string, fileName string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}
	bucket, err := gridfs.NewBucket(infra.MongoClient.Database(infra.MongoDatabase))
	if err != nil {
		return err
	}
	opts := options.GridFSUpload()
	opts.SetMetadata(bsonx.Doc{{Key: "context-type", Value: bsonx.String("binary")}})
	uStream, err := bucket.OpenUploadStream(fileName, opts)
	if err != nil {
		return err
	}
	defer func() {
		_ = uStream.Close()
	}()

	fSize, err := uStream.Write(data)
	if err != nil {
		return err
	}
	ylog.Infof("GridFS_UPLOAD", "write file to db success. file size: %d", fSize)
	return nil
}
