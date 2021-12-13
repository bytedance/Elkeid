package v6

import (
	"fmt"

	"github.com/bytedance/Elkeid/server/manager/biz/common"
	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/mongo/gridfs"
)

type DownloadReq struct {
	FileName string `form:"file_name" json:"file_name" bson:"file_name" binding:"required"`
}

func Download(ctx *gin.Context) {
	fileName, ok := ctx.Params.Get("FileName")
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
			ctx.AbortWithStatus(404)
		}
	}
}
