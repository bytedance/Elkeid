package common

import (
	"archive/zip"
	"context"
	"encoding/csv"
	"io"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/bytedance/Elkeid/server/manager/infra/utils"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/bsontype"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/gridfs"

	"github.com/gin-gonic/gin"
)

type MongoDBDefs []struct {
	Key    string
	Header string
}

type ExportProgress struct {
	ExportTotal int64 `json:"export_total"`
	ExportCount int64 `json:"export_count"`
	//init exporting saving success failed
	Status   string `json:"status"`
	FileName string `json:"file_name"`
}
type ExportHostsResp struct {
	Code int             `json:"code"`
	Msg  string          `json:"msg"`
	Data *ExportProgress `json:"data"`
}

func MarshalBasicBson(d bson.RawValue) (r string) {
	switch d.Type {
	case bsontype.String:
		r, _ = d.StringValueOK()
	case bsontype.Double:
		if v, ok := d.DoubleOK(); ok {
			r = strconv.FormatFloat(v, 'f', -1, 64)
		}
	case bsontype.Int32:
		if v, ok := d.Int32OK(); ok {
			r = strconv.FormatInt(int64(v), 10)
		}
	case bsontype.Int64:
		if v, ok := d.Int64OK(); ok {
			r = strconv.FormatInt(v, 10)
		}
	case bsontype.ObjectID:
		if v, ok := d.ObjectIDOK(); ok {
			r = v.Hex()
		}
	}
	return
}
func ExportFromMongoDB(c *gin.Context, collection *mongo.Collection, filter interface{}, defs MongoDBDefs, filename string) {
	var err error
	mu := sync.Mutex{}
	filename = filename + "-" + strconv.FormatInt(time.Now().UnixNano(), 10) + "-" + utils.GenerateRandomString(8) + ".zip"
	resp := ExportHostsResp{
		Data: &ExportProgress{
			Status:   "init",
			FileName: filename,
		},
	}
	ticker := time.NewTicker(time.Second)
	done := make(chan error)
	go func() {
		defer ticker.Stop()
		defer close(done)
		resp.Data.ExportTotal, err = collection.CountDocuments(context.Background(), filter)
		if err != nil {
			ylog.Errorf("export", err.Error())
			done <- err
			return
		}
		cursor, err := collection.Find(context.Background(), filter)
		if err != nil {
			ylog.Errorf("export", err.Error())
			done <- err
			return
		}
		bucket, err := gridfs.NewBucket(infra.MongoClient.Database(infra.MongoDatabase))
		if err != nil {
			ylog.Errorf("export", err.Error())
			done <- err
			return
		}
		stream, err := bucket.OpenUploadStream(filename)
		if err != nil {
			ylog.Errorf("export", err.Error())
			done <- err
			return
		}
		ziper := zip.NewWriter(stream)
		file, err := ziper.Create(path.Base(filename)[:len(filename)-3] + "csv")
		if err != nil {
			ylog.Errorf("export", err.Error())
			done <- err
			return
		}
		_, _ = file.Write([]byte{0xEF, 0xBB, 0xBF})
		csver := csv.NewWriter(file)
		var headers []string
		for _, def := range defs {
			headers = append(headers, def.Header)
		}
		err = csver.Write(headers)
		if err != nil {
			ylog.Errorf("export", err.Error())
			done <- err
			return
		}
		mu.Lock()
		resp.Data.Status = "exporting"
		resp.Data.FileName = filename
		mu.Unlock()
		for cursor.Next(context.Background()) {
			var record []string
			for _, def := range defs {
				d := cursor.Current.Lookup(strings.Split(def.Key, ".")...)
				if a, ok := d.ArrayOK(); ok {
					r := ""
					if av, err := a.Values(); err == nil {
						for _, v := range av {
							if r != "" {
								r = r + "," + MarshalBasicBson(v)
							} else {
								r = MarshalBasicBson(v)
							}
						}
					}
					record = append(record, r)
				} else {
					record = append(record, MarshalBasicBson(d))
				}
			}
			err = csver.Write(record)
			if err != nil {
				ylog.Errorf("export", err.Error())
				done <- err
				return
			}
			mu.Lock()
			resp.Data.ExportCount++
			mu.Unlock()
		}
		mu.Lock()
		resp.Data.Status = "saving"
		mu.Unlock()
		csver.Flush()
		err = ziper.Close()
		if err != nil {
			ylog.Errorf("export", err.Error())
			done <- err
			return
		}
		err = stream.Close()
		if err != nil {
			ylog.Errorf("export", err.Error())
			done <- err
			return
		}
	}()
	c.Stream(func(w io.Writer) bool {
		select {
		case <-ticker.C:
			mu.Lock()
			defer mu.Unlock()
			resp.Code = SuccessCode
			resp.Msg = "success"
			c.SSEvent("progress", resp)
			return true
		case err, ok := <-done:
			mu.Lock()
			defer mu.Unlock()
			if ok {
				resp.Code = UnknownErrorCode
				resp.Msg = "export failed, " + err.Error()
				resp.Data.Status = "failed"
			} else {
				resp.Code = SuccessCode
				resp.Msg = "success"
				resp.Data.Status = "success"
				resp.Data.ExportCount = resp.Data.ExportTotal
			}
			c.SSEvent("progress", resp)
			return false
		}
	})
}

func ExportFromList(c *gin.Context, exportList [][]string, defs MongoDBDefs, filename string) {
	mu := sync.Mutex{}
	filename = filename + "-" + strconv.FormatInt(time.Now().UnixNano(), 10) + "-" + utils.GenerateRandomString(8) + ".zip"
	resp := ExportHostsResp{
		Data: &ExportProgress{
			Status:   "init",
			FileName: filename,
		},
	}
	ticker := time.NewTicker(time.Second)
	done := make(chan error)
	go func() {
		defer ticker.Stop()
		defer close(done)
		resp.Data.ExportTotal = int64(len(exportList))

		bucket, err := gridfs.NewBucket(infra.MongoClient.Database(infra.MongoDatabase))
		if err != nil {
			ylog.Errorf("export", err.Error())
			done <- err
			return
		}
		stream, err := bucket.OpenUploadStream(filename)
		if err != nil {
			ylog.Errorf("export", err.Error())
			done <- err
			return
		}
		ziper := zip.NewWriter(stream)
		file, err := ziper.Create(path.Base(filename)[:len(filename)-3] + "csv")
		if err != nil {
			ylog.Errorf("export", err.Error())
			done <- err
			return
		}
		_, _ = file.Write([]byte{0xEF, 0xBB, 0xBF})
		csver := csv.NewWriter(file)
		var headers []string
		for _, def := range defs {
			headers = append(headers, def.Header)
		}
		err = csver.Write(headers)
		if err != nil {
			ylog.Errorf("export", err.Error())
			done <- err
			return
		}
		mu.Lock()
		resp.Data.Status = "exporting"
		resp.Data.FileName = filename
		mu.Unlock()
		for _, record := range exportList {
			err = csver.Write(record)
			if err != nil {
				ylog.Errorf("export", err.Error())
				done <- err
				return
			}
			mu.Lock()
			resp.Data.ExportCount++
			mu.Unlock()
		}
		mu.Lock()
		resp.Data.Status = "saving"
		mu.Unlock()
		csver.Flush()
		err = ziper.Close()
		if err != nil {
			ylog.Errorf("export", err.Error())
			done <- err
			return
		}
		err = stream.Close()
		if err != nil {
			ylog.Errorf("export", err.Error())
			done <- err
			return
		}
	}()
	c.Stream(func(w io.Writer) bool {
		select {
		case <-ticker.C:
			mu.Lock()
			defer mu.Unlock()
			resp.Code = SuccessCode
			resp.Msg = "success"
			c.SSEvent("progress", resp)
			return true
		case err, ok := <-done:
			mu.Lock()
			defer mu.Unlock()
			if ok {
				resp.Code = UnknownErrorCode
				resp.Msg = "export failed, " + err.Error()
				resp.Data.Status = "failed"
			} else {
				resp.Code = SuccessCode
				resp.Msg = "success"
				resp.Data.Status = "success"
				resp.Data.ExportCount = resp.Data.ExportTotal
			}
			c.SSEvent("progress", resp)
			return false
		}
	})
}
