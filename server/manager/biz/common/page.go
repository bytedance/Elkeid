package common

import (
	"context"
	"io"
	"math"
	"time"

	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const (
	MongoTimeout    = 30 * time.Second
	DefaultPage     = 1
	DefaultPageSize = 100
)

type PageRequest struct {
	Page       int64  `form:"page,default=1" binding:"required,numeric,min=1"`
	PageSize   int64  `form:"page_size,default=100" binding:"required,numeric,min=1,max=5000"`
	OrderKey   string `form:"order_key"`
	OrderValue int    `form:"order_value"`
}

type PageOption struct {
	Page     int64
	PageSize int64
	Filter   interface{}
	Sorter   interface{}
}

// PageSearch 查询定义
type PageSearch struct {
	Page     int64
	PageSize int64
	Filter   interface{}
	Sorter   interface{}
}

// PageResponse 返回定义
type PageResponse struct {
	Total    int64 `json:"total" bson:"total"`
	Page     int64 `json:"page"`
	PageSize int64 `json:"page_size"`
}

type PageFuncForModal func(*mongo.Cursor) (interface{}, error)

type PageFunc func(*mongo.Cursor) error // 处理monogo迭代返回结果

type ModelPage struct {
	Total    int64         `json:"total"`
	Count    int64         `json:"count"`
	Pages    int64         `json:"pages"`
	Page     int64         `json:"page"`
	PageSize int64         `json:"page_size"`
	HasPrev  bool          `json:"has_prev"`
	HasNext  bool          `json:"has_next"`
	Items    []interface{} `json:"items"`
}

//  -------------------------------mongo高级查询-------------------------------  //

type MongoInside struct {
	Inside interface{} `bson:"$in"` // 传入数组类型
}
type MongoNinside struct {
	Value interface{} `bson:"$nin"` // 传入数组类型
}
type MongoRegex struct {
	Regex string `bson:"$regex"`
}
type MongoNe struct {
	Value interface{} `bson:"$ne"`
}
type MongoGte struct {
	Value interface{} `bson:"$gte"` // 传入数组类型
}
type MongoLte struct {
	Value interface{} `bson:"$lte"`
}
type MongoElem struct {
	Value interface{} `bson:"$elemMatch"` // 传入数组类型
}
type MongoExists struct {
	Value interface{} `bson:"$exists"` // 传入数组类型
}

func DBModelPaginate(collection *mongo.Collection, pageOption PageOption, pageFunc PageFuncForModal) (*ModelPage, error) {
	total, err := collection.CountDocuments(context.Background(), pageOption.Filter)
	if err != nil {
		ylog.Errorf("DBModelPaginate", err.Error())
		return nil, err
	}

	findOption := options.Find()
	if pageOption.Sorter != nil {
		findOption.SetSort(pageOption.Sorter)
	}
	findOption.SetSkip((pageOption.Page - 1) * pageOption.PageSize)
	findOption.SetLimit(pageOption.PageSize)

	cursor, err := collection.Find(context.Background(), pageOption.Filter, findOption)
	if err != nil {
		ylog.Errorf("DBModelPaginate", err.Error())
		return nil, err
	}

	defer func() {
		_ = cursor.Close(context.Background())
	}()

	var modelPage ModelPage

	for cursor.Next(context.Background()) {
		item, err := pageFunc(cursor)

		if err != nil {
			ylog.Errorf("DBModelPaginate", err.Error())
			continue
		}

		modelPage.Count++
		modelPage.Items = append(modelPage.Items, item)
	}

	modelPage.Total = total
	modelPage.Page = pageOption.Page
	modelPage.Pages = int64(math.Ceil(float64(total) / float64(pageOption.PageSize)))
	modelPage.PageSize = pageOption.PageSize
	modelPage.HasPrev = modelPage.Page > 1
	modelPage.HasNext = modelPage.Page < modelPage.Pages

	return &modelPage, nil
}

// DBSearchPaginate 分页查询
func DBSearchPaginate(collection *mongo.Collection, pageOption PageSearch, pageFunc PageFunc, opts ...*options.FindOptions) (*PageResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), MongoTimeout)
	defer cancel()

	// 获取总数
	var total int64
	var err error
	if m, ok := pageOption.Filter.(bson.M); ok && len(m) == 0 {
		total, err = collection.EstimatedDocumentCount(ctx)
	}
	if err != nil {
		ylog.Errorf("DBSearchPaginate", err.Error())
		return nil, err
	}
	if total < 1000000 {
		total, err = collection.CountDocuments(ctx, pageOption.Filter)
	}
	if err != nil {
		ylog.Errorf("DBSearchPaginate", err.Error())
		return nil, err
	}
	var findOption *options.FindOptions
	if len(opts) != 0 {
		findOption = opts[0]
	} else {
		findOption = options.Find()
	}
	// 配置分页
	if pageOption.Sorter != nil {
		findOption.SetSort(pageOption.Sorter)
	}
	findOption.SetSkip((pageOption.Page - 1) * pageOption.PageSize)
	findOption.SetLimit(pageOption.PageSize)

	// 查询
	cursor, err := collection.Find(ctx, pageOption.Filter, findOption)
	if err != nil {
		ylog.Errorf("DBSearchPaginate", err.Error())
		return nil, err
	}
	defer func(cursor *mongo.Cursor, ctx context.Context) {
		err := cursor.Close(ctx)
		if err != nil {
			ylog.Errorf("DBSearchPaginate", err.Error())
		}
	}(cursor, ctx)

	// 迭代返回数据
	for cursor.Next(ctx) {
		err := pageFunc(cursor)

		if err != nil {
			ylog.Errorf("DBSearchPaginate", err.Error())
			return nil, err
		}

	}
	// 拼装返回页面数据
	var pageResponse PageResponse
	pageResponse.Total = total
	pageResponse.Page = pageOption.Page
	pageResponse.PageSize = pageOption.PageSize
	return &pageResponse, nil
}

func DBAggregatePaginate(collection *mongo.Collection, pipe []interface{}, pageOption PageSearch, pageFunc PageFunc) (*PageResponse, error) {
	pipeline := append(pipe, bson.M{
		"$count": "total",
	})
	cursor, err := collection.Aggregate(context.Background(), pipeline)
	if err != nil {
		ylog.Errorf("DBAggregatePaginate", err.Error())
		return nil, err
	}

	pageResponse := PageResponse{
		Page:     pageOption.Page,
		PageSize: pageOption.PageSize,
	}
	cursor.Next(context.Background())
	err = cursor.Decode(&pageResponse)
	if err != nil {
		if err == io.EOF {
			return &pageResponse, nil
		}
		ylog.Errorf("DBAggregatePaginate", err.Error())
		return nil, err
	}

	// 判断排序
	if pageOption.Sorter != nil {
		pipe = append(pipe, bson.M{"$sort": pageOption.Sorter})
	}

	_ = cursor.Close(context.Background())
	pagePipeline := append(pipe, bson.M{"$skip": (pageOption.Page - 1) * pageOption.PageSize}, bson.M{"$limit": pageOption.PageSize})
	cursor, err = collection.Aggregate(context.Background(), pagePipeline)
	if err != nil {
		ylog.Errorf("DBAggregatePaginate", err.Error())
		return nil, err
	}
	defer func() {
		_ = cursor.Close(context.Background())
	}()
	for cursor.Next(context.Background()) {
		err := pageFunc(cursor)
		if err != nil {
			ylog.Errorf("DBAggregatePaginate", err.Error())
			return nil, err
		}
	}
	return &pageResponse, nil
}
