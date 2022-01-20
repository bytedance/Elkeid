package v6

import (
	"context"
	"io"
	"time"

	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// mongo查询相关接口
//  -------------------------------宏定义-------------------------------  //
const (
	MongoTimeout    = 30 * time.Second
	DefaultPage     = 1
	DefaultPageSize = 100
)

//  -------------------------------分页相关定义-------------------------------  //

// PageRequest 请求定义
type PageRequest struct {
	Page       int64  `form:"page,default=1" binding:"required,numeric,min=1"`
	PageSize   int64  `form:"page_size,default=100" binding:"required,numeric,min=1,max=999"`
	OrderKey   string `form:"order_key"`
	OrderValue int    `form:"order_value"`
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

type PageFunc func(*mongo.Cursor) error // 处理monogo迭代返回结果

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

type MongoElem struct {
	Value interface{} `bson:"$elemMatch"` // 传入数组类型
}

// DBSearchPaginate 分页查询
func DBSearchPaginate(collection *mongo.Collection, pageOption PageSearch, pageFunc PageFunc) (*PageResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), MongoTimeout)
	defer cancel()

	// 获取总数
	total, err := collection.CountDocuments(ctx, pageOption.Filter)
	if err != nil {
		ylog.Errorf("DBSearchPaginate", err.Error())
		return nil, err
	}

	// 配置分页
	findOption := options.Find()
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
	cursor.Close(context.Background())
	pagePipeline := append(pipe, bson.M{"$skip": (pageOption.Page - 1) * pageOption.PageSize}, bson.M{"$limit": pageOption.PageSize})
	cursor, err = collection.Aggregate(context.Background(), pagePipeline)
	if err != nil {
		ylog.Errorf("DBAggregatePaginate", err.Error())
		return nil, err
	}
	defer cursor.Close(context.Background())
	for cursor.Next(context.Background()) {
		err := pageFunc(cursor)
		if err != nil {
			ylog.Errorf("DBAggregatePaginate", err.Error())
			return nil, err
		}
	}
	return &pageResponse, nil
}
