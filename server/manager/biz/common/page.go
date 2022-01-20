package common

import (
	"context"
	"math"

	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type PageFunc func(*mongo.Cursor) (interface{}, error)

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

func DBModelPaginate(collection *mongo.Collection, pageOption PageOption, pageFunc PageFunc) (*ModelPage, error) {
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

	defer cursor.Close(context.Background())

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

func DBAggregatePaginate(collection *mongo.Collection, pipe []interface{}, pageOption PageOption, pageFunc PageFunc) (*ModelPage, error) {
	total, err := collection.CountDocuments(context.Background(), pageOption.Filter)
	if err != nil {
		ylog.Errorf("DBAggregatePaginate", err.Error())
		return nil, err
	}

	pipeline := bson.A{
		bson.M{"$match": pageOption.Filter},
		bson.M{"$skip": (pageOption.Page - 1) * pageOption.PageSize},
		bson.M{"$limit": pageOption.PageSize},
	}

	pipeline = append(pipeline, pipe...)

	cursor, err := collection.Aggregate(context.Background(), pipeline)
	if err != nil {
		ylog.Errorf("DBAggregatePaginate", err.Error())
		return nil, err
	}

	defer cursor.Close(context.Background())

	var modelPage ModelPage

	for cursor.Next(context.Background()) {
		item, err := pageFunc(cursor)

		if err != nil {
			ylog.Errorf("DBAggregatePaginate", err.Error())
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
