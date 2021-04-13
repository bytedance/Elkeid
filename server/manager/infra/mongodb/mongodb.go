package mongodb

import (
	"context"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
	"time"
)

func NewMongoClient(uri string) (*mongo.Client, error) {
	ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)

	var opt options.ClientOptions
	opt.SetMaxPoolSize(10)
	opt.SetMinPoolSize(10)
	opt.SetReadPreference(readpref.SecondaryPreferred())

	mongoClient, err := mongo.Connect(ctx, options.Client().ApplyURI(uri), &opt)
	if err != nil {
		return nil, err
	}

	err = mongoClient.Ping(ctx, readpref.Primary())
	if err != nil {
		return nil, err
	}

	return mongoClient, nil
}
