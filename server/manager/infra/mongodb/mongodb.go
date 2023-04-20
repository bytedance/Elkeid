package mongodb

import (
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

func NewMongoClient(uri string) (*mongo.Client, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var opt options.ClientOptions
	opt.SetMaxPoolSize(10)
	opt.SetMinPoolSize(10)
	//opt.SetConnectTimeout(200 * time.Millisecond)
	//opt.SetReadPreference(readpref.PrimaryPreferred())
	opt.SetReadPreference(readpref.SecondaryPreferred())
	mongoClient, err := mongo.Connect(ctx, options.Client().ApplyURI(uri), &opt)
	if err != nil {
		fmt.Printf("NEW_MONGO_ERROR %s\n", err.Error())
		return nil, err
	}

	err = mongoClient.Ping(ctx, readpref.Primary())
	if err != nil {
		fmt.Printf("NEW_MONGO_ERROR %s\n", err.Error())
		return nil, err
	}

	return mongoClient, nil
}
