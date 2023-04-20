package common

import (
	"context"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func CountTop(ctx context.Context, collection *mongo.Collection, key string, top int) (ret []struct {
	Name  string `bson:"name" json:"name"`
	Value int    `bson:"value" json:"value"`
},
	err error) {
	var c *mongo.Cursor
	opts := &options.AggregateOptions{}
	opts.SetAllowDiskUse(true)
	c, err = collection.Aggregate(ctx, bson.A{
		bson.M{
			"$project": bson.M{
				key: 1,
			}},
		bson.M{
			"$sort": bson.M{
				key: 1,
			}},
		bson.M{
			"$group": bson.M{
				"_id": "$" + key,
				"value": bson.M{
					"$sum": 1,
				},
			}},
		bson.M{
			"$sort": bson.M{
				"value": -1,
			}},
		bson.M{
			"$limit": top,
		},
		bson.M{"$project": bson.M{
			"name":  "$_id",
			"value": 1,
		}},
	}, opts,
	)
	if err != nil {
		return
	}
	err = c.All(ctx, &ret)
	return
}
