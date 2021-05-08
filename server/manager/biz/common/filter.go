package common

import (
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"time"
)

type FilterRule struct {
	Operator string      `json:"operator" binding:"required,oneof=$eq $gt $gte $in $lt $lte $ne $nin $regex $time"`
	Value    interface{} `json:"value" binding:"required"`
}

type FilterContent struct {
	Key       string       `json:"key" binding:"required"`
	Rules     []FilterRule `json:"rules" binding:"required,dive"`
	Condition string       `json:"condition" binding:"required,oneof=$and $or $nor"`
}

type FilterQuery struct {
	Filter    []FilterContent `json:"filter" binding:"dive"`
	Condition string          `json:"condition" binding:"oneof=$and $or $nor"`
}

func (f *FilterQuery) Transform() bson.M {
	var filterStatement bson.A

	for _, filter := range f.Filter {
		if len(filter.Rules) == 0 {
			continue
		}

		var part bson.A

		for _, rule := range filter.Rules {
			value := rule.Value

			// regex
			if rule.Operator == "$regex" {
				value = primitive.Regex{Pattern: rule.Value.(string), Options: ""}
			}

			// time
			if rule.Operator == "$time" {
				timeFilter := value.(map[string]interface{})

				start, ok := timeFilter["start"]
				if !ok {
					start = "1970-01-01 00:00"
				}

				end, ok := timeFilter["end"]
				if !ok {
					end = "9999-01-01 00:00"
				}

				startTime, _ := time.ParseInLocation("2006-01-02 15:04", start.(string), time.Local)
				endTime, _ := time.ParseInLocation("2006-01-02 15:04", end.(string), time.Local)

				part = append(
					part,
					bson.M{
						filter.Key: bson.M{
							"$gte": startTime.Unix(),
							"$lte": endTime.Unix(),
						},
					},
				)

				continue
			}

			part = append(
				part,
				bson.M{
					filter.Key: bson.M{
						rule.Operator: value,
					},
				},
			)
		}

		filterStatement = append(
			filterStatement,
			bson.M{
				filter.Condition: part,
			})
	}

	if len(filterStatement) == 0 {
		return bson.M{}
	}

	return bson.M{f.Condition: filterStatement}
}

func BindFilterQuery(c *gin.Context) (*FilterQuery, error) {
	filterQuery := FilterQuery{
		Condition: "$and",
	}

	err := c.BindJSON(&filterQuery)
	if err != nil {
		return nil, err
	}

	return &filterQuery, nil
}
