package utils

import (
	"regexp"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

func TransBackwardsRegex(s string) primitive.Regex {
	return primitive.Regex{Pattern: "^" + regexp.QuoteMeta(s)}
}
