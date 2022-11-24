package main

import (
	"context"
	"crypto/sha1"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/spf13/viper"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
	"io"
	"math/rand"
	"os"
	"time"
)

type IndexItem struct {
	Keys   map[string]interface{} `json:"keys"`
	Unique bool                   `json:"unique"`
}

type IndexCollection struct {
	CollectionName string      `json:"collection"`
	Index          []IndexItem `json:"index"`
}

type User struct {
	Username string `json:"username" bson:"username"`
	Password string `json:"password" bson:"password"`
	Salt     string `json:"salt" bson:"salt"`
	Level    int    `json:"level" bson:"level"` //权限等级 0--》admin；1--》普通用户
}

var (
	UserCollection = "user"

	help      bool
	opType    string
	confPath  string
	userName  string
	Password  string
	IndexFile string
)

func init() {
	flag.BoolVar(&help, "h", false, "help")

	flag.StringVar(&confPath, "c", "./conf/svr.yml", "config file path")
	flag.StringVar(&opType, "t", "", "operation type: addUser/addIndex")
	flag.StringVar(&userName, "u", "", "username")
	flag.StringVar(&Password, "p", "", "password")
	flag.StringVar(&IndexFile, "f", "", "index json path")
}

func usage() {
	_, _ = fmt.Fprintf(os.Stderr, `Usage: init -c confPath -t operationType -u username -p password -f index.json`)
	flag.PrintDefaults()
}

func main() {
	flag.Parse()
	if help {
		usage()
		return
	}

	userConfig := viper.New()
	userConfig.SetConfigFile(confPath)

	err := userConfig.ReadInConfig()
	if err != nil {
		fmt.Printf("%v\n", err)
		return
	}

	mongoCluster := userConfig.GetString("mongo.uri")
	mongoDB := userConfig.GetString("mongo.dbname")
	mongoClient, err := NewMongoClient(mongoCluster)
	if err != nil {
		fmt.Printf("connect failed: %v\n", err)
		return
	}
	db := mongoClient.Database(mongoDB)

	switch opType {
	case "addUser":
		addUser(db)
	case "addIndex":
		addIndex(db)
	default:
		fmt.Printf("operation type %s is not support(addUser/addIndex)\n", opType)
	}
}

func addIndex(db *mongo.Database) {
	indexFile, err := os.Open(IndexFile)
	if err != nil {
		fmt.Printf("%v\n", err)
		return
	}

	defer func() {
		_ = indexFile.Close()
	}()

	var indexCollections []IndexCollection
	b, _ := io.ReadAll(indexFile)
	err = json.Unmarshal(b, &indexCollections)
	if err != nil {
		fmt.Printf("%v\n", err)
		return
	}

	for _, c := range indexCollections {
		collection := db.Collection(c.CollectionName)

		for _, index := range c.Index {
			keys := bson.D{}

			for field, value := range index.Keys {
				keys = append(keys, bson.E{Key: field, Value: int(value.(float64))})
			}
			mod := mongo.IndexModel{
				Keys:    keys,
				Options: options.Index().SetUnique(index.Unique),
			}

			_, err = collection.Indexes().CreateOne(context.Background(), mod)
			if err != nil {
				fmt.Printf("%v\n", err)
			}
		}
	}
}

func addUser(db *mongo.Database) {
	userCol := db.Collection(UserCollection)
	user := User{
		Username: userName,
		Password: Password,
	}
	user.Salt = RandStringBytes(16)
	user.Password = GenPassword(user.Password, user.Salt)
	user.Level = 0
	count, err := userCol.CountDocuments(context.Background(), bson.M{"username": user.Username})
	if err != nil {
		fmt.Printf("connect failed: %v\n", err)
		return
	}
	if count != 0 {
		fmt.Printf("user existed!")
		return
	}

	res, err := userCol.InsertOne(context.Background(), user)
	if err != nil {
		fmt.Printf("connect failed: %v\n", err)
		return
	}
	fmt.Println("InsertedID:", res.InsertedID, user)
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func RandStringBytes(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}

func GenPassword(password, salt string) string {
	t := sha1.New()
	_, err := io.WriteString(t, password+salt)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%x", t.Sum(nil))
}

func NewMongoClient(uri string) (*mongo.Client, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var opt options.ClientOptions
	opt.SetMaxPoolSize(10)
	opt.SetMinPoolSize(10)
	opt.SetReadPreference(readpref.SecondaryPreferred())

	mongoClient, err := mongo.Connect(ctx, options.Client().ApplyURI(uri), &opt)
	if err != nil {
		fmt.Println("NEW_MONGO_ERROR", err.Error())
		return nil, err
	}

	err = mongoClient.Ping(ctx, readpref.Primary())
	if err != nil {
		fmt.Println("NEW_MONGO_ERROR", err.Error())
		return nil, err
	}

	return mongoClient, nil
}
