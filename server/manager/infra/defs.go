package infra

import (
	"github.com/go-redis/redis/v8"
	"github.com/spf13/viper"
	"go.mongodb.org/mongo-driver/mongo"
	"os"
)

const (
	DefaultCollection        = "default"
	UserCollection           = "user"
	AgentHeartBeatCollection = "agent_heartbeat"
	AgentTaskCollection      = "agent_task"
	AgentSubTaskCollection   = "agent_subtask"
)

var (
	Conf     *viper.Viper
	ConfPath string
	Sig      = make(chan os.Signal, 1)
	Quit     = make(chan bool)

	Grds          redis.Cmdable
	MongoClient   *mongo.Client
	MongoDatabase string

	HttpPort  int
	ApiAuth   bool
	InnerAuth map[string]string
	Secret    string

	SvrName string
	SvrAK   string
	SvrSK   string

	SDAddrs      []string
	RegisterName string
	LocalIP      string
	SdAK         string
	SdSK         string
)
