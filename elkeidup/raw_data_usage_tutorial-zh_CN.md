### Kafka Config
* Topic: hids_svr
* Auth Conf: `{"sasl.mechanism":"PLAIN","sasl.password":"elkeid","sasl.username":"admin","security.protocol":"SASL_PLAINTEXT"}`

### Elkeid Protobuf Schema
```protobuf
syntax = "proto3";
option go_package = "hids_pb";
package hids_pb;

//server -> bmq
message MQData{
  int32 data_type = 1;
  int64 timestamp = 2;
  Item body = 3;

  string agent_id = 4;
  string in_ipv4_list = 5;
  string ex_ipv4_list = 6;
  string in_ipv6_list = 7;
  string ex_ipv6_list = 8;
  string hostname = 9;
  string version = 10;
  string product = 11;

  int64  time_pkg = 12;
  string psm_name = 13;
  string psm_path = 14;
  string tags = 15;
}

message Item{d
  map<string,string> fields = 1;
}
```

### Option 1: Use Elkeid HUB
hids conf:
```protobuf
InputID: hids
InputName: hids
InputType: kafka
DataType: protobuf_hids
KafkaBootstrapServers: kafka:9092
KafkaGroupId: elkeid_test1
KafkaOffsetReset: earliest
KafkaCompression: none
KafkaTopics:
  - hids_svr
KafkaOtherConf: ~
KafkaWorkerSize: 2
```
```css
INPUT.hids --> OUTPUT.your_kafka
```
'your_kafka' 中可以得到json类型的Elkeid原始数据

### Option 2: Customize Consumer

(Python Kafka Example)

首先需要安装protobuf的 compiler，主要用于生成MQData_pb2.py 这个文件。用户可以使用我们直接提供的文件，或者自行编译。这里以 linux 为例，执行下面语句即可安装3.14的 protoc
PROTOC_ZIP=protoc-3.14.0-linux-x86_64.zip
```bash
curl -OL https://github.com/protocolbuffers/protobuf/releases/download/v3.14.0/$PROTOC_ZIP
sudo unzip -o $PROTOC_ZIP -d /usr/local bin/protoc
sudo unzip -o $PROTOC_ZIP -d /usr/local 'include/*'
rm -f $PROTOC_ZIP
```

将上面的PB Schema进行编译
```bash
protoc -I=. --python_out=. ./MQData.proto
```
会生成  MQData_pb2.py 文件，将这个文件放到您的项目中

因为Elkeid PB 将主要数据放入 body.field 这个map中，因此需要对数据进行拍平，生成原生的一级数据结构。这里提供一个 decoder 供Kafka Serializer使用
```python
#!/usr/bin/python3

# decoder of Elkeid PB, input string and will dump json for you.
def pbDecoder(value):
ret = {}
aMQData = MQData.MQData();
aMQData.ParseFromString(value)

    # common part of message
    ret["data_type"] = str(aMQData.data_type)
    ret["timestamp"] = str(aMQData.timestamp)
    ret["agent_id"] = aMQData.agent_id
    ret["in_ipv4_list"] = aMQData.in_ipv4_list
    ret["ex_ipv4_list"] = aMQData.ex_ipv4_list
    ret["in_ipv6_list"] = aMQData.in_ipv6_list
    ret["ex_ipv6_list"] = aMQData.ex_ipv6_list
    ret["hostname"] = aMQData.hostname
    ret["version"] = aMQData.version
    ret["product"] = aMQData.product
    ret["time_pkg"] = str(aMQData.time_pkg)
    ret["psm_name"] = aMQData.psm_name
    ret["psm_path"] = aMQData.psm_path
    ret["tags"] = aMQData.tags

    # major data part of message
    for key in aMQData.body.fields:
        ret[key] =  aMQData.body.fields[key]
    
    return json.dumps(ret)
```

然后创建 Kafka consumer，将上述的decoder作为 kafka 的 value_deserializer 传递进去。Elkeid的默认topic为 hids_svr
```python
#!/usr/bin/python3
from kafka import KafkaConsumer
import MQData_pb2 as MQData # 刚刚编译的那个class文件
import json

# decoder of Elkeid PB, input string and will dump json for you.
def pbDecoder(value):
ret = {}
aMQData = MQData.MQData();
aMQData.ParseFromString(value)

    # common part of message
    ret["data_type"] = str(aMQData.data_type)
    ret["timestamp"] = str(aMQData.timestamp)
    ret["agent_id"] = aMQData.agent_id
    ret["in_ipv4_list"] = aMQData.in_ipv4_list
    ret["ex_ipv4_list"] = aMQData.ex_ipv4_list
    ret["in_ipv6_list"] = aMQData.in_ipv6_list
    ret["ex_ipv6_list"] = aMQData.ex_ipv6_list
    ret["hostname"] = aMQData.hostname
    ret["version"] = aMQData.version
    ret["product"] = aMQData.product
    ret["time_pkg"] = str(aMQData.time_pkg)
    ret["psm_name"] = aMQData.psm_name
    ret["psm_path"] = aMQData.psm_path
    ret["tags"] = aMQData.tags

    # major data part of message
    for key in aMQData.body.fields:
        ret[key] =  aMQData.body.fields[key]
    
    return json.dumps(ret)


# To consume latest messages and auto-commit offsets
consumer = KafkaConsumer('hids_svr',
group_id='test',
auto_offset_reset='latest',
bootstrap_servers=['10.2.0.67:9092', '10.2.0.233:9092', '10.2.0.92:9092'],
value_deserializer = lambda m: pbDecoder(m))

# Print all message in JSON format
# this is the part that you need to code to your job
for message in consumer:
# do something with message.value
print ("%s:%d:%d: key=%s value=%s" % (message.topic, message.partition,
message.offset, message.key,
message.value))
```

<img src="pb_to_json.png" style="float:left;"/>

