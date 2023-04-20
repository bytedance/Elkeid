echo "// $RANDOM " >>main.go

BUILD_VERSION="1.0.1.19"
GOARCH=arm64 go build -o baseline main.go
tar -zcvf baseline-linux-amd64-${BUILD_VERSION}.tar.gz baseline config

mkdir output 2>/dev/null
sha256sum baseline | awk '{print($1)}'> output/sign
sha256sum baseline-linux-amd64-${BUILD_VERSION}.tar.gz | awk '{print($1)}' > output/sha256
mv baseline-linux-amd64-${BUILD_VERSION}.tar.gz output
echo ${BUILD_VERSION} > output/version