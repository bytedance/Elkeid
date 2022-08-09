PREFIX ?= /etc/elkeid/plugin/rasp
STATIC ?= "FALSE"
VERSION ?= 1.9.1.0
PERV_LIB ?= "lib"

.PHONY: help
help:
	@echo "Usage : make <commands>"
	@echo "available commands :"
	@echo "---"
	@echo "Hint :"
	@echo "make build && sudo make install"
	@echo "---"
	@grep -hE '##' Makefile  | grep -v grep | sed -e 's/\\$$//' | sed -e 's/##/,/'  | sed -e 's/:.*,/ ,/' | column -t -c2 -s,

update_version: ## patch version VERSION=x.x.x.x
	sed -i "s/1.0.0.1/${VERSION}/g" "librasp/src/settings.rs"
	sed -i "s/1.0.0/${VERSION}/g" "node/client.js"
	sed -i "s/1.0.0/${VERSION}/g" "python/python-probe/rasp/client.py"
	sed -i "s/1.0.0/${VERSION}/g" "golang/client/smith_message.cpp"


rasp: ## build elkeid_rasp bin file
	mkdir -p output
ifeq ($(STATIC), TRUE)
	$(MAKE) -C librasp build-musl
	cp librasp/target/x86_64-unknown-linux-musl/release/elkeid_rasp output/elkeid_rasp
else
	$(MAKE) -C librasp build
	cp librasp/target/release/elkeid_rasp output/elkeid_rasp
endif


server: ## build rasp_server bin file
	mkdir -p output/lib
ifeq ($(STATIC), TRUE)
	$(MAKE) -C rasp_server build-musl
	cp rasp_server/target/x86_64-unknown-linux-musl/release/rasp_server output/lib/rasp_server
else
	$(MAKE) -C rasp_server build
	cp rasp_server/target/release/rasp_server output/lib/rasp_server
endif


clean: ## clean your workspace
	$(MAKE) -C rasp_server clean
	$(MAKE) -C librasp clean
	$(MAKE) -C plugin clean
	rm -rf pangolin/build
	rm -rf python/python-probe/build
	rm -rf python/python-probe/dist
	rm -rf python/python-probe/rasp.egg-info
	rm -rf python/python-loader/build
	rm -rf golang/build
	rm -rf output


nsenter: ## build nsenter from util-linux
ifeq ($(STATIC), TRUE)
	cd util-linux && \
	./autogen.sh && \
	CC=$(CC) CFLAGS="-static" ./configure --enable-static-programs=nsenter --disable-all-programs --enable-nsenter && \
	make
	cp util-linux/nsenter.static output/nsenter
else
	cd util-linux && \
	./autogen.sh && \
	CC=$(CC) ./configure --enable-static-programs=nsenter --disable-all-programs --enable-nsenter && \
	make
	cp util-linux/nsenter output/nsenter
endif

java-attach: ## build jattach using musl-gcc
ifeq ($(STATIC), TRUE)
	cd jvm/jattach && \
	mkdir -p build && \
	$(CC) -static -DJATTACH_VERSION=\"1.5\" src/jattach_posix.c -o build/jattach
else
	cd jvm/jattach && \
	mkdir -p build && \
	$(CC) -DJATTACH_VERSION=\"1.5\" src/jattach_posix.c -o build/jattach
endif


java-probe: ## build JVM probe
	cd jvm/JVMProbe && mkdir -p output && ./gradlew proguard && cp build/libs/JVMProbe-1.0-SNAPSHOT-pro.jar output/SmithAgent.jar

java-probe-example: ## build JVM probe example for test
	cd jvm/JVMProbe && ./gradlew build:example

java: java-attach java-probe ## java probe
	@echo "build JVM probe"
	mkdir -p output/lib/java
	cp jvm/JVMProbe/output/SmithAgent.jar output/lib/java/SmithAgent.jar
	cp jvm/jattach/build/jattach output/lib/java/jattach

process_injector: ## build process injector
	cd pangolin && \
	CFLAGS=-DDISABLE_LOG=1 CC=$(CC) LD=$(LD) make -C shellcode
	mkdir -p pangolin/build && cd pangolin/build && \
	CC=$(CC) CXX=$(CXX) \
	LD=$(LD) cmake -DSTATIC_BUILD=$(STATIC) .. && make
	mkdir -p output/lib
	cp pangolin/bin/pangolin output/lib/pangolin

python-loader: ## build python loader
	mkdir -p python/python-loader/build && cd python/python-loader/build && \
	CC=$(CC) CXX=$(CXX) cmake -DSTATIC_BUILD=$(STATIC) .. && make

python-probe: python-loader ## install python client so
	cd python/python-probe && python3 setup.py sdist bdist_wheel --universal

python: python-probe ## build CPython probe
	@echo "build CPython probe"
	mkdir -p output/
	mkdir -p output/lib
	mkdir -p output/lib/python
	cp python/python-loader/bin/* output/lib/python/
	cp -r python/python-probe/dist/rasp-1.0.0-py2.py3-none-any.whl output/lib/python/
	cd output/lib/python/ && unzip -o rasp-1.0.0-py2.py3-none-any.whl
	cp -r python/entry.py output/lib/python/


go-probe: ## build golang probe
	mkdir -p golang/build && cd golang/build && \
	CC=$(CC) CXX=$(CXX) cmake -DSTATIC_BUILD=$(STATIC) .. && make


go: go-probe ## build go probe
	@echo "build Golang probe"
	mkdir -p output
	mkdir -p output/lib
	mkdir -p output/lib/golang
	cp golang/bin/go_probe output/lib/golang/go_probe
	cp golang/bin/go_loader output/lib/golang/go_loader


node: nsenter ## build node probe
	@echo "build NodeJS probe"
	mkdir -p output/lib/node
	cp node/*.js output/lib/node/

agent_plugin: rasp server ## build Elkeid-RASP plugin for Agent
	@echo "build plugin"
	mkdir -p output
	make -C plugin
ifeq ($(STATIC), TRUE)
	$(MAKE) -C plugin plugin-musl
	cp plugin/target/x86_64-unknown-linux-musl/release/elkeid_rasp_monitor output/rasp
	cp plugin/settings.toml output/settings.toml
else
	$(MAKE) -C plugin plugin
	cp plugin/target/release/elkeid_rasp_monitor output/rasp
	cp plugin/settings.toml output/settings.toml
endif

build: agent_plugin nsenter process_injector java python go node rasp server ## build all
	cd output && mv lib "lib-${VERSION}"
	cd output && mkdir "${PERV_LIB}"
	cd output && tar -czvf "rasp_${VERSION}.tar.gz" ./* && sha256sum "rasp_${VERSION}.tar.gz" && sha256sum rasp
	mv "output/rasp_${VERSION}.tar.gz" .


install: ## install to $PREFIX default: /etc/elkeid/plugin/rasp
	mkdir -p $(PREFIX)
	cp -r output/* $(PREFIX)
