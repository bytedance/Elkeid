PREFIX ?= /etc/elkeid/plugin/rasp
STATIC ?= "FALSE"

.PHONY: help
help:
	@echo "Usage : make <commands>"
	@echo "available commands :"
	@echo "---"
	@echo "Hint :"
	@echo "make build && sudo make install"
	@echo "---"
	@grep -hE '##' Makefile  | grep -v grep | sed -e 's/\\$$//' | sed -e 's/##/,/'  | sed -e 's/:.*,/ ,/' | column -t -c2 -s,

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
	mkdir -p output
ifeq ($(STATIC), TRUE)
	$(MAKE) -C rasp_server build-musl
	cp rasp_server/target/x86_64-unknown-linux-musl/release/rasp_server output/rasp_server
else
	$(MAKE) -C rasp_server build
	cp rasp_server/target/release/rasp_server output/rasp_server
endif


clean: ## clean your workspace
	$(MAKE) -C rasp_server clean
	$(MAKE) -C librasp clean
	$(MAKE) -C plugin clean
	rm -rf pangolin/build
	rm -rf python/build
	rm -rf python/dist
	rm -rf python/rasp.egg-info
	rm -rf python/python-inject/build
	rm -rf golang/build
	rm -rf output


nsenter: ## build nsenter from util-linux
ifeq ($(STATIC), TRUE)
	cd util-linux && \
	./autogen.sh && \
	CC=$(CC) CFLAGS="-static" ./configure --enable-static-programs=nsenter --disable-all-programs --enable-nsenter && \
	make
else
	cd util-linux && \
	./autogen.sh && \
	CC=$(CC) ./configure --enable-static-programs=nsenter --disable-all-programs --enable-nsenter && \
	make
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
	mkdir -p output/java
	cp jvm/JVMProbe/output/SmithAgent.jar output/java/SmithAgent.jar
	cp jvm/jattach/build/jattach output/java/jattach

process_injector: ## build process injector
	mkdir -p pangolin/build && cd pangolin/build && \
	CC=$(CC) CXX=$(CXX) \
	LD=$(LD) cmake -DSTATIC_BUILD=$(STATIC) .. && make
	cd pangolin && \
	CFLAGS=-DDISABLE_LOG=1 CC=$(CC) LD=$(LD) make -C shellcode && mv shellcode/lib* bin
	cp pangolin/bin/pangolin output/pangolin
	cp pangolin/bin/lib*.so output/

python-inject: ## build python injector
	mkdir -p python/python-inject/build && cd python/python-inject/build && \
	CC=$(CC) CXX=$(CXX) cmake -DSTATIC_BUILD=$(STATIC) .. && make
	cd python/python-inject && \
	CFLAGS=-DDISABLE_LOG=1 CC=$(CC) LD=$(LD) make -C caller && mv caller/python_caller bin

python-probe: python-inject ## install python client so
	cd python/ && python setup.py sdist bdist_wheel --universal

python: python-probe ## build CPython probe
	@echo "build CPython probe"
	mkdir -p output/python
	cp python/python-inject/bin/* output/
	cp -r python/dist/rasp-1.0.0-py2.py3-none-any.whl output/python/
	cd output/python/ && unzip -o rasp-1.0.0-py2.py3-none-any.whl
	cp -r python/entry.py output/python/


go-probe: ## build golang probe
	mkdir -p golang/build && cd golang/build && \
	CC=$(CC) CXX=$(CXX) cmake -DSTATIC_BUILD=$(STATIC) .. && make


go: go-probe ## build go probe
	@echo "build Golang probe"
	cp golang/bin/go_probe output/go_probe


node: nsenter ## build node probe
	@echo "build NodeJS probe"
	mkdir -p output/node
	cp node/*.js output/node/

agent_plugin: rasp server ## build Elkeid-RASP plugin for Agent
	@echo "build plugin"
	mkdir -p output
	make -C plugin
ifeq ($(STATIC), TRUE)
	$(MAKE) -C plugin plugin-musl
	cp plugin/target/x86_64-unknown-linux-musl/release/elkeid_rasp_monitor output/rasp
else
	$(MAKE) -C plugin plugin
	cp plugin/target/release/elkeid_rasp_monitor output/rasp
endif

build: agent_plugin nsenter process_injector java python go node rasp server ## build all
	mkdir -p output
	cp util-linux/nsenter output/


install: ## install to $PREFIX default: /etc/elkeid/plugin/rasp
	mkdir -p $(PREFIX)
	cp -r output/* $(PREFIX)

