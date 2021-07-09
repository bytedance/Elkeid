PREFIX ?= /etc/elkeid/plugin/RASP
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
	rm -rf pangolin/build
	rm -rf python/python-client/build
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
	cd jvm/JVMProbe && sh build.sh

java-probe-example: ## build JVM probe example for test
	cd jvm/JVMProbe && ./gradlew build:example

java: java-attach java-probe ## java probe
	@echo "build JVM probe"
	mkdir -p output/rasp
	cp jvm/JVMProbe/output/SmithAgent.jar output/rasp/SmithAgent.jar
	cp jvm/jattach/build/jattach output/jattach

process_injector: ## build process injector
	mkdir -p pangolin/build && cd pangolin/build && \
	CC=$(CC) CXX=$(CXX) \
	LD=$(LD) cmake .. && make
	cd pangolin && \
	CFLAGS=-DDISABLE_LOG=1 CC=$(CC) LD=$(LD) make -C shellcode && mv shellcode/lib* bin

python-client: ## build python client
	mkdir -p python/python-client/build && cd python/python-client/build && \
	CC=$(CC) CXX=$(CXX) LD=$(LD) CFLAGS=-Wl,--no-undefined cmake -D CMAKE_CXX_FLAGS=-DLOG_LEVEL=1 .. && make


python-inject: ## build python injector
ifeq ($(STATIC), TRUE)
	mkdir -p python/python-inject/build && cd python/python-inject/build && \
	CC=$(CC) CXX=$(CXX) CFLAGS=-static-pie cmake .. && make
	cd python/python-inject && \
	CFLAGS=-DDISABLE_LOG=1 CC=$(CC) LD=$(LD) make -C caller && mv caller/python_caller bin
else
	mkdir -p python/python-inject/build && cd python/python-inject/build && \
	CC=$(CC) CXX=$(CXX) cmake .. && make
	cd python/python-inject && \
	CFLAGS=-DDISABLE_LOG=1 CC=$(CC) LD=$(LD) make -C caller && mv caller/python_caller bin
endif

python-probe: python-client python-inject ## install python client so
	cp python/python-client/bin/libpython_client.so python/rasp/resource/libsmith_client.so
	cd python/ && python setup.py sdist bdist_wheel --universal

python: python-probe ## build CPython probe
	@echo "build CPython probe"
	mkdir -p output/rasp/python
	cp python/python-inject/bin/* output/rasp/
	cp -r python/dist/rasp-1.0.0-py2.py3-none-any.whl output/rasp/python/
	cd output/rasp/python/ && unzip -o rasp-1.0.0-py2.py3-none-any.whl
	cp -r python/entry.py output/rasp/python/


go-probe: ## build golang probe
ifeq ($(STATIC), TRUE)
	mkdir -p golang/build && cd golang/build && \
	CC=$(CC) CXX=$(CXX) CFLAGS=-static-pie cmake .. && make
else
	mkdir -p golang/build && cd golang/build && \
	CC=$(CC) CXX=$(CXX) cmake .. && make
endif


go: go-probe ## build go probe
	@echo "build Golang probe"
	mkdir -p output/rasp/go_probe
	cp golang/bin/go_probe output/rasp/go_probe



node: nsenter ## build node probe
	@echo "budild NodeJS probe"
	mkdir -p output/rasp/node
	cp node/*.js output/rasp/node/

build: nsenter process_injector java python go node rasp server ## build all
	mkdir -p output
	mkdir -p output/rasp
	cp pangolin/bin/pangolin output/rasp/pangolin
	cp pangolin/bin/lib*.so output/rasp/
	cp util-linux/nsenter output/


install: ## install to $PREFIX default: /etc/elkeid/plugin/RASP
	mkdir -p $(PREFIX)
	cp -r output/* $(PREFIX)

