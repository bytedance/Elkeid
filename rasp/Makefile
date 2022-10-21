PREFIX ?= /etc/elkeid/plugin/rasp
STATIC ?= "FALSE"
VERSION ?= 1.0.0.0

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
	sed -i "s/1.0.0/${VERSION}/g" "python/python-probe/rasp/probe/client/smith_message.cpp"
	sed -i "s/1.0.0/${VERSION}/g" "golang/client/smith_message.cpp"
	sed -i "s/1.0.0/${VERSION}/g" "php/client/smith_message.cpp"


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
	CFLAGS="-static" ./configure --enable-static-programs=nsenter --disable-all-programs --enable-nsenter && \
	make
	cp util-linux/nsenter.static output/nsenter
else
	cd util-linux && \
	./autogen.sh && \
	./configure --enable-static-programs=nsenter --disable-all-programs --enable-nsenter && \
	make
	cp util-linux/nsenter output/nsenter
endif

mounts:
	mkdir -p output
	chmod +x mount_script
	cp mount_script output/mount_script

java-attach: ## build jattach using musl-gcc
ifeq ($(STATIC), TRUE)
	cd jvm/jattach && \
	mkdir -p build && \
	$(CC) -static -DJATTACH_VERSION=\"2.1\" src/posix/*.c -o build/jattach
else
	cd jvm/jattach && \
	mkdir -p build && \
	$(CC) -DJATTACH_VERSION=\"2.1\" src/posix/*.c -o build/jattach
endif


java-probe: ## build JVM probe
	cd jvm/JVMProbe && mkdir -p output && BUILD_VERSION=${VERSION} ./gradlew proguard && cp build/libs/JVMProbe-1.0-SNAPSHOT-pro.jar output/SmithAgent.jar

java-probe-example: ## build JVM probe example for test
	cd jvm/JVMProbe && ./gradlew build:example

java: java-attach java-probe ## java probe
	@echo "build JVM probe"
	mkdir -p output/lib/java
	cp jvm/JVMProbe/output/SmithAgent.jar output/lib/java/SmithAgent.jar
	cp jvm/jattach/build/jattach output/lib/java/jattach

process_injector: ## build process injector
	cd pangolin && \
	CFLAGS=-DDISABLE_LOG=1 make -C shellcode
	mkdir -p pangolin/build && cd pangolin/build && \
	cmake -DSTATIC_BUILD=$(STATIC) .. && make
	mkdir -p output/lib
	cp pangolin/bin/pangolin output/lib/pangolin

python-loader: ## build python loader
	mkdir -p python/python-loader/build && cd python/python-loader/build && \
	cmake -DSTATIC_BUILD=$(STATIC) .. && make

python-probe: python-loader ## build python package
ifeq ($(STATIC), TRUE)
ifeq ($(PY_PREBUILT), TRUE)
	cd python/python-probe && mkdir -p rasp/probe/build && CC=$(GNU_CC) CXX=$(GNU_CXX) cmake -B rasp/probe/build -DSTATIC_BUILD=ON -DPython_INCLUDE_DIRS=$(PYTHON2_INCLUDE) rasp/probe && cmake --build rasp/probe/build -j$$(nproc) && cp rasp/probe/lib/libpython_probe.so rasp/probe.so && cmake -B rasp/probe/build -DSTATIC_BUILD=ON -DPython_INCLUDE_DIRS=$(PYTHON3_INCLUDE) rasp/probe && cmake --build rasp/probe/build -j$$(nproc) && cp rasp/probe/lib/libpython_probe.so rasp/probe.abi3.so && PREBUILT=1 python3 setup.py bdist_wheel
else
	cd python/python-probe && CC=$(GNU_CC) CXX=$(GNU_CXX) python3 setup.py bdist_wheel
endif
else
ifeq ($(PY_PREBUILT), TRUE)
	cd python/python-probe && mkdir -p rasp/probe/build && cmake -B rasp/probe/build -DSTATIC_BUILD=ON -DPython_INCLUDE_DIRS=$(PYTHON2_INCLUDE) rasp/probe && cmake --build rasp/probe/build -j$$(nproc) && cp rasp/probe/lib/libpython_probe.so rasp/probe.so && cmake -B rasp/probe/build -DSTATIC_BUILD=ON -DPython_INCLUDE_DIRS=$(PYTHON3_INCLUDE) rasp/probe && cmake --build rasp/probe/build -j$$(nproc) && cp rasp/probe/lib/libpython_probe.so rasp/probe.abi3.so && PREBUILT=1 python3 setup.py bdist_wheel
else
	cd python/python-probe && python3 setup.py bdist_wheel
endif
endif

python: python-probe ## build CPython probe
	@echo "build CPython probe"
	mkdir -p output/
	mkdir -p output/lib
	mkdir -p output/lib/python
	cp python/python-loader/bin/* output/lib/python/
	cp -r python/python-probe/dist/rasp-*.whl output/lib/python/
	cd output/lib/python/ && unzip -o rasp-*.whl


go-probe: ## build golang probe
	mkdir -p golang/build && cd golang/build && \
	cmake -DSTATIC_BUILD=$(STATIC) .. && make


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

php_probe: ## build php probe
	@echo "build PHP probe"
	mkdir -p output/lib/php
ifeq ($(STATIC), TRUE)
	cd php && mkdir -p output build; for header in ${PHP_HEADERS}/*; do [ -d include ] && rm -rf include; cp -r $$header include; CC=$(GNU_CC) CXX=$(GNU_CXX) cmake -B build -DSTATIC_BUILD=ON -DPHP_EXTENSIONS_INCLUDE_DIR=$$(pwd)/include && cmake --build build -j$$(nproc) && cp lib/libphp_probe.so output/libphp_probe-$$(basename $$header).so; done
else
	cd php && mkdir -p output build; for header in ${PHP_HEADERS}/*; do [ -d include ] && rm -rf include; cp -r $$header include; cmake -B build -DSTATIC_BUILD=ON -DPHP_EXTENSIONS_INCLUDE_DIR=$$(pwd)/include && cmake --build build -j$$(nproc) && cp lib/libphp_probe.so output/libphp_probe-$$(basename $$header).so; done
endif
	cp php/output/* output/lib/php


agent_plugin: rasp server ## build Elkeid-RASP plugin for Agent
	@echo "build plugin"
	mkdir -p output
ifeq ($(STATIC), TRUE)
	$(MAKE) -C plugin plugin-musl
	cp plugin/target/x86_64-unknown-linux-musl/release/elkeid_rasp_monitor output/rasp
	cp plugin/settings.toml output/settings.toml
else
	$(MAKE) -C plugin plugin
	cp plugin/target/release/elkeid_rasp_monitor output/rasp
	cp plugin/settings.toml output/settings.toml
endif

define split_debug
	objcopy --only-keep-debug $(1) debug/$$(basename $(1)).debug
	strip --strip-debug --strip-unneeded $(1)
	objcopy --add-gnu-debuglink=./debug/$$(basename $(1)).debug $(1)
endef

build: update_version agent_plugin nsenter mounts process_injector java python go node php_probe rasp server ## build all
	mkdir -p debug

	$(call split_debug, output/rasp)
	$(call split_debug, output/elkeid_rasp)
	$(call split_debug, output/lib/pangolin)
	$(call split_debug, output/lib/rasp_server)
	$(call split_debug, output/lib/golang/go_loader)
	$(call split_debug, output/lib/golang/go_probe)
	$(call split_debug, output/lib/python/python_loader)
	$(foreach file, $(wildcard output/lib/php/*), $(call split_debug, $(file));)

	tar -czvf debug.tar.gz debug
	cd output && mv lib "lib-${VERSION}" && tar -czvf ../rasp_${VERSION}.tar.gz ./*
	sha256sum "rasp_${VERSION}.tar.gz" && sha256sum output/rasp

install: ## install to $PREFIX default: /etc/elkeid/plugin/rasp
	mkdir -p $(PREFIX)
	cp -r output/* $(PREFIX)
