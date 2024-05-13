PREFIX ?= /etc/elkeid/plugin/rasp
STATIC ?= "FALSE"
VERSION ?= 1.0.0.0
OUTPUT ?= output
DEBUG_SYMBOLS ?= debug
LIB_OUTPUT ?= $(OUTPUT)/lib-$(VERSION)
VCPKG_OVERLAY_PORTS ?= $(abspath overlay-ports)

.PHONY: all help install clean set-version agent-plugin nsenter pangolin jattach  JVMAgent JVMProbe python-probe python-loader go-probe go-probe-ebpf node-probe php-probe librasp rasp-server NSMount

all: rasp-$(VERSION).tar.gz rasp-$(VERSION)-debug.tar.gz SHA256SUMS


help:
	@echo "Usage : make <commands>"
	@echo "available commands :"
	@echo "---"
	@echo "Hint :"
	@echo "make build && sudo make install"
	@echo "---"
	@grep -hE '##' Makefile  | grep -v grep | sed -e 's/\\$$//' | sed -e 's/##/,/'  | sed -e 's/:.*,/ ,/' | column -t -c2 -s,


install: | $(OUTPUT)
	mkdir -p $(PREFIX)
	cp -r $(OUTPUT)/* $(PREFIX)


clean:
	rm -rf $(OUTPUT) $(DEBUG_SYMBOLS) rasp-$(VERSION).tar.gz rasp-$(VERSION)-debug.tar.gz SHA256SUMS


rasp-$(VERSION).tar.gz: rasp-$(VERSION)-debug.tar.gz
	cd $(OUTPUT) && tar -czvf ../$@ ./*


rasp-$(VERSION)-debug.tar.gz: | $(DEBUG_SYMBOLS)
	tar -czvf $@ $(DEBUG_SYMBOLS)


SHA256SUMS: rasp-$(VERSION).tar.gz
	sha256sum $(OUTPUT)/rasp rasp-$(VERSION).tar.gz > $@


set-version:
	sed -i "s/1.0.0.1/${VERSION}/g" "librasp/src/settings.rs"
	sed -i "s/1.0.0/${VERSION}/g" "node/src/client.js"
	sed -i "s/1.0.0/${VERSION}/g" "python/python-probe/rasp/probe/client/smith_message.cpp"
	sed -i "s/1.0.0/${VERSION}/g" "golang/client/smith_message.cpp"
	sed -i "s/1.0.0/${VERSION}/g" "golang-ebpf/client/smith_message.cpp"
	sed -i "s/1.0.0/${VERSION}/g" "php/client/smith_message.cpp"


librasp:
ifeq ($(STATIC), TRUE)
	$(MAKE) -C librasp build-musl
else
	$(MAKE) -C librasp build
endif


rasp-server:
ifeq ($(STATIC), TRUE)
	$(MAKE) -C rasp_server build-musl
else
	$(MAKE) -C rasp_server build
endif


agent-plugin:
ifeq ($(STATIC), TRUE)
	$(MAKE) -C plugin plugin-musl
else
	$(MAKE) -C plugin plugin
endif


NSMount:
	cd NSMount && \
	mkdir -p build && \
	cmake -B build \
		-DCMAKE_BUILD_TYPE=Release \
		-DSTATIC_BUILD=$(STATIC) \
		-DCMAKE_TOOLCHAIN_FILE="$(VCPKG_INSTALLATION_ROOT)/scripts/buildsystems/vcpkg.cmake" \
		-DVCPKG_TARGET_TRIPLET=x64-linux-release && \
	$(MAKE) -C build


nsenter:
ifeq ($(STATIC), TRUE)
	cd util-linux && \
	./autogen.sh && \
	CFLAGS="-static" ./configure --enable-static-programs=nsenter --disable-all-programs --enable-nsenter && \
	$(MAKE)
else
	cd util-linux && \
	./autogen.sh && \
	./configure --enable-static-programs=nsenter --disable-all-programs --enable-nsenter && \
	$(MAKE)
endif


jattach:
ifeq ($(STATIC), TRUE)
	cd jvm/jattach && \
	mkdir -p build && \
	$(CC) -static -DJATTACH_VERSION=\"2.1\" src/posix/*.c -o build/jattach
else
	cd jvm/jattach && \
	mkdir -p build && \
	$(CC) -DJATTACH_VERSION=\"2.1\" src/posix/*.c -o build/jattach
endif


JVMAgent:
	cd jvm/JVMAgent && \
	mkdir -p output && \
	BUILD_VERSION=${VERSION} ./gradlew shadow && \
	cp build/libs/JVMAgent-1.0-SNAPSHOT-all.jar output/SmithAgent.jar
JVMProbe:
	cd jvm/JVMProbe && \
	mkdir -p output && \
	BUILD_VERSION=${VERSION} ./gradlew shadow && \
	cp build/libs/JVMProbe-1.0-SNAPSHOT-all.jar output/SmithProbe.jar


pangolin:
	cd pangolin && \
	CFLAGS=-DDISABLE_LOG=1 $(MAKE) -C shellcode && \
	mkdir -p build && \
	cmake -B build \
		-DCMAKE_BUILD_TYPE=Release \
		-DSTATIC_BUILD=$(STATIC) && \
	$(MAKE) -C build


python-loader:
ifeq ($(STATIC), TRUE)
	cd python/python-loader && \
	mkdir -p build && \
	cmake -B build \
		-DCMAKE_BUILD_TYPE=Release \
		-DSTATIC_BUILD=ON \
		-DCMAKE_TOOLCHAIN_FILE="$(VCPKG_INSTALLATION_ROOT)/scripts/buildsystems/vcpkg.cmake" \
		-DVCPKG_OVERLAY_PORTS=$(VCPKG_OVERLAY_PORTS) \
		-DVCPKG_TARGET_TRIPLET=x64-linux-release && \
	$(MAKE) -C build
else
	cd python/python-loader && \
	mkdir -p build && \
	cmake -B build \
		-DCMAKE_BUILD_TYPE=Release \
		-DSTATIC_BUILD=OFF \
		-DCMAKE_TOOLCHAIN_FILE="$(VCPKG_INSTALLATION_ROOT)/scripts/buildsystems/vcpkg.cmake" \
		-DVCPKG_TARGET_TRIPLET=x64-linux-release && \
	$(MAKE) -C build
endif


python-probe:
ifeq ($(STATIC), TRUE)
ifeq ($(PY_PREBUILT), TRUE)
	cd python/python-probe && \
	mkdir -p rasp/probe/build && \
	CC=$(GNU_CC) CXX=$(GNU_CXX) cmake -B rasp/probe/build \
		-DCMAKE_BUILD_TYPE=Release \
		-DSTATIC_BUILD=ON \
		-DPython_INCLUDE_DIRS=$(PYTHON2_INCLUDE) \
		-DCMAKE_TOOLCHAIN_FILE="$(VCPKG_INSTALLATION_ROOT)/scripts/buildsystems/vcpkg.cmake" \
		-DVCPKG_TARGET_TRIPLET=x64-linux-release rasp/probe && \
	$(MAKE) -C rasp/probe/build && \
	cp rasp/probe/lib/libpython_probe.so rasp/probe.so && \
	CC=$(GNU_CC) CXX=$(GNU_CXX) cmake -B rasp/probe/build \
		-DCMAKE_BUILD_TYPE=Release \
		-DSTATIC_BUILD=ON \
		-DPython_INCLUDE_DIRS=$(PYTHON3_INCLUDE) \
		-DCMAKE_TOOLCHAIN_FILE="$(VCPKG_INSTALLATION_ROOT)/scripts/buildsystems/vcpkg.cmake" \
		-DVCPKG_TARGET_TRIPLET=x64-linux-release rasp/probe && \
	$(MAKE) -C rasp/probe/build && \
	cp rasp/probe/lib/libpython_probe.so rasp/probe.abi3.so && \
	PREBUILT=1 python3 setup.py bdist_wheel
else
	cd python/python-probe && \
	CC=$(GNU_CC) CXX=$(GNU_CXX) python3 setup.py bdist_wheel
endif
else
ifeq ($(PY_PREBUILT), TRUE)
	cd python/python-probe && \
	mkdir -p rasp/probe/build && \
	cmake -B rasp/probe/build \
		-DCMAKE_BUILD_TYPE=Release \
		-DSTATIC_BUILD=ON \
		-DPython_INCLUDE_DIRS=$(PYTHON2_INCLUDE) \
		-DCMAKE_TOOLCHAIN_FILE="$(VCPKG_INSTALLATION_ROOT)/scripts/buildsystems/vcpkg.cmake" \
		-DVCPKG_TARGET_TRIPLET=x64-linux-release rasp/probe && \
	$(MAKE) -C rasp/probe/build && \
	cp rasp/probe/lib/libpython_probe.so rasp/probe.so && \
	cmake -B rasp/probe/build \
		-DCMAKE_BUILD_TYPE=Release \
		-DSTATIC_BUILD=ON \
		-DPython_INCLUDE_DIRS=$(PYTHON3_INCLUDE) \
		-DCMAKE_TOOLCHAIN_FILE="$(VCPKG_INSTALLATION_ROOT)/scripts/buildsystems/vcpkg.cmake" \
		-DVCPKG_TARGET_TRIPLET=x64-linux-release rasp/probe && \
	$(MAKE) -C rasp/probe/build && \
	cp rasp/probe/lib/libpython_probe.so rasp/probe.abi3.so && \
	PREBUILT=1 python3 setup.py bdist_wheel
else
	cd python/python-probe && python3 setup.py bdist_wheel
endif
endif


go-probe:
ifeq ($(STATIC), TRUE)
	cd golang && \
	mkdir -p build && \
	cmake -B build \
		-DCMAKE_BUILD_TYPE=Release \
		-DSTATIC_BUILD=ON \
		-DCMAKE_TOOLCHAIN_FILE="$(VCPKG_INSTALLATION_ROOT)/scripts/buildsystems/vcpkg.cmake" \
		-DVCPKG_OVERLAY_PORTS=$(VCPKG_OVERLAY_PORTS) \
		-DVCPKG_TARGET_TRIPLET=x64-linux-release && \
	$(MAKE) -C build
else
	cd golang && \
	mkdir -p build && \
	cmake -B build \
		-DCMAKE_BUILD_TYPE=Release \
		-DSTATIC_BUILD=OFF \
		-DCMAKE_TOOLCHAIN_FILE="$(VCPKG_INSTALLATION_ROOT)/scripts/buildsystems/vcpkg.cmake" \
		-DVCPKG_TARGET_TRIPLET=x64-linux-release&& \
	$(MAKE) -C build
endif


go-probe-ebpf:
	mkdir -p golang-ebpf/output golang-ebpf/build
ifeq ($(STATIC), TRUE)
	curl -fsSL https://zlib.net/zlib-1.3.tar.gz | tar -xz -C /tmp && cd /tmp/zlib-1.3 && CFLAGS="-fPIC" ./configure --static --prefix=/tmp/output && $(MAKE) && $(MAKE) install && rm -rf /tmp/zlib-1.3
	curl -fsSL https://github.com/arachsys/libelf/archive/refs/tags/v0.188.tar.gz | tar -xz -C /tmp && cd /tmp/libelf-0.188 && sed -e 's|^CFLAGS = |CFLAGS = -fPIC -I/tmp/output/include -L/tmp/output/lib |g' -i Makefile && $(MAKE) PREFIX=/tmp/output install-static && rm -rf /tmp/libelf-0.188
	echo -e 'prefix=/tmp/output\nexec_prefix=$${prefix}\nlibdir=$${exec_prefix}/lib\nincludedir=$${prefix}/include\n\nName: libelf\nDescription: elfutils libelf library to read and write ELF files\nVersion: 0.188\nURL: http://elfutils.org/\n\nLibs: -L$${libdir} -lelf\nCflags: -I$${includedir}\n\nRequires.private: zlib' > /tmp/output/lib/pkgconfig/libelf.pc

	cd golang-ebpf && \
	$(MAKE) -C ebpf clean && \
	PKG_CONFIG_PATH=/tmp/output/lib/pkgconfig $(MAKE) -C ebpf \
		V=1 \
		HOSTCC=$(CC) \
		EXTRA_LDFLAGS="-static-pie" \
		EXTRA_CFLAGS="-fPIC -L/tmp/output/lib -I/tmp/output/include -D__always_inline=__inline__" \
		BPF_CFLAGS="-D__x86_64__" && \
	PKG_CONFIG_PATH="/tmp/output/lib/pkgconfig:$$(pwd)/ebpf/.output/libbpf/lib64/pkgconfig" cmake -B build \
		-DCMAKE_BUILD_TYPE=Release \
		-DSTATIC_BUILD=ON \
		-DZLIB_ROOT=/tmp/output \
		-DCMAKE_TOOLCHAIN_FILE="$(VCPKG_INSTALLATION_ROOT)/scripts/buildsystems/vcpkg.cmake" \
		-DVCPKG_TARGET_TRIPLET=x64-linux-release && \
	$(MAKE) -C build && \
	cp bin/go_probe_ebpf output/go_probe_ebpf_4.14

	cd golang-ebpf && \
	$(MAKE) -C ebpf clean && \
	PKG_CONFIG_PATH=/tmp/output/lib/pkgconfig $(MAKE) -C ebpf \
		V=1 \
		HOSTCC=$(CC) \
		EXTRA_LDFLAGS="-static-pie" \
		EXTRA_CFLAGS="-fPIC -L/tmp/output/lib -I/tmp/output/include -D__always_inline=__inline__" \
		BPF_CFLAGS="-D__x86_64__ -DENABLE_HTTP -DDISABLE_HTTP_HEADER" && \
	PKG_CONFIG_PATH="/tmp/output/lib/pkgconfig:$$(pwd)/ebpf/.output/libbpf/lib64/pkgconfig" cmake -B build \
		-DCMAKE_BUILD_TYPE=Release \
		-DSTATIC_BUILD=ON \
		-DZLIB_ROOT=/tmp/output \
		-DCMAKE_CXX_FLAGS="-DENABLE_HTTP -DDISABLE_HTTP_HEADER" \
		-DCMAKE_TOOLCHAIN_FILE="$(VCPKG_INSTALLATION_ROOT)/scripts/buildsystems/vcpkg.cmake" \
		-DVCPKG_TARGET_TRIPLET=x64-linux-release && \
	$(MAKE) -C build && \
	cp bin/go_probe_ebpf output/go_probe_ebpf_4.16

	cd golang-ebpf && \
	$(MAKE) -C ebpf clean && \
	PKG_CONFIG_PATH=/tmp/output/lib/pkgconfig $(MAKE) -C ebpf \
		V=1 \
		HOSTCC=$(CC) \
		EXTRA_LDFLAGS="-static-pie" \
		EXTRA_CFLAGS="-fPIC -L/tmp/output/lib -I/tmp/output/include -D__always_inline=__inline__" \
		BPF_CFLAGS="-D__x86_64__ -DENABLE_HTTP" && \
	PKG_CONFIG_PATH="/tmp/output/lib/pkgconfig:$$(pwd)/ebpf/.output/libbpf/lib64/pkgconfig" cmake -B build \
		-DCMAKE_BUILD_TYPE=Release \
		-DSTATIC_BUILD=ON \
		-DZLIB_ROOT=/tmp/output \
		-DCMAKE_CXX_FLAGS="-DENABLE_HTTP" \
		-DCMAKE_TOOLCHAIN_FILE="$(VCPKG_INSTALLATION_ROOT)/scripts/buildsystems/vcpkg.cmake" \
		-DVCPKG_TARGET_TRIPLET=x64-linux-release && \
	$(MAKE) -C build && \
	cp bin/go_probe_ebpf output/go_probe_ebpf_5.2

	cd golang-ebpf && \
	$(MAKE) -C ebpf clean && \
	PKG_CONFIG_PATH=/tmp/output/lib/pkgconfig $(MAKE) -C ebpf \
		V=1 \
		HOSTCC=$(CC) \
		EXTRA_LDFLAGS="-static-pie" \
		EXTRA_CFLAGS="-fPIC -L/tmp/output/lib -I/tmp/output/include -D__always_inline=__inline__" \
		BPF_CFLAGS="-D__x86_64__ -DENABLE_HTTP -DUSE_RING_BUFFER" && \
	PKG_CONFIG_PATH="/tmp/output/lib/pkgconfig:$$(pwd)/ebpf/.output/libbpf/lib64/pkgconfig" cmake -B build \
		-DCMAKE_BUILD_TYPE=Release \
		-DSTATIC_BUILD=ON \
		-DZLIB_ROOT=/tmp/output \
		-DCMAKE_CXX_FLAGS="-DENABLE_HTTP -DUSE_RING_BUFFER" \
		-DCMAKE_TOOLCHAIN_FILE="$(VCPKG_INSTALLATION_ROOT)/scripts/buildsystems/vcpkg.cmake" \
		-DVCPKG_TARGET_TRIPLET=x64-linux-release && \
	$(MAKE) -C build && \
	cp bin/go_probe_ebpf output/go_probe_ebpf_5.8
else
	cd golang-ebpf && \
	$(MAKE) -C ebpf clean && \
	$(MAKE) -C ebpf \
		V=1 \
		HOSTCC=$(CC) \
		BPF_CFLAGS="-D__x86_64__" && \
	PKG_CONFIG_PATH=$$(pwd)/ebpf/.output/libbpf/lib64/pkgconfig cmake -B build \
		-DCMAKE_BUILD_TYPE=Release \
		-DCMAKE_TOOLCHAIN_FILE="$(VCPKG_INSTALLATION_ROOT)/scripts/buildsystems/vcpkg.cmake" \
		-DVCPKG_TARGET_TRIPLET=x64-linux-release && \
	$(MAKE) -C build && \
	cp bin/go_probe_ebpf output/go_probe_ebpf_4.14

	cd golang-ebpf && \
	$(MAKE) -C ebpf clean && \
	$(MAKE) -C ebpf \
		V=1 \
		HOSTCC=$(CC) \
		BPF_CFLAGS="-D__x86_64__ -DENABLE_HTTP -DDISABLE_HTTP_HEADER" && \
	PKG_CONFIG_PATH=$$(pwd)/ebpf/.output/libbpf/lib64/pkgconfig cmake -B build \
		-DCMAKE_BUILD_TYPE=Release \
		-DCMAKE_CXX_FLAGS="-DENABLE_HTTP -DDISABLE_HTTP_HEADER" \
		-DCMAKE_TOOLCHAIN_FILE="$(VCPKG_INSTALLATION_ROOT)/scripts/buildsystems/vcpkg.cmake" \
		-DVCPKG_TARGET_TRIPLET=x64-linux-release && \
	$(MAKE) -C build && \
	cp bin/go_probe_ebpf output/go_probe_ebpf_4.16

	cd golang-ebpf && \
	$(MAKE) -C ebpf clean && \
	$(MAKE) -C ebpf \
		V=1 \
		HOSTCC=$(CC) \
		BPF_CFLAGS="-D__x86_64__ -DENABLE_HTTP" && \
	PKG_CONFIG_PATH=$$(pwd)/ebpf/.output/libbpf/lib64/pkgconfig cmake -B build \
		-DCMAKE_BUILD_TYPE=Release \
		-DCMAKE_CXX_FLAGS="-DENABLE_HTTP" \
		-DCMAKE_TOOLCHAIN_FILE="$(VCPKG_INSTALLATION_ROOT)/scripts/buildsystems/vcpkg.cmake" \
		-DVCPKG_TARGET_TRIPLET=x64-linux-release && \
	$(MAKE) -C build && \
	cp bin/go_probe_ebpf output/go_probe_ebpf_5.2

	cd golang-ebpf && \
	$(MAKE) -C ebpf clean && \
	$(MAKE) -C ebpf \
		V=1 \
		HOSTCC=$(CC) \
		BPF_CFLAGS="-D__x86_64__ -DENABLE_HTTP -DUSE_RING_BUFFER" && \
	PKG_CONFIG_PATH=$$(pwd)/ebpf/.output/libbpf/lib64/pkgconfig cmake -B build \
		-DCMAKE_BUILD_TYPE=Release \
		-DCMAKE_CXX_FLAGS="-DENABLE_HTTP -DUSE_RING_BUFFER" \
		-DCMAKE_TOOLCHAIN_FILE="$(VCPKG_INSTALLATION_ROOT)/scripts/buildsystems/vcpkg.cmake" \
		-DVCPKG_TARGET_TRIPLET=x64-linux-release && \
	$(MAKE) -C build && \
	cp bin/go_probe_ebpf output/go_probe_ebpf_5.8
endif


node-probe:
	cd node && \
	npm install && \
	npm run build


php-probe:
ifeq ($(STATIC), TRUE)
	cd php && \
	mkdir -p output build && \
	for header in ${PHP_HEADERS}/*; \
		do \
			[ -d include ] && rm -rf include; \
			cp -r $$header include && \
			CC=$(GNU_CC) CXX=$(GNU_CXX) cmake -B build \
				-DCMAKE_BUILD_TYPE=Release \
				-DSTATIC_BUILD=ON \
				-DPHP_EXTENSIONS_INCLUDE_DIR=$$(pwd)/include \
				-DCMAKE_TOOLCHAIN_FILE="$(VCPKG_INSTALLATION_ROOT)/scripts/buildsystems/vcpkg.cmake" \
				-DVCPKG_TARGET_TRIPLET=x64-linux-release && \
			$(MAKE) -C build && \
			cp lib/libphp_probe.so output/libphp_probe-$$(basename $$header).so; \
		done
else
	cd php && \
	mkdir -p output build && \
	for header in ${PHP_HEADERS}/*; \
		do \
			[ -d include ] && rm -rf include; \
			cp -r $$header include && \
			cmake -B build \
				-DCMAKE_BUILD_TYPE=Release \
				-DSTATIC_BUILD=ON \
				-DPHP_EXTENSIONS_INCLUDE_DIR=$$(pwd)/include \
				-DCMAKE_TOOLCHAIN_FILE="$(VCPKG_INSTALLATION_ROOT)/scripts/buildsystems/vcpkg.cmake" \
				-DVCPKG_TARGET_TRIPLET=x64-linux-release && \
			$(MAKE) -C build && \
			cp lib/libphp_probe.so output/libphp_probe-$$(basename $$header).so; \
		done
endif


$(OUTPUT): set-version agent-plugin nsenter pangolin jattach JVMAgent JVMProbe python-probe python-loader go-probe go-probe-ebpf node-probe php-probe rasp-server librasp NSMount
	mkdir -p $(OUTPUT) $(LIB_OUTPUT) $(LIB_OUTPUT)/golang $(LIB_OUTPUT)/java $(LIB_OUTPUT)/node $(LIB_OUTPUT)/php $(LIB_OUTPUT)/python

	cp plugin/settings.toml $(OUTPUT)/settings.toml

ifeq ($(STATIC), TRUE)
	cp librasp/target/x86_64-unknown-linux-musl/release/elkeid_rasp $(OUTPUT)/elkeid_rasp
	cp plugin/target/x86_64-unknown-linux-musl/release/elkeid_rasp_monitor $(OUTPUT)/rasp
	cp rasp_server/target/x86_64-unknown-linux-musl/release/rasp_server $(LIB_OUTPUT)/rasp_server
	cp util-linux/nsenter.static $(OUTPUT)/nsenter
else
	cp librasp/target/release/elkeid_rasp $(OUTPUT)/elkeid_rasp
	cp plugin/target/release/elkeid_rasp_monitor $(OUTPUT)/rasp
	cp rasp_server/target/release/rasp_server $(LIB_OUTPUT)/rasp_server
	cp util-linux/nsenter $(OUTPUT)/nsenter
endif

	cp NSMount/bin/NSMount $(OUTPUT)/NSMount
	cp pangolin/bin/pangolin $(LIB_OUTPUT)/pangolin

	cp jvm/JVMAgent/output/SmithAgent.jar 
	cp jvm/JVMProbe/output/SmithProbe.jar $(LIB_OUTPUT)/java/SmithProbe.jar
	cp jvm/jattach/build/jattach $(LIB_OUTPUT)/java/jattach

	cp python/python-loader/bin/python_loader $(LIB_OUTPUT)/python
	cp python/python-probe/dist/rasp-*.whl $(LIB_OUTPUT)/python && cd $(LIB_OUTPUT)/python/ && unzip -o rasp-*.whl

	cp golang/bin/go_probe $(LIB_OUTPUT)/golang/go_probe
	cp golang/bin/go_loader $(LIB_OUTPUT)/golang/go_loader
	cp golang-ebpf/output/* $(LIB_OUTPUT)/golang

	cp node/output/*.js $(LIB_OUTPUT)/node
	cp node/scripts/*.js $(LIB_OUTPUT)/node
	cp php/output/* $(LIB_OUTPUT)/php


define split_debug
	objcopy --only-keep-debug $(1) $(DEBUG_SYMBOLS)/$$(basename $(1)).debug
	strip --strip-debug --strip-unneeded $(1)
	objcopy --add-gnu-debuglink=$(DEBUG_SYMBOLS)/$$(basename $(1)).debug $(1)
endef


$(DEBUG_SYMBOLS): | $(OUTPUT)
	mkdir -p $@

	$(call split_debug, $(OUTPUT)/rasp)
	$(call split_debug, $(OUTPUT)/elkeid_rasp)
	$(call split_debug, $(OUTPUT)/nsenter)
	$(call split_debug, $(LIB_OUTPUT)/pangolin)
	$(call split_debug, $(LIB_OUTPUT)/rasp_server)
	$(call split_debug, $(LIB_OUTPUT)/java/jattach)
	$(call split_debug, $(LIB_OUTPUT)/python/python_loader)
	$(call split_debug, $(LIB_OUTPUT)/python/rasp/probe.so)
	$(call split_debug, $(LIB_OUTPUT)/python/rasp/probe.abi3.so)
	$(foreach file, $(wildcard $(LIB_OUTPUT)/golang/*), $(call split_debug, $(file));)
	$(foreach file, $(wildcard $(LIB_OUTPUT)/php/*), $(call split_debug, $(file));)
