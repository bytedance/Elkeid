# Elkeid RASP


### Introduction

* Analyze the runtime used by the process.
* The following probes are supported for dynamic attach to process:
  * CPython
  * Golang
  * JVM
  * NodeJS
* Compatible with Elkeid stack.


### Install

* build manually: [GUIDE](./INSTALL)
  1. RUST toolchain 1.40+
  2. JDK 11+(for Java probe)
  3. Python + pip + wheel (for python probe)
  4. MUSL toolcahin(download via CDN: [link](https://sf1-cdn-tos.douyinstatic.com/obj/eden-cn/laahweh7uhwbps/x86_64-linux-musl.tar.gz))
  5. make and install

```bash
git submodule update --recursive --init
make build
sudo make install
```

### Run

* for single process inject
```
sudo env RUST_LOG=<loglevel> /etc/elkeid/plugin/RASP/elkeid_rasp -p <pid>
```

* with Elkied Agent (multi target)

> Expected to be released in late July.

### File Structure

```
.
|- jvm              Java probe.
|- python           Python probe.
|- golang           Golang probe.
|- node             NodeJS probe.
|- rasp_server      probe comm server.
|- librasp          runtime inspect, attach interface.
|- pangolin         Linux process injection tool.
```

## License
Elkeid RASP are distributed under the Apache-2.0 license.

