# go-probe: golang RASP
## intro
golang runtime application self-protection, by using [pangolin](https://github.com/Hackerl/pangolin).
## installation
```shell
git submodule update --init --recursive
mkdir build
cd build
cmake ..
make
```
## example run
```shell
# in shell 1
$ socat UNIX-LISTEN:"/tmp/smith_agent.sock" -
# in shell 2
$ ./go-program
# in shell 3
$ ./pangolin -c $(pwd)/go_probe -p $(pidof go-program)
```