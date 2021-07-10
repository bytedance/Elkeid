# node-probe: node RASP

## intro
node.js runtime application self-protection, by using node inspector.

## example run

```shell
# in shell 1
$ socat UNIX-LISTEN:"/var/run/smith_agent.sock" -
# in shell 2
$ node test.js
# in shell 3
$ node injector.js $(pidof node) "require('./smith')"
```
