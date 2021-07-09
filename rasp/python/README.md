# python probe

## Intro

* CPython 2/3 Hook/RASP/IAST framework

## Build & Install

* install
```bash
python setup.py install
```

* build & install

```bash
python setup.py sdist bdist_wheel --universal
```

```bash
python -m pip install -I dist/rasp-1.0.0-py2.py3-none-any.whl
```

## Usage

* [static hook](#static-attachdetach)
* [dynamic hook](#dynamic-attachdetach)
* [with Mongoose-RASP]()
* [with IAST]()

### static attach/detach

1. Inject entry to `site.py`

* !!! DANGER !!!
* READ CODE BEFORE RUN THIS COMMAND

```bash
rasp_static_attach
rasp_static_dettach
```

2. check hook

### dynamic attach/detach

```bash
$ rasp_dyn_attach --IAST
import rasp;rasp.set_var(True, False);rasp.hook()
$ rasp_dyn_attach --IAST --DEBUG
import rasp;rasp.set_var(True, True);rasp.hook()
# sudo socat UNIX-LISTEN:/var/run/smith_agent.sock -
$ rasp_dyn_attach --IAST --DEBUG --CLIENT
import rasp;rasp.set_var(True, True);rasp.setup_client();rasp.hook()
```


### With Elkeid-rasp

```bash
# unix socket server
cd mongoose_rasp
sudo socat UNIX-LISTEN:/var/run/smith_agent.sock -
sudo python/pyinject/bin/pyinject --pangolin=~/mongoose_rasp/pangolin/bin/pangolin -s '"import rasp;rasp.setup_var(debug_switch=True);rasp.setup_client();rasp.hook()"' -p <PID>
```

