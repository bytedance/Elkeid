#include "library.h"
#include "client/smith_probe.h"
#include <csignal>
#include <sys/prctl.h>
#include <zero/log.h>

struct PyTrace : public PyObject, Trace {

};

PyObject *newPyTrace(PyTypeObject *type, PyObject *args, PyObject *kwargs) {
    return type->tp_alloc(type, 0);
}

void deallocPyTrace(PyObject *self) {
    Py_TYPE(self)->tp_free(self);
}

int initPyTrace(PyTrace *self, PyObject *args, PyObject *kwargs) {
    PyObject *argList;
    PyObject *kwargsDict;
    PyObject *stackTraceList;

    if (!PyArg_ParseTuple(args, "iiOOO", &self->classID, &self->methodID, &argList, &kwargsDict, &stackTraceList))
        return -1;

    self->count = std::min(SMITH_ARG_COUNT, (int) PyList_Size(argList));

    for (int i = 0; i < self->count; i++) {
#if PY_MAJOR_VERSION >= 3
        strncpy(self->args[i], PyUnicode_AsUTF8(PyList_GetItem(argList, i)), SMITH_ARG_LENGTH - 1);
#else
        strncpy(self->args[i], PyString_AS_STRING(PyList_GetItem(argList, i)), SMITH_ARG_LENGTH - 1);
#endif
    }

    PyObject *key, *value;

    for (Py_ssize_t pos = 0, index = 0; PyDict_Next(kwargsDict, &pos, &key, &value); index++) {
#if PY_MAJOR_VERSION >= 3
        strncpy(self->kwargs[index][0], PyUnicode_AsUTF8(key), SMITH_ARG_LENGTH - 1);
        strncpy(self->kwargs[index][1], PyUnicode_AsUTF8(value), SMITH_ARG_LENGTH - 1);
#else
        strncpy(self->kwargs[index][0], PyString_AS_STRING(key), SMITH_ARG_LENGTH - 1);
        strncpy(self->kwargs[index][1], PyString_AS_STRING(value), SMITH_ARG_LENGTH - 1);
#endif
    }

    for (int i = 0; i < std::min(SMITH_TRACE_COUNT, (int) PyList_Size(stackTraceList)); i++) {
#if PY_MAJOR_VERSION >= 3
        strncpy(self->stackTrace[i], PyUnicode_AsUTF8(PyList_GetItem(stackTraceList, i)), SMITH_TRACE_LENGTH - 1);
#else
        strncpy(self->stackTrace[i], PyString_AS_STRING(PyList_GetItem(stackTraceList, i)), SMITH_TRACE_LENGTH - 1);
#endif
    }

    return 0;
}

PyObject *send(PyObject *self, PyObject *args) {
    PyTrace *pyTrace;

    if (!PyArg_ParseTuple(args, "O", &pyTrace))
        return nullptr;

    gAPITrace->enqueue(*pyTrace);

    Py_RETURN_NONE;
}

PyObject *block(PyObject *self, PyObject *args) {
    PyTrace *pyTrace;

    if (!PyArg_ParseTuple(args, "O", &pyTrace))
        return nullptr;

    if (!gAPIConfig->block(*pyTrace))
        Py_RETURN_FALSE;

    pyTrace->blocked = true;

    Py_RETURN_TRUE;
}

PyObject *surplus(PyObject *self, PyObject *args) {
    int classID;
    int methodID;

    if (!PyArg_ParseTuple(args, "ii", &classID, &methodID))
        return nullptr;

    if (!gAPIConfig->surplus(classID, methodID))
        Py_RETURN_FALSE;

    Py_RETURN_TRUE;
}

constexpr PyMethodDef MODULE_METHODS[] = {
        {"send",    send,    METH_VARARGS, nullptr},
        {"block",   block,   METH_VARARGS, nullptr},
        {"surplus", surplus, METH_VARARGS, nullptr},
        {nullptr,   nullptr, 0,            nullptr}
};

INIT_FUNCTION(probe) {
    if (!gAPIConfig || !gAPITrace)
        INIT_RETURN(nullptr);

    if (fork() == 0) {
        INIT_FILE_LOG(zero::INFO, "python-probe-addon");

        char name[16] = {};
        snprintf(name, sizeof(name), "probe(%d)", getppid());

        if (prctl(PR_SET_PDEATHSIG, SIGKILL) < 0) {
            LOG_ERROR("set death signal failed");
            exit(-1);
        }

        if (pthread_setname_np(pthread_self(), name) != 0) {
            LOG_ERROR("set process name failed");
            exit(-1);
        }

        gSmithProbe->start();

        exit(0);
    }

    static PyTypeObject traceType = {PyVarObject_HEAD_INIT(nullptr, 0)};

    traceType.tp_name = "probe.Trace";
    traceType.tp_doc = PyDoc_STR("trace objects of probe");
    traceType.tp_basicsize = sizeof(PyTrace);
    traceType.tp_itemsize = 0;
    traceType.tp_flags = Py_TPFLAGS_DEFAULT;
    traceType.tp_new = newPyTrace;
    traceType.tp_init = (initproc) initPyTrace;
    traceType.tp_dealloc = deallocPyTrace;

    if (PyType_Ready(&traceType) < 0)
        INIT_RETURN(nullptr);

#if PY_MAJOR_VERSION >= 3
    static PyModuleDef moduleDef = {
            PyModuleDef_HEAD_INIT,
            "probe",
            nullptr,
            -1,
            (PyMethodDef *) MODULE_METHODS
    };

    PyObject *module = PyModule_Create(&moduleDef);
#else
    PyObject *module = Py_InitModule("probe", (PyMethodDef *) MODULE_METHODS);
#endif

    if (!module)
        INIT_RETURN(nullptr);

    Py_INCREF(&traceType);

    if (PyModule_AddObject(module, "Trace", (PyObject *) &traceType) < 0) {
        Py_DECREF(&traceType);
        Py_DECREF(module);

        INIT_RETURN(nullptr);
    }

    INIT_RETURN(module);
}