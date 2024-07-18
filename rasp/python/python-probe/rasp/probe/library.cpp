#include "library.h"
#include "client/smith_probe.h"
#include <csignal>
#include <execinfo.h>
#include <sys/prctl.h>
#include <sys/eventfd.h>
#include <zero/log.h>
#include <re.h>

int pid = 0;

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

    self->count = std::min(ARG_COUNT, (int) PyList_Size(argList));

    for (int i = 0; i < self->count; i++) {
#if PY_MAJOR_VERSION >= 3
        strncpy(self->args[i], PyUnicode_AsUTF8(PyList_GetItem(argList, i)), ARG_LENGTH - 1);
#else
        strncpy(self->args[i], PyString_AS_STRING(PyList_GetItem(argList, i)), ARG_LENGTH - 1);
#endif
    }

    PyObject *key, *value;

    for (Py_ssize_t pos = 0, index = 0; PyDict_Next(kwargsDict, &pos, &key, &value); index++) {
#if PY_MAJOR_VERSION >= 3
        strncpy(self->kwargs[index][0], PyUnicode_AsUTF8(key), ARG_LENGTH - 1);
        strncpy(self->kwargs[index][1], PyUnicode_AsUTF8(value), ARG_LENGTH - 1);
#else
        strncpy(self->kwargs[index][0], PyString_AS_STRING(key), ARG_LENGTH - 1);
        strncpy(self->kwargs[index][1], PyString_AS_STRING(value), ARG_LENGTH - 1);
#endif
    }

    for (int i = 0; i < std::min(FRAME_COUNT, (int) PyList_Size(stackTraceList)); i++) {
#if PY_MAJOR_VERSION >= 3
        strncpy(self->stackTrace[i], PyUnicode_AsUTF8(PyList_GetItem(stackTraceList, i)), FRAME_LENGTH - 1);
#else
        strncpy(self->stackTrace[i], PyString_AS_STRING(PyList_GetItem(stackTraceList, i)), FRAME_LENGTH - 1);
#endif
    }

    return 0;
}

PyObject *send(PyObject *self, PyObject *args) {
    PyTrace *pyTrace;

    if (!PyArg_ParseTuple(args, "O", &pyTrace))
        return nullptr;

    std::optional<size_t> index = gProbe->buffer.reserve();

    if (!index) {
        gProbe->discard_post++;
        Py_RETURN_NONE;
    }

    gProbe->buffer[*index] = *(Trace *) pyTrace;
    gProbe->buffer.commit(*index);

    if (gProbe->buffer.size() < TRACE_BUFFER_SIZE / 2)
        Py_RETURN_NONE;

    bool expected = true;

    if (!gProbe->waiting.compare_exchange_strong(expected, false))
        Py_RETURN_NONE;

    eventfd_t value = 1;
    eventfd_write(gProbe->efd, value);

    Py_RETURN_NONE;
}

PyObject *block(PyObject *self, PyObject *args) {
    PyTrace *pyTrace;

    if (!PyArg_ParseTuple(args, "O", &pyTrace))
        return nullptr;

    z_rwlock_t *lock = gProbe->locks[pyTrace->classID] + pyTrace->methodID;
    z_rwlock_read_lock(lock);

    auto &[size, policies] = gProbe->policies[pyTrace->classID][pyTrace->methodID];

    if (std::none_of(policies, policies + size, [&](const Policy *policy) {
        if (policy->ruleCount > 0 && std::none_of(
                policy->rules,
                policy->rules + policy->ruleCount,
                [&](const auto &rule) {
                    if (rule.first >= pyTrace->count)
                        return false;

                    int length = 0;

                    return re_match(rule.second, pyTrace->args[rule.first], &length) != -1;
                }))
            return false;

        if (policy->KeywordCount == 0) {
            pyTrace->blocked = true;
            strncpy(pyTrace->policyID, policy->policyID, sizeof(Trace::policyID) - 1);
            return true;
        }

        auto pred = [&](const auto &keyword) {
            return std::any_of(pyTrace->stackTrace, pyTrace->stackTrace + FRAME_COUNT, [=](const auto &frame) {
                if (!frame)
                    return false;

                int length = 0;

                return re_match(keyword, frame, &length) != -1;
            });
        };

        const auto &[logicalOperator, keywords] = policy->stackFrame;

        if (logicalOperator == OR && std::any_of(keywords, keywords + policy->KeywordCount, pred)) {
            pyTrace->blocked = true;
            strncpy(pyTrace->policyID, policy->policyID, sizeof(Trace::policyID) - 1);
            return true;
        }

        if (logicalOperator == AND && std::all_of(keywords, keywords + policy->KeywordCount, pred)) {
            pyTrace->blocked = true;
            strncpy(pyTrace->policyID, policy->policyID, sizeof(Trace::policyID) - 1);
            return true;
        }

        return false;
    })) {
        z_rwlock_read_unlock(lock);
        Py_RETURN_FALSE;
    }

    z_rwlock_read_unlock(lock);
    Py_RETURN_TRUE;
}

PyObject *surplus(PyObject *self, PyObject *args) {
    int classID;
    int methodID;

    if (!PyArg_ParseTuple(args, "ii", &classID, &methodID))
        return nullptr;

    std::atomic<int> &quota = gProbe->quotas[classID][methodID];
    int n = quota;

    do {
        if (n <= 0) {
            gProbe->discard_surplus++;
            Py_RETURN_FALSE;
        }
    } while (!quota.compare_exchange_weak(n, n - 1));

    Py_RETURN_TRUE;
}

constexpr PyMethodDef MODULE_METHODS[] = {
        {"send",    send,    METH_VARARGS, nullptr},
        {"block",   block,   METH_VARARGS, nullptr},
        {"surplus", surplus, METH_VARARGS, nullptr},
        {nullptr,   nullptr, 0,            nullptr}
};

void send_exception_info(int sig) {
    void *buffer[100];
    struct ExceptionInfo exceptioninfo;
    int nptrs = backtrace(buffer, 100);
    char **stackstrings = backtrace_symbols(buffer, nptrs);
    if(!stackstrings)
        return ;

    memset(&exceptioninfo,0,sizeof(struct ExceptionInfo));

    exceptioninfo.signal = sig;
    for (int i = 0; i < std::min(FRAME_COUNT, nptrs); i++) {
        snprintf((char*)&exceptioninfo.stackTrace[i],FRAME_LENGTH,"%s",stackstrings[i]);
    }

    free(stackstrings);

    std::optional<size_t> index = gProbe->info.reserve();

    if (!index)
        return;

    gProbe->info[*index] = exceptioninfo;
    gProbe->info.commit(*index);

    if (gProbe->info.size() < EXCEPTIONINFO_BUFFER_SIZE / 2)
        return;

    bool expected = true;

    if (!gProbe->infowaiting.compare_exchange_strong(expected, false))
        return;

    eventfd_t value = 1;
    eventfd_write(gProbe->infoefd, value);
}

/*
void printinfo(int sig) {
    void *buffer[100];
    int nptrs = backtrace(buffer, 100);
    char **strings = backtrace_symbols(buffer, nptrs);

    printf("Caught signal %d:\n", sig);
    printf("Backtrace:\n");
    for (int i = 0; i < nptrs; i++) {
        printf("%s\n", strings[i]);
    }

    free(strings);
}
*/

void signal_handler(int sig) {
    //printinfo(sig);
    send_exception_info(sig);
    sleep(30);
    exit(0);
}

INIT_FUNCTION(probe) {
    if (!gProbe)
        INIT_RETURN(nullptr);

    signal(SIGTERM, signal_handler);    //  15
    signal(SIGINT, signal_handler);     //  2
    signal(SIGSEGV, signal_handler);    //  11
    signal(SIGFPE, signal_handler);     //  8
    signal(SIGILL, signal_handler);     //  4

    pid = getpid();

    auto nodes = (Policy *) allocShared(sizeof(Policy) * (PREPARED_POLICY_COUNT - 1));

    if (!nodes)
        INIT_RETURN(nullptr);

    for (int i = 0; i < PREPARED_POLICY_COUNT - 1; i++) {
        if (!gProbe->pushNode(nodes + i)) {
            freeShared(nodes);
            INIT_RETURN(nullptr);
        }
    }

    startProbe();

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