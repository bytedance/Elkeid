#ifndef PYTHON_CLIENT_LIBRARY_H
#define PYTHON_CLIENT_LIBRARY_H

#include <Python.h>

#if PY_MAJOR_VERSION >= 3
#define INIT_FUNCTION(m) PyMODINIT_FUNC PyInit_##m()
#define INIT_RETURN(v) return v;
#else
#define INIT_FUNCTION(m) PyMODINIT_FUNC init##m()
#define INIT_RETURN(v) return;
#endif

INIT_FUNCTION(probe) __attribute__((visibility ("default")));

#endif //PYTHON_CLIENT_LIBRARY_H
