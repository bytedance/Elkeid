#ifndef PHP_PROBE_LIBRARY_H
#define PHP_PROBE_LIBRARY_H

#include "client/smith_message.h"
#include <Zend/zend_API.h>
#include <Zend/zend_modules.h>
#include <php_version.h>

extern zend_module_entry php_probe_module_entry;

ZEND_BEGIN_MODULE_GLOBALS(php_probe)
    SmithRequest request{};
ZEND_END_MODULE_GLOBALS(php_probe)

ZEND_EXTERN_MODULE_GLOBALS(php_probe)

#if PHP_MAJOR_VERSION > 5
#define PHP_PROBE_G(v) ZEND_MODULE_GLOBALS_ACCESSOR(php_probe, v)
#else
#ifdef ZTS
#define PHP_PROBE_G(v) TSRMG(php_probe_globals_id, zend_php_probe_globals *, v)
#else
#define PHP_PROBE_G(v) (php_probe_globals.v)
#endif
#endif

#endif //PHP_PROBE_LIBRARY_H
