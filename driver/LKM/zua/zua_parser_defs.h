#ifndef ZUA_ZUA_PARSER_DEFS_H
#define ZUA_ZUA_PARSER_DEFS_H

#include "zua_scanner.h"

typedef struct _zua_json_parser zua_json_parser;

struct _zua_json_parser {
    zua_json_scanner scanner;
    zval *return_value;
    int depth;
    int max_depth;
};

void zua_json_parser_init(
    zua_json_parser *parser,
    zval *return_value,
    const char *str,
    size_t str_len,
    int options,
    int max_depth);


#endif /* ZUA_ZUA_PARSER_DEFS_H */
