#ifndef ZUA_ZUA_SCANNER_H
#define ZUA_ZUA_SCANNER_H

#include "zua_type.h"

typedef char zua_json_ctype;

enum {
    ZUA_JSON_SYNTAX_ERROR = 1 << 6,
    ZUA_JSON_BRACKET_MISMATCH,
};

typedef struct _zua_json_scanner {
    zua_json_ctype *cursor;         /* cursor position */
    zua_json_ctype *token;          /* token position */
    zua_json_ctype *limit;          /* the last read character + 1 position */
    zua_json_ctype *marker;         /* marker position for backtracking */
    zua_json_ctype *ctxmarker;      /* marker position for context backtracking */
    zua_json_ctype *str_start;      /* start position of the string */
    zua_json_ctype *pstr;           /* string pointer for escapes conversion */
    zval value;                     /* value */
    int str_esc;                    /* number of extra characters for escaping */
    int state;                      /* condition state */
    int options;                    /* options */
    int errcode;                    /* error type if there is an error */
    int utf8_invalid;               /* whether utf8 is invalid */
    int utf8_invalid_count;         /* number of extra character for invalid utf8 */
} zua_json_scanner;


void zua_json_scanner_init(zua_json_scanner *scanner, const char *str, uint32_t str_len, int options);
int zua_json_scan(zua_json_scanner *s);

#endif /* ZUA_ZUA_SCANNER_H */
