#ifndef ZUA_ZUA_TYPE_H
#define ZUA_ZUA_TYPE_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "hashmap.h"
#include <assert.h>
#include <inttypes.h>

typedef union  _zua_value         zua_value;
typedef struct _zua_struct        zval;
typedef struct hashmap_s          zua_hashmap;
typedef struct hashmap_element_s  zua_hashmap_ele;
typedef struct hashmap_s          zua_array;
typedef struct hashmap_s          zua_object;
#define zua_free                  free
#define zua_malloc                malloc
#define ZUA_API
typedef int bool;
#define TRUE    1
#define FALSE   0

typedef struct _zua_string {
    uint32_t len;
    char     v[1];
} zua_string;

#define ZUA_STR(s)   (s), (sizeof(s)-1)
#define ZUA_STR2(s)   (s), (sizeof(s)-1), (s), (sizeof(s)-1)
#define ZSTR_LEN(s)  (s)->len
#define ZSTR_VAL(s)  (s)->v
#define ZSTRL(s) ZSTR_VAL(s), ZSTR_LEN(s)

static inline uint32_t zua_string_size(uint32_t length) {
    return sizeof(zua_string) - sizeof(char) + sizeof(char) * length;
}

static inline void zua_string_free(zua_string *r) {
    if (r != NULL) zua_free(r);
}

static inline void *zua_hashmap_init() {
    return zua_malloc(sizeof(zua_hashmap));
}

zua_string *zua_string_create(const char *str, uint32_t str_len);
zua_string *zua_string_append(zua_string *r, const char *str, uint32_t str_len);
zua_string *zua_string_addslashes(zua_string *r);

enum {
    IS_NULL = 1 << 5,
    IS_FALSE,
    IS_TRUE,
    IS_LONG,
    IS_DOUBLE,
    IS_STRING,
    IS_ARRAY,
    IS_OBJECT,
    IS_NAN,                 /* JSON5 NaN      */
    IS_INFINITY,            /* JSON  Infinity */
    IS_NEGATIVE_INFINITY,   /* JSON -Infinity */
};

union _zua_value {
    long        lval;
    double      dval;
    zua_string  *str;
    zua_array   *arr;
    zua_object  *obj;
    struct {
        uint32_t w1;
        uint32_t w2;
    } ww;
};

struct _zua_struct {
    zua_value value;
    union {
        uint32_t type;
    } u1;
    union {
       uint32_t lineno;
       uint32_t errcode; /* Used for JSON parse error */
    } u2;
};

#define Z_LVAL(z)    (z).value.lval
#define Z_LVAL_P(z)  Z_LVAL(*(z))

#define Z_DVAL(z)     (z).value.dval
#define Z_DVAL_P(z)   Z_DVAL(*(z))

#define Z_STR(z)     (z).value.str
#define Z_STR_P(z)   Z_STR(*(z))

#define Z_ARR(z)     (z).value.arr
#define Z_ARR_P(z)   Z_ARR(*(z))

#define Z_OBJ(z)     (z).value.obj
#define Z_OBJ_P(z)   Z_OBJ(*(z))

#define Z_TYPE(z)    (z).u1.type
#define Z_TYPE_P(z)  Z_TYPE(*(z))

#define Z_LINENO(z)    (z).u2.lineno
#define Z_LINENO_P(z)  Z_LINENO(*(z))

#define ZVAL_LONG(z, l) {                  \
       zval *_z = (z);                     \
       Z_LVAL_P(_z) = l;                   \
       Z_TYPE_P(_z) = IS_LONG;             \
    }

#define ZVAL_NULL(z) {                     \
       Z_TYPE_P(z) = IS_NULL;              \
    }

#define ZVAL_NAN(z) {                     \
       Z_TYPE_P(z) = IS_NAN;              \
    }

#define ZVAL_INFINITY(z) {                \
       Z_TYPE_P(z) = IS_INFINITY;         \
    }

#define ZVAL_NINFINITY(z) {                \
       Z_TYPE_P(z) = IS_NEGATIVE_INFINITY; \
    }

#define ZVAL_NULL(z) {                     \
       Z_TYPE_P(z) = IS_NULL;              \
    }

#define ZVAL_TRUE(z) {                     \
       Z_TYPE_P(z) = IS_TRUE;              \
    }

#define ZVAL_FALSE(z) {                    \
       Z_TYPE_P(z) = IS_FALSE;             \
    }

#define ZVAL_DOUBLE(z, d) {                \
       zval *_z = (z);                     \
       Z_DVAL_P(_z) = d;                   \
       Z_TYPE_P(_z) = IS_DOUBLE;           \
    }

#define ZVAL_STRINGL(z, s, l) {            \
   zval *_z = (z);                         \
   Z_STR_P(_z) = zua_string_create(s, l);  \
   Z_TYPE_P(_z) = IS_STRING;               \
    }

#define ZVAL_STRING(z, s) {               \
       ZVAL_STRINGL(z, s, strlen(s));     \
    }

#define ZUA_COPY_VALUE(z, v)               \
    do {                                   \
        zval *z1 = (z);                    \
        const zval *z2 = (v);              \
        Z_TYPE_P(z1) = Z_TYPE_P(z2);       \
        Z_LINENO_P(z1) = Z_LINENO_P(z2);   \
        z1->value.ww.w1 = z2->value.ww.w1; \
        z1->value.ww.w2 = z2->value.ww.w2; \
    } while(0)

#define HASHMAP_DEFAULT_SIZE 256

ZUA_API zval *zval_init();
ZUA_API void object_init(zval *v);
ZUA_API void array_init(zval *v);
ZUA_API void zval_free(zval *v);
void zval_free_nogc(zval *v);


ZUA_API void zua_hash_str_add_or_update(zval *h, const char *key, uint32_t key_len, zval *value);
ZUA_API void zua_hash_index_add(zval *h, zval *value);

#define MAX_STRING_KEY 256

#define ZUA_HASHMAP_FOREACH_ELE(s, i, ele)\
do  {                                    \
for (i = 0; i < s->table_size; i++) {    \
ele = &s->data[i];                       \
if (ele->in_use) {


#define ZUA_HASHMAP_FOREACH_END()  \
}}                                \
} while(0)

ZUA_API zua_string *json_encode(zval *v);
ZUA_API zua_string *json_encode_pretty(zval *v);

ZUA_API zval *json_decode(const char *str, uint32_t str_len);

ZUA_API zval *zua_get_value(zval *v, const char *key, uint32_t key_len);
ZUA_API zval *zua_get_value_by_index(zval *v, uint32_t index);
ZUA_API zval *zua_get_value_by_path(zval *r, const char *str, uint32_t str_len);
ZUA_API bool  zua_in_array(zval *r, zval *value);

ZUA_API zua_string *zua_file_gets(const char *file_name);

#endif
