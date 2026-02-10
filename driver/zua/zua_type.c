#include "zua_type.h"
#include "zua_parser_defs.h"
#include "zua_parser.h"

zua_string *zua_string_create(const char *str, uint32_t str_len) {
    zua_string *r = zua_malloc(zua_string_size(str_len));
    bzero(r, zua_string_size(str_len));
    bcopy(str, ZSTR_VAL(r), sizeof(char) * str_len);
    ZSTR_LEN(r) = str_len;
    return r;
}

zua_string *zua_string_append(zua_string *r, const char *str, uint32_t str_len) {
    if (r == NULL) return zua_string_create(str, str_len);
    uint32_t new_str_len = zua_string_size(ZSTR_LEN(r) + str_len);
    zua_string *t = zua_malloc(new_str_len);
    bzero(t, new_str_len);
    bcopy(ZSTR_VAL(r), ZSTR_VAL(t), ZSTR_LEN(r));
    bcopy(str, ZSTR_VAL(t) + ZSTR_LEN(r), sizeof(char) * str_len);
    ZSTR_LEN(t) = ZSTR_LEN(r) + str_len;
    zua_string_free(r);
    return t;
}

zua_string *zua_string_addslashes(zua_string *r) {
    uint32_t i = 0, j = 0;
    zua_string *str = NULL;
    for (; i < ZSTR_LEN(r); i++) {
        if (ZSTR_VAL(r)[i] == '"') {
            if (str == NULL) {
                str = zua_string_create(ZSTR_VAL(r), i - j);
            } else {
                str = zua_string_append(str, ZSTR_VAL(r)+j, i - j);
            }
            str = zua_string_append(str, ZUA_STR("\\\""));
            j = i+1;
        }
    }
    str = zua_string_append(str, ZSTR_VAL(r)+j, i - j);
    return str;
}

ZUA_API zval *zval_init() {
    zval *v1 = zua_malloc(sizeof(zval));
    memset(v1, 0, sizeof(zval));
    return v1;
}

void object_init(zval *v) {
    Z_OBJ_P(v) = zua_hashmap_init();
    assert(0 == hashmap_create(HASHMAP_DEFAULT_SIZE, Z_OBJ_P(v)));
    Z_TYPE_P(v) = IS_OBJECT;
}


void array_init(zval *v) {
    Z_ARR_P(v) = zua_hashmap_init();
    assert(0 == hashmap_create(HASHMAP_DEFAULT_SIZE, Z_ARR_P(v)));
    Z_TYPE_P(v) = IS_ARRAY;
}

int _array_object_free_hashmap(void * const context, zua_hashmap_ele *const ele) {
    zua_free(ele->key);
    zval_free(ele->data);
    return 0;
}

void zval_free_by_type(zval *v, uint32_t gc) {
    switch (Z_TYPE_P(v)) {
        case IS_ARRAY:
        {
            hashmap_iterate_pairs(Z_ARR_P(v), _array_object_free_hashmap, NULL);
            hashmap_destroy(Z_ARR_P(v));
            zua_free(Z_ARR_P(v));
            break;
        }
        case IS_OBJECT:
        {
            hashmap_iterate_pairs(Z_OBJ_P(v), _array_object_free_hashmap, NULL);
            hashmap_destroy(Z_OBJ_P(v));
            zua_free(Z_OBJ_P(v));
            break;
        }
        case IS_STRING:
        {
            zua_free(Z_STR_P(v));
            break;
        }
        case IS_TRUE:
        case IS_FALSE:
        case IS_NULL:
        case IS_NAN:
        case IS_NEGATIVE_INFINITY:
        case IS_INFINITY:
            break;
    }
    if (gc) zua_free(v);
}

void zval_free(zval *v) {
    zval_free_by_type(v, 1);
}

void zval_free_nogc(zval *v) {
    zval_free_by_type(v, 0);
}

ZUA_API void zua_hash_str_add_or_update(zval *h, const char *key, uint32_t key_len, zval *v2) {
    if ( h == NULL || Z_ARR_P(h) == NULL || Z_OBJ_P(h) == NULL) return ;
    if ( Z_TYPE_P(h) != IS_OBJECT ) return ;
    
    zval *v1 = NULL;
    char *k = zua_malloc(sizeof(char) * key_len);
    bzero(k, sizeof(char) * key_len);
    memcpy(k, key, sizeof(char) * key_len);
    
    v1 = zua_malloc(sizeof(zval));
    ZUA_COPY_VALUE(v1, v2);
    
    switch (Z_TYPE_P(h)) {
        case IS_ARRAY:
        {
            zval *v = hashmap_get(Z_ARR_P(h), k, key_len);
            if (v != HASHMAP_NULL) {
                zval_free(v);
            }
            hashmap_put(Z_ARR_P(h), k, key_len, v1);
            break;
        }
        case IS_OBJECT:
        {
            zval *v = hashmap_get(Z_OBJ_P(h), k, key_len);
            if (v != HASHMAP_NULL) {
                zval_free(v);
            }
            hashmap_put(Z_OBJ_P(h), k, key_len, v1);
            break;
        }
    }
}

ZUA_API void zua_hash_index_add(zval *h, zval *value) {
    if ( h == NULL || Z_ARR_P(h) == NULL || Z_OBJ_P(h) == NULL) return ;
    if ( Z_TYPE_P(h) != IS_ARRAY ) return ;
    
    char *keyBuf = zua_malloc(sizeof(char) * MAX_STRING_KEY);
    bzero(keyBuf, sizeof(char) * MAX_STRING_KEY);
    sprintf(keyBuf, "%d", hashmap_num_entries(Z_ARR_P(h)));
    
    zval *v1 = zua_malloc(sizeof(zval));
    ZUA_COPY_VALUE(v1, value);
    
    hashmap_put(Z_ARR_P(h), keyBuf, strlen(keyBuf), v1);
}

ZUA_API zval *json_decode(const char *str, uint32_t str_len) {
    zval *val = zua_malloc(sizeof(zval));
    zua_json_parser parser;
    zua_json_parser_init(&parser, val, str, str_len, 0, 0);

    zua_yyparse(&parser);
    val->u2.errcode = parser.scanner.errcode;
    return val;
}

ZUA_API zval *zua_get_value(zval *v, const char *key, uint32_t key_len) {
    zua_hashmap *map = NULL;
    if (Z_TYPE_P(v) == IS_OBJECT) {
        map = Z_OBJ_P(v);
    } else if (Z_TYPE_P(v) == IS_ARRAY) {
        map = Z_ARR_P(v);
    } else {
        return NULL;
    }
    return hashmap_get(map, key, key_len);
}

ZUA_API zval *zua_get_value_by_index(zval *v, uint32_t index) {
    zval *ret = NULL;
    char keyBuf[MAX_STRING_KEY];
    if (Z_TYPE_P(v) == IS_ARRAY) {
        bzero(keyBuf, sizeof(char) * MAX_STRING_KEY);
        sprintf(keyBuf, "%d", index);
        ret = hashmap_get(Z_ARR_P(v), keyBuf, strlen(keyBuf));
    }
    return ret;
}

ZUA_API zua_string *json_encode(zval *v) {
    if (Z_TYPE_P(v) == 0) return NULL;

    char str[MAX_STRING_KEY];

    switch(Z_TYPE_P(v)) {
        case IS_LONG:
        {
            memset(str, 0, sizeof(str));
            sprintf(str, "%ld", Z_LVAL_P(v));
            return zua_string_create(str, strlen(str));
        }
        case IS_TRUE:
        {
            memset(str, 0, sizeof(str));
            sprintf(str, "true");
            return zua_string_create(str, strlen(str));
        }
        case IS_FALSE:
        {
            memset(str, 0, sizeof(str));
            sprintf(str, "false");
            return zua_string_create(str, strlen(str));
        }
        case IS_NULL:
        {
            memset(str, 0, sizeof(str));
            sprintf(str, "null");
            return zua_string_create(str, strlen(str));
        }
        case IS_NAN:
        {
            memset(str, 0, sizeof(str));
            sprintf(str, "NaN");
            return zua_string_create(str, strlen(str));
        }
        case IS_INFINITY:
        {
            memset(str, 0, sizeof(str));
            sprintf(str, "Infinity");
            return zua_string_create(str, strlen(str));
        }
        case IS_NEGATIVE_INFINITY:
        {
            memset(str, 0, sizeof(str));
            sprintf(str, "-Infinity");
            return zua_string_create(str, strlen(str));
        }
        case IS_STRING:
        {
            return zua_string_create(ZSTRL(Z_STR_P(v)));
        }
        case IS_DOUBLE:
        {
            memset(str, 0, sizeof(str));
            sprintf(str, "%f", Z_DVAL_P(v));
            return zua_string_create(str, strlen(str));
        }
    }

    zua_string *r = zua_string_create(Z_TYPE_P(v) == IS_ARRAY ? "[" : "{", 1);
    zua_hashmap *map = NULL;
    if (Z_TYPE_P(v) == IS_ARRAY) {
        map = Z_ARR_P(v);
    } else {
        map = Z_OBJ_P(v);
    }
    zua_hashmap_ele *e = NULL;
    zua_string *t = NULL;
    zua_string *s = NULL;
    unsigned int i;
    
    ZUA_HASHMAP_FOREACH_ELE(map, i, e) {
        zval *val = e->data;
        if (Z_TYPE_P(v) == IS_OBJECT) {
            r = zua_string_append( r, ZUA_STR("\"") );
            t = zua_string_create(e->key, e->key_len);
            s = zua_string_addslashes(t);
            r = zua_string_append( r, ZSTR_VAL(s), ZSTR_LEN(s) );
            zua_string_free(s);
            zua_string_free(t);
            r = zua_string_append( r, ZUA_STR("\":") );
        }
        switch(Z_TYPE_P(val)) {
            case IS_STRING:
                r = zua_string_append(r, ZUA_STR("\"") );
                s = zua_string_addslashes(Z_STR_P(val));
                r = zua_string_append(r, ZSTRL(s) );
                zua_string_free(s);
                r = zua_string_append(r, ZUA_STR("\"") );
                break;
            case IS_DOUBLE:
                memset(str, 0, sizeof(str));
                sprintf(str, "%f", Z_DVAL_P(val));
                r = zua_string_append(r, str, strlen(str));
                break;
            case IS_FALSE:
                r = zua_string_append(r, ZUA_STR("false") );
                break;
            case IS_TRUE:
                r = zua_string_append(r, ZUA_STR("true") );
                break;
            case IS_NULL:
                r = zua_string_append(r, ZUA_STR("null") );
                break;
            case IS_NAN:
                r = zua_string_append(r, ZUA_STR("NaN") );
                break;
            case IS_INFINITY:
                r = zua_string_append(r, ZUA_STR("Infinity") );
                break;
            case IS_NEGATIVE_INFINITY:
                r = zua_string_append(r, ZUA_STR("-Infinity") );
                break;
            case IS_LONG:
                memset(str, 0, sizeof(str));
                sprintf(str, "%ld", Z_LVAL_P(val));
                r = zua_string_append(r, str, strlen(str));
                break;
            case IS_OBJECT:
            case IS_ARRAY:
                t = json_encode(val);
                r = zua_string_append(r, ZSTRL(t));
                zua_string_free(t);
                break;
        }
        if ( i < (map->table_size - 1) ) r = zua_string_append(r, ZUA_STR(","));
    } ZUA_HASHMAP_FOREACH_END();
    if (ZSTR_VAL(r)[ZSTR_LEN(r) - 1] == ',') ZSTR_LEN(r)--;
    r = zua_string_append(r, Z_TYPE_P(v) == IS_ARRAY ? "]" : "}", 1);
    return r;
}

static inline zua_string *json_encode_pretty_with_indent(zval *v, const char *indent_str, uint32_t indent_str_len, const char *raw_indent_str, uint32_t initial_indent_str_len) {
    if (Z_TYPE_P(v) == 0) return NULL;
    
    char str[MAX_STRING_KEY];
    
    switch(Z_TYPE_P(v)) {
        case IS_LONG:
        {
            memset(str, 0, sizeof(str));
            sprintf(str, "%ld", Z_LVAL_P(v));
            return zua_string_create(str, strlen(str));
        }
        case IS_TRUE:
        {
            memset(str, 0, sizeof(str));
            sprintf(str, "true");
            return zua_string_create(str, strlen(str));
        }
        case IS_FALSE:
        {
            memset(str, 0, sizeof(str));
            sprintf(str, "false");
            return zua_string_create(str, strlen(str));
        }
        case IS_NULL:
        {
            memset(str, 0, sizeof(str));
            sprintf(str, "null");
            return zua_string_create(str, strlen(str));
        }
        case IS_NAN:
        {
            memset(str, 0, sizeof(str));
            sprintf(str, "NaN");
            return zua_string_create(str, strlen(str));
        }
        case IS_INFINITY:
        {
            memset(str, 0, sizeof(str));
            sprintf(str, "Infinity");
            return zua_string_create(str, strlen(str));
        }
        case IS_NEGATIVE_INFINITY:
        {
            memset(str, 0, sizeof(str));
            sprintf(str, "-Infinity");
            return zua_string_create(str, strlen(str));
        }
        case IS_STRING:
        {
            return zua_string_create(ZSTRL(Z_STR_P(v)));
        }
        case IS_DOUBLE:
        {
            memset(str, 0, sizeof(str));
            sprintf(str, "%f", Z_DVAL_P(v));
            return zua_string_create(str, strlen(str));
        }
    }
    
    uint32_t         i;
    zua_string      *r = NULL;
    zua_string      *t = NULL;
    zua_string      *s = NULL;
    zua_string *indent = NULL;
    zua_hashmap_ele *e = NULL;
    zua_hashmap   *map = NULL;
    if (Z_TYPE_P(v) == IS_ARRAY) {
        map = Z_ARR_P( v );
        r = zua_string_create(ZUA_STR("[\n"));
    } else if (Z_TYPE_P(v) == IS_OBJECT) {
        map = Z_OBJ_P( v );
        r = zua_string_create(ZUA_STR( "{\n"));
    }
    
    indent = zua_string_create(indent_str, indent_str_len);
    
    ZUA_HASHMAP_FOREACH_ELE(map, i, e) {
        zval *val = e->data;
        r = zua_string_append(r, ZSTRL(indent));
        if (Z_TYPE_P(v) == IS_OBJECT) {
            r = zua_string_append( r, ZUA_STR("\"") );
            t = zua_string_create(e->key, e->key_len);
            s = zua_string_addslashes(t);
            r = zua_string_append( r, ZSTRL(s) );
            zua_string_free(t);
            zua_string_free(s);
            r = zua_string_append( r, ZUA_STR("\":") );
        }
        switch(Z_TYPE_P(val)) {
            case IS_STRING:
                r = zua_string_append(r, ZUA_STR("\"") );
                s = zua_string_addslashes(Z_STR_P(val));
                r = zua_string_append(r, ZSTRL(s) );
                zua_string_free(s);
                r = zua_string_append(r, ZUA_STR("\"") );
                break;
            case IS_DOUBLE:
                memset(str, 0, sizeof(str));
                sprintf(str, "%f", Z_DVAL_P(val));
                r = zua_string_append(r, str, strlen(str));
                break;
            case IS_FALSE:
                r = zua_string_append(r, ZUA_STR("false") );
                break;
            case IS_TRUE:
                r = zua_string_append(r, ZUA_STR("true") );
                break;
            case IS_NULL:
                r = zua_string_append(r, ZUA_STR("null") );
                break;
            case IS_NAN:
                r = zua_string_append(r, ZUA_STR("NaN") );
                break;
            case IS_INFINITY:
                r = zua_string_append(r, ZUA_STR("Infinity") );
                break;
            case IS_NEGATIVE_INFINITY:
                r = zua_string_append(r, ZUA_STR("-Infinity") );
                break;
            case IS_LONG:
                memset(str, 0, sizeof(str));
                sprintf(str, "%ld", Z_LVAL_P(val));
                r = zua_string_append(r, str, strlen(str));
                break;
            case IS_OBJECT:
            case IS_ARRAY:
                indent = zua_string_append(indent, raw_indent_str, initial_indent_str_len);
                t = json_encode_pretty_with_indent(val, ZSTRL(indent), raw_indent_str, initial_indent_str_len);
                r = zua_string_append(r, ZSTRL(t));
                ZSTRL(indent) -= initial_indent_str_len;
                zua_string_free(t);
                break;
        }
        if ( i < (map->table_size - 1) ) r = zua_string_append(r, ZUA_STR(",\n"));
    } ZUA_HASHMAP_FOREACH_END();
    
    if (ZSTR_VAL(r)[ZSTR_LEN(r) - 1] == '\n' && ZSTR_VAL(r)[ZSTR_LEN(r) - 2] == ',') ZSTR_LEN(r)-=2;
    
    ZSTRL(indent) -= initial_indent_str_len;
    r = zua_string_append(r, ZUA_STR("\n"));
    r = zua_string_append(r, ZSTRL(indent));
    
    if (Z_TYPE_P(v) == IS_ARRAY) {
        r = zua_string_append(r, ZUA_STR("]"));
    } else if (Z_TYPE_P(v) == IS_OBJECT) {
        r = zua_string_append(r, ZUA_STR("}"));
    }
    
    zua_string_free(indent);
    return r;
}

ZUA_API zua_string *json_encode_pretty(zval *v) {
    return json_encode_pretty_with_indent(v, ZUA_STR2("     "));
}

ZUA_API zval *zua_get_value_by_path(zval *r, const char *str, uint32_t str_len) {
    uint32_t i = 0, j = 0;
    
    zval *t = NULL;
    zua_hashmap *map = NULL;
    
    if (Z_TYPE_P(r) == IS_ARRAY) {
        map = Z_ARR_P(r);
    } else if (Z_TYPE_P(r) == IS_OBJECT) {
        map = Z_OBJ_P(r);
    }
    
    for (; i < str_len; i++) {
        if (str[i] == '.') {
            t = hashmap_get(map, str + j, i - j);
            if (Z_TYPE_P(t) == IS_ARRAY) {
                map = Z_ARR_P(t);
            } else if (Z_TYPE_P(t) == IS_OBJECT) {
                map = Z_OBJ_P(t);
            } else {
                return t;
            }
            j = i + 1;
        }
    }
    
    return hashmap_get(map, str + j, i - j);
}

ZUA_API bool zua_in_array(zval *r, zval *value) {
    zua_hashmap *map = NULL;
    if (Z_TYPE_P(r) == IS_OBJECT) {
        map = Z_OBJ_P(r);
    } else if (Z_TYPE_P(r) == IS_ARRAY) {
        map = Z_ARR_P(r);
    }
    
    uint32_t i;
    zval *v = NULL;
    zua_hashmap_ele *e;
    ZUA_HASHMAP_FOREACH_ELE(map, i, e) {
        v = e->data;
        
        switch ( Z_TYPE_P(value) ) {
            case IS_NAN:
            {
                if (Z_TYPE_P(v) == IS_NAN) return TRUE;
                break;
            }
            case IS_NEGATIVE_INFINITY:
            {
                if (Z_TYPE_P(v) == IS_NEGATIVE_INFINITY) return TRUE;
                break;
            }
            case IS_INFINITY:
            {
                if (Z_TYPE_P(v) == IS_INFINITY) return TRUE;
                break;
            }
            case IS_ARRAY:
            case IS_OBJECT:
            {
                return FALSE;
            }
            case IS_DOUBLE:
            {
                if(Z_TYPE_P(v) == IS_DOUBLE && (Z_DVAL_P(v) - Z_DVAL_P(value) <= 0)) return TRUE;
                break;
            }
            case IS_STRING:
            {
                if(Z_TYPE_P(v) == IS_STRING && ( ZSTR_LEN(Z_STR_P(v)) == ZSTR_LEN(Z_STR_P(value)) ) &&
                (0 == strncasecmp(ZSTR_VAL(Z_STR_P(value)), ZSTR_VAL(Z_STR_P(v)), ZSTR_LEN(Z_STR_P(v))))) return TRUE;
                break;
            }
            case IS_NULL:
            {
                if(Z_TYPE_P(v) == IS_NULL) return TRUE;
                break;
            }
            case IS_FALSE:
            {
                if(Z_TYPE_P(v) == IS_FALSE) return TRUE;
                break;
            }
            case IS_TRUE:
            {
                if(Z_TYPE_P(v) == IS_TRUE) return TRUE;
                break;
            }
            case IS_LONG:
            {
                if(Z_TYPE_P(v) == IS_LONG && Z_LVAL_P(v) == Z_LVAL_P(value)) return TRUE;
                break;
            }
            default:
                return FALSE;
        }
    } ZUA_HASHMAP_FOREACH_END();
    
    return FALSE;
}

ZUA_API zua_string *zua_file_gets(const char *file_name) {
    zua_string *r = NULL;
    FILE *f = fopen(file_name, "r");
    char buf[MAX_STRING_KEY];
    while(f && !feof(f)) {
        if (ferror(f)) break;
        memset(buf, 0, sizeof(buf));
        size_t n = fread(buf, sizeof(char), MAX_STRING_KEY - 1, f);
        if (n >= 1)
            r = zua_string_append(r, buf, strlen(buf));
    }
    fclose(f);
    return r;
}