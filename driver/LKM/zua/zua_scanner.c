/* Generated by re2c 2.1.1 */
/*
 * re2c -t zua_scanner_defs.h -bci -o zua_scanner.c --no-generation-date zua_scanner.re
*/
#include <stdio.h>
#include "zua_scanner.h"
#include "zua_scanner_defs.h"
#include "zua_parser.h"
#include "zua_type.h"
#include <ctype.h>
#include <inttypes.h>

#define YYCTYPE     zua_json_ctype
#define YYCURSOR    s->cursor
#define YYLIMIT     s->limit
#define YYMARKER    s->marker
#define YYCTXMARKER s->ctxmarker

#define YYGETCONDITION()        s->state
#define YYSETCONDITION(yystate) s->state = yystate

#define YYFILL(n)

#define ZUA_JSON_CONDITION_SET(condition) YYSETCONDITION(yyc##condition)
#define ZUA_JSON_CONDITION_GOTO(condition) goto yyc_##condition
#define ZUA_JSON_CONDITION_SET_AND_GOTO(condition) \
    ZUA_JSON_CONDITION_SET(condition);            \
    ZUA_JSON_CONDITION_GOTO(condition)

void zua_json_scanner_init(zua_json_scanner *s, const char *str, uint32_t str_len, int options) {
    s->cursor = (zua_json_ctype *)str;
    s->limit  = (zua_json_ctype *)str + str_len;
    s->options = options;
    ZUA_JSON_CONDITION_SET(JS);
}


int zua_json_scan(zua_json_scanner *s) {
    ZVAL_NULL(&s->value);
    
std:
    s->token = s->cursor;
    

	{
		YYCTYPE yych;
		unsigned int yyaccept = 0;
		if (YYGETCONDITION() < 2) {
			if (YYGETCONDITION() < 1) {
				goto yyc_JS;
			} else {
				goto yyc_STR_P2;
			}
		} else {
			if (YYGETCONDITION() < 3) {
				goto yyc_COMMENTS;
			} else {
				goto yyc_STR_P1;
			}
		}
/* *********************************** */
yyc_JS:
		{
			static const unsigned char yybm[] = {
				  0,   0,   0,   0,   0,   0,   0,   0, 
				  0,  16,   0,   0,   0,  16,   0,   0, 
				  0,   0,   0,   0,   0,   0,   0,   0, 
				  0,   0,   0,   0,   0,   0,   0,   0, 
				 16,   0,   0,   0,   0,   0,   0,   0, 
				  0,   0,   0,   0,   0,   0,   0,   0, 
				 96,  96,  96,  96,  96,  96,  96,  96, 
				 96,  96,   0,   0,   0,   0,   0,   0, 
				  0, 192, 192, 192, 192, 192, 192,  64, 
				 64,  64,  64,  64,  64,  64,  64,  64, 
				 64,  64,  64,  64,  64,  64,  64,  64, 
				 64,  64,  64,   0,   0,   0,   0,  64, 
				  0, 192, 192, 192, 192, 192, 192,  64, 
				 64,  64,  64,  64,  64,  64,  64,  64, 
				 64,  64,  64,  64,  64,  64,  64,  64, 
				 64,  64,  64,   0,   0,   0,   0,   0, 
				 64,  64,  64,  64,  64,  64,  64,  64, 
				 64,  64,  64,  64,  64,  64,  64,  64, 
				 64,  64,  64,  64,  64,  64,  64,  64, 
				 64,  64,  64,  64,  64,  64,  64,  64, 
				 64,  64,  64,  64,  64,  64,  64,  64, 
				 64,  64,  64,  64,  64,  64,  64,  64, 
				 64,  64,  64,  64,  64,  64,  64,  64, 
				 64,  64,  64,  64,  64,  64,  64,  64, 
				 64,  64,  64,  64,  64,  64,  64,  64, 
				 64,  64,  64,  64,  64,  64,  64,  64, 
				 64,  64,  64,  64,  64,  64,  64,  64, 
				 64,  64,  64,  64,  64,  64,  64,  64, 
				 64,  64,  64,  64,  64,  64,  64,  64, 
				 64,  64,  64,  64,  64,  64,  64,  64, 
				 64,  64,  64,  64,  64,  64,  64,  64, 
				 64,  64,  64,  64,  64,  64,  64,  64, 
			};
			yych = *YYCURSOR;
			switch (yych) {
			case 0x00:	goto yy2;
			case 0x01:
			case 0x02:
			case 0x03:
			case 0x04:
			case 0x05:
			case 0x06:
			case 0x07:
			case 0x08:
			case '\v':
			case '\f':
			case 0x0E:
			case 0x0F:
			case 0x10:
			case 0x11:
			case 0x12:
			case 0x13:
			case 0x14:
			case 0x15:
			case 0x16:
			case 0x17:
			case 0x18:
			case 0x19:
			case 0x1A:
			case 0x1B:
			case 0x1C:
			case 0x1D:
			case 0x1E:
			case 0x1F:
			case '!':
			case '#':
			case '$':
			case '%':
			case '&':
			case '(':
			case ')':
			case '*':
			case ';':
			case '<':
			case '=':
			case '>':
			case '?':
			case '\\':
			case '^':
			case '`':
			case '|':
			case '~':
			case 0x7F:	goto yy4;
			case '\t':
			case ' ':	goto yy6;
			case '\n':	goto yy9;
			case '\r':	goto yy10;
			case '"':
			case '\'':	goto yy11;
			case '+':	goto yy13;
			case ',':	goto yy14;
			case '-':	goto yy16;
			case '.':	goto yy17;
			case '/':	goto yy20;
			case '0':	goto yy21;
			case '1':
			case '2':
			case '3':
			case '4':
			case '5':
			case '6':
			case '7':
			case '8':
			case '9':	goto yy23;
			case ':':	goto yy25;
			case '@':	goto yy27;
			case 'I':	goto yy31;
			case 'N':	goto yy32;
			case '[':	goto yy33;
			case ']':	goto yy35;
			case 'f':	goto yy37;
			case 'n':	goto yy38;
			case 't':	goto yy39;
			case '{':	goto yy40;
			case '}':	goto yy42;
			default:	goto yy28;
			}
yy2:
			++YYCURSOR;
			{
    if (s->limit < s->cursor) {
        return ZUA_JSON_T_EOI;
    } else {
        s->errcode = 1;
        return ZUA_JSON_T_ERROR;
    }
}
yy4:
			++YYCURSOR;
yy5:
			{
    return ZUA_JSON_T_ERROR;
}
yy6:
			yych = *++YYCURSOR;
yy7:
			if (yybm[0+yych] & 16) {
				goto yy6;
			}
yy8:
			{ goto std; }
yy9:
			++YYCURSOR;
			goto yy8;
yy10:
			yych = *++YYCURSOR;
			if (yych == '\n') goto yy9;
			goto yy7;
yy11:
			++YYCURSOR;
			{
    char c = s->token[0];
    s->str_start = s->cursor;
    uint32_t i = 0, j = 0;
    zua_string *str = NULL;
    for (; ; i++) {
        if (YYCURSOR < YYLIMIT) {
            if (*YYCURSOR == c) break;
            if (*YYCURSOR++ == '\\') {
                if (str == NULL) {
                    str = zua_string_create(s->str_start, i - j);
                } else {
                    str = zua_string_append(str, s->str_start+j, i - j);
                }
                while (isspace(*YYCURSOR)) {
                    YYCURSOR++;
                    i++;
                }
                j = i + 1;
            }
        } else {
            zua_string_free(str);
            return ZUA_JSON_T_ERROR;
        }
    }
    str = zua_string_append(str, s->str_start+j, i - j);
    s->cursor++;
    Z_STR_P(&s->value) = str;
    Z_TYPE_P(&s->value) = IS_STRING;
    return ZUA_JSON_T_STRING;
}
yy13:
			yych = *++YYCURSOR;
			if (yych <= '/') goto yy5;
			if (yych <= '0') goto yy44;
			if (yych <= '9') goto yy23;
			goto yy5;
yy14:
			++YYCURSOR;
			{ return ','; }
yy16:
			yyaccept = 0;
			yych = *(YYMARKER = ++YYCURSOR);
			if (yych <= '9') {
				if (yych <= '/') goto yy5;
				if (yych <= '0') goto yy44;
				goto yy23;
			} else {
				if (yych == 'I') goto yy45;
				goto yy5;
			}
yy17:
			yyaccept = 1;
			yych = *(YYMARKER = ++YYCURSOR);
			if (yybm[0+yych] & 32) {
				goto yy17;
			}
			if (yych == 'E') goto yy47;
			if (yych == 'e') goto yy47;
yy19:
			{
    ZVAL_DOUBLE(&s->value, strtod((char *) s->token, NULL));
    return ZUA_JSON_T_DOUBLE;
}
yy20:
			yych = *++YYCURSOR;
			if (yych == '*') goto yy48;
			if (yych == '/') goto yy50;
			goto yy5;
yy21:
			yyaccept = 2;
			yych = *(YYMARKER = ++YYCURSOR);
			if (yych <= 'W') {
				if (yych <= '.') {
					if (yych >= '.') goto yy17;
				} else {
					if (yych == 'E') goto yy47;
				}
			} else {
				if (yych <= 'e') {
					if (yych <= 'X') goto yy52;
					if (yych >= 'e') goto yy47;
				} else {
					if (yych == 'x') goto yy52;
				}
			}
yy22:
			{
    ZVAL_LONG(&s->value, strtol((char *)s->token, NULL, 10));
    return ZUA_JSON_T_INT;
}
yy23:
			yyaccept = 2;
			yych = *(YYMARKER = ++YYCURSOR);
			if (yych <= '9') {
				if (yych == '.') goto yy17;
				if (yych <= '/') goto yy22;
				goto yy23;
			} else {
				if (yych <= 'E') {
					if (yych <= 'D') goto yy22;
					goto yy47;
				} else {
					if (yych == 'e') goto yy47;
					goto yy22;
				}
			}
yy25:
			++YYCURSOR;
			{ return ':'; }
yy27:
			yych = *++YYCURSOR;
			if (yych == '"') goto yy53;
			if (yych == '\'') goto yy55;
			goto yy5;
yy28:
			yych = *++YYCURSOR;
yy29:
			if (yybm[0+yych] & 64) {
				goto yy28;
			}
			{
    ZVAL_STRINGL(&s->value, s->token, s->cursor - s->token);
    ZUA_JSON_CONDITION_SET(JS);
    return ZUA_JSON_T_ETRING;
}
yy31:
			yych = *++YYCURSOR;
			if (yych == 'n') goto yy57;
			goto yy29;
yy32:
			yych = *++YYCURSOR;
			if (yych == 'a') goto yy58;
			goto yy29;
yy33:
			++YYCURSOR;
			{ return '['; }
yy35:
			++YYCURSOR;
			{ return ']'; }
yy37:
			yych = *++YYCURSOR;
			if (yych == 'a') goto yy59;
			goto yy29;
yy38:
			yych = *++YYCURSOR;
			if (yych == 'u') goto yy60;
			goto yy29;
yy39:
			yych = *++YYCURSOR;
			if (yych == 'r') goto yy61;
			goto yy29;
yy40:
			++YYCURSOR;
			{ return '{'; }
yy42:
			++YYCURSOR;
			{ return '}'; }
yy44:
			yyaccept = 2;
			yych = *(YYMARKER = ++YYCURSOR);
			if (yych <= 'D') {
				if (yych == '.') goto yy17;
				goto yy22;
			} else {
				if (yych <= 'E') goto yy47;
				if (yych == 'e') goto yy47;
				goto yy22;
			}
yy45:
			yych = *++YYCURSOR;
			if (yych == 'n') goto yy62;
yy46:
			YYCURSOR = YYMARKER;
			if (yyaccept <= 1) {
				if (yyaccept == 0) {
					goto yy5;
				} else {
					goto yy19;
				}
			} else {
				goto yy22;
			}
yy47:
			yych = *++YYCURSOR;
			if (yych <= ',') {
				if (yych == '+') goto yy63;
				goto yy46;
			} else {
				if (yych <= '-') goto yy63;
				if (yych <= '/') goto yy46;
				if (yych <= '9') goto yy64;
				goto yy46;
			}
yy48:
			++YYCURSOR;
			{
    while(YYCURSOR < YYLIMIT) {
        if (*YYCURSOR++ == '*' && *YYCURSOR == '/') {
            break;
        }
    }
    if (YYCURSOR < YYLIMIT) {
        YYCURSOR++;
    } else {
        return ZUA_JSON_T_COMMENT_NOT_CLOSED;
    }
    goto std;
}
yy50:
			++YYCURSOR;
			{
    ZUA_JSON_CONDITION_SET_AND_GOTO(COMMENTS);
}
yy52:
			yych = *++YYCURSOR;
			if (yybm[0+yych] & 128) {
				goto yy66;
			}
			goto yy46;
yy53:
			++YYCURSOR;
			{
    s->str_start = s->cursor;
    s->str_esc = 0;
    s->utf8_invalid = 0;
    s->utf8_invalid_count = 0;
    ZUA_JSON_CONDITION_SET_AND_GOTO(STR_P1);
}
yy55:
			++YYCURSOR;
			{
    s->str_start = s->cursor;
    s->str_esc = 0;
    s->utf8_invalid = 0;
    s->utf8_invalid_count = 0;
    ZUA_JSON_CONDITION_SET_AND_GOTO(STR_P2);
}
yy57:
			yych = *++YYCURSOR;
			if (yych == 'f') goto yy69;
			goto yy29;
yy58:
			yych = *++YYCURSOR;
			if (yych == 'N') goto yy70;
			goto yy29;
yy59:
			yych = *++YYCURSOR;
			if (yych == 'l') goto yy72;
			goto yy29;
yy60:
			yych = *++YYCURSOR;
			if (yych == 'l') goto yy73;
			goto yy29;
yy61:
			yych = *++YYCURSOR;
			if (yych == 'u') goto yy74;
			goto yy29;
yy62:
			yych = *++YYCURSOR;
			if (yych == 'f') goto yy75;
			goto yy46;
yy63:
			yych = *++YYCURSOR;
			if (yych <= '/') goto yy46;
			if (yych >= ':') goto yy46;
yy64:
			yych = *++YYCURSOR;
			if (yych <= '/') goto yy19;
			if (yych <= '9') goto yy64;
			goto yy19;
yy66:
			yych = *++YYCURSOR;
			if (yybm[0+yych] & 128) {
				goto yy66;
			}
			{
    ZVAL_LONG(&s->value, strtol((char *)s->token, NULL, 16));
    return ZUA_JSON_T_INT;
}
yy69:
			yych = *++YYCURSOR;
			if (yych == 'i') goto yy76;
			goto yy29;
yy70:
			yych = *++YYCURSOR;
			if (yybm[0+yych] & 64) {
				goto yy28;
			}
			{
    ZVAL_NAN(&s->value);
    return ZUA_JSON_T_NAN;
}
yy72:
			yych = *++YYCURSOR;
			if (yych == 's') goto yy77;
			goto yy29;
yy73:
			yych = *++YYCURSOR;
			if (yych == 'l') goto yy78;
			goto yy29;
yy74:
			yych = *++YYCURSOR;
			if (yych == 'e') goto yy80;
			goto yy29;
yy75:
			yych = *++YYCURSOR;
			if (yych == 'i') goto yy82;
			goto yy46;
yy76:
			yych = *++YYCURSOR;
			if (yych == 'n') goto yy83;
			goto yy29;
yy77:
			yych = *++YYCURSOR;
			if (yych == 'e') goto yy84;
			goto yy29;
yy78:
			yych = *++YYCURSOR;
			if (yybm[0+yych] & 64) {
				goto yy28;
			}
			{
    ZVAL_NULL(&s->value);
    return ZUA_JSON_T_NUL;
}
yy80:
			yych = *++YYCURSOR;
			if (yybm[0+yych] & 64) {
				goto yy28;
			}
			{
    ZVAL_TRUE(&s->value);
    return ZUA_JSON_T_TRUE;
}
yy82:
			yych = *++YYCURSOR;
			if (yych == 'n') goto yy86;
			goto yy46;
yy83:
			yych = *++YYCURSOR;
			if (yych == 'i') goto yy87;
			goto yy29;
yy84:
			yych = *++YYCURSOR;
			if (yybm[0+yych] & 64) {
				goto yy28;
			}
			{
    ZVAL_FALSE(&s->value);
    return ZUA_JSON_T_FALSE;
}
yy86:
			yych = *++YYCURSOR;
			if (yych == 'i') goto yy88;
			goto yy46;
yy87:
			yych = *++YYCURSOR;
			if (yych == 't') goto yy89;
			goto yy29;
yy88:
			yych = *++YYCURSOR;
			if (yych == 't') goto yy90;
			goto yy46;
yy89:
			yych = *++YYCURSOR;
			if (yych == 'y') goto yy91;
			goto yy29;
yy90:
			yych = *++YYCURSOR;
			if (yych == 'y') goto yy93;
			goto yy46;
yy91:
			yych = *++YYCURSOR;
			if (yybm[0+yych] & 64) {
				goto yy28;
			}
			{
    ZVAL_INFINITY(&s->value);
    return ZUA_JSON_T_INFINITY;
}
yy93:
			++YYCURSOR;
			{
    ZVAL_NINFINITY(&s->value);
    return ZUA_JSON_T_NEGATIVE_INFINITY;
}
		}
/* *********************************** */
yyc_STR_P2:
		{
			static const unsigned char yybm[] = {
				128, 128, 128, 128, 128, 128, 128, 128, 
				128, 128, 128, 128, 128, 128, 128, 128, 
				128, 128, 128, 128, 128, 128, 128, 128, 
				128, 128, 128, 128, 128, 128, 128, 128, 
				128, 128, 128, 128, 128, 128, 128,   0, 
				128, 128, 128, 128, 128, 128, 128, 128, 
				128, 128, 128, 128, 128, 128, 128, 128, 
				128, 128, 128, 128, 128, 128, 128, 128, 
				128, 128, 128, 128, 128, 128, 128, 128, 
				128, 128, 128, 128, 128, 128, 128, 128, 
				128, 128, 128, 128, 128, 128, 128, 128, 
				128, 128, 128, 128, 128, 128, 128, 128, 
				128, 128, 128, 128, 128, 128, 128, 128, 
				128, 128, 128, 128, 128, 128, 128, 128, 
				128, 128, 128, 128, 128, 128, 128, 128, 
				128, 128, 128, 128, 128, 128, 128, 128, 
				128, 128, 128, 128, 128, 128, 128, 128, 
				128, 128, 128, 128, 128, 128, 128, 128, 
				128, 128, 128, 128, 128, 128, 128, 128, 
				128, 128, 128, 128, 128, 128, 128, 128, 
				128, 128, 128, 128, 128, 128, 128, 128, 
				128, 128, 128, 128, 128, 128, 128, 128, 
				128, 128, 128, 128, 128, 128, 128, 128, 
				128, 128, 128, 128, 128, 128, 128, 128, 
				128, 128, 128, 128, 128, 128, 128, 128, 
				128, 128, 128, 128, 128, 128, 128, 128, 
				128, 128, 128, 128, 128, 128, 128, 128, 
				128, 128, 128, 128, 128, 128, 128, 128, 
				128, 128, 128, 128, 128, 128, 128, 128, 
				128, 128, 128, 128, 128, 128, 128, 128, 
				128, 128, 128, 128, 128, 128, 128, 128, 
				128, 128, 128, 128, 128, 128, 128, 128, 
			};
			yych = *YYCURSOR;
			if (yybm[0+yych] & 128) {
				goto yy97;
			}
			goto yy100;
yy97:
			yych = *++YYCURSOR;
			if (yybm[0+yych] & 128) {
				goto yy97;
			}
			{ ZUA_JSON_CONDITION_GOTO(STR_P2); }
yy100:
			++YYCURSOR;
			{
    size_t len = s->cursor - s->str_start - s->str_esc - 1 + s->utf8_invalid_count;
    ZVAL_STRINGL(&s->value, s->str_start, len);
    ZUA_JSON_CONDITION_SET(JS);
    return ZUA_JSON_T_STRING;
}
		}
/* *********************************** */
yyc_COMMENTS:
		yych = *YYCURSOR;
		if (yych == '\n') goto yy106;
		++YYCURSOR;
		{
    if (YYCURSOR >= YYLIMIT) {
        return ZUA_JSON_T_ERROR;
    }
    ZUA_JSON_CONDITION_SET_AND_GOTO(COMMENTS);
}
yy106:
		++YYCURSOR;
		{ ZUA_JSON_CONDITION_SET_AND_GOTO(JS); }
/* *********************************** */
yyc_STR_P1:
		{
			static const unsigned char yybm[] = {
				128, 128, 128, 128, 128, 128, 128, 128, 
				128, 128, 128, 128, 128, 128, 128, 128, 
				128, 128, 128, 128, 128, 128, 128, 128, 
				128, 128, 128, 128, 128, 128, 128, 128, 
				128, 128,   0, 128, 128, 128, 128, 128, 
				128, 128, 128, 128, 128, 128, 128, 128, 
				128, 128, 128, 128, 128, 128, 128, 128, 
				128, 128, 128, 128, 128, 128, 128, 128, 
				128, 128, 128, 128, 128, 128, 128, 128, 
				128, 128, 128, 128, 128, 128, 128, 128, 
				128, 128, 128, 128, 128, 128, 128, 128, 
				128, 128, 128, 128, 128, 128, 128, 128, 
				128, 128, 128, 128, 128, 128, 128, 128, 
				128, 128, 128, 128, 128, 128, 128, 128, 
				128, 128, 128, 128, 128, 128, 128, 128, 
				128, 128, 128, 128, 128, 128, 128, 128, 
				128, 128, 128, 128, 128, 128, 128, 128, 
				128, 128, 128, 128, 128, 128, 128, 128, 
				128, 128, 128, 128, 128, 128, 128, 128, 
				128, 128, 128, 128, 128, 128, 128, 128, 
				128, 128, 128, 128, 128, 128, 128, 128, 
				128, 128, 128, 128, 128, 128, 128, 128, 
				128, 128, 128, 128, 128, 128, 128, 128, 
				128, 128, 128, 128, 128, 128, 128, 128, 
				128, 128, 128, 128, 128, 128, 128, 128, 
				128, 128, 128, 128, 128, 128, 128, 128, 
				128, 128, 128, 128, 128, 128, 128, 128, 
				128, 128, 128, 128, 128, 128, 128, 128, 
				128, 128, 128, 128, 128, 128, 128, 128, 
				128, 128, 128, 128, 128, 128, 128, 128, 
				128, 128, 128, 128, 128, 128, 128, 128, 
				128, 128, 128, 128, 128, 128, 128, 128, 
			};
			yych = *YYCURSOR;
			if (yybm[0+yych] & 128) {
				goto yy110;
			}
			goto yy113;
yy110:
			yych = *++YYCURSOR;
			if (yybm[0+yych] & 128) {
				goto yy110;
			}
			{ ZUA_JSON_CONDITION_GOTO(STR_P1); }
yy113:
			++YYCURSOR;
			{
    size_t len = s->cursor - s->str_start - s->str_esc - 1 + s->utf8_invalid_count;
    ZVAL_STRINGL(&s->value, s->str_start, len);
    ZUA_JSON_CONDITION_SET(JS);
    return ZUA_JSON_T_STRING;
}
		}
	}

}