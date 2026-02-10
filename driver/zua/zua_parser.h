/* A Bison parser, made by GNU Bison 3.3.2.  */

/* Bison interface for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2015, 2018-2019 Free Software Foundation,
   Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

/* Undocumented macros, especially those whose name start with YY_,
   are private implementation details.  Do not rely on them.  */

#ifndef YY_ZUA_YY_ZUA_PARSER_H_INCLUDED
# define YY_ZUA_YY_ZUA_PARSER_H_INCLUDED
/* Debug traces.  */
#ifndef ZUA_YYDEBUG
# if defined YYDEBUG
#if YYDEBUG
#   define ZUA_YYDEBUG 1
#  else
#   define ZUA_YYDEBUG 0
#  endif
# else /* ! defined YYDEBUG */
#  define ZUA_YYDEBUG 0
# endif /* ! defined YYDEBUG */
#endif  /* ! defined ZUA_YYDEBUG */
#if ZUA_YYDEBUG
extern int zua_yydebug;
#endif
/* "%code requires" blocks.  */


    #include "zua_type.h"
    #include "zua_parser_defs.h"



/* Token type.  */
#ifndef ZUA_YYTOKENTYPE
# define ZUA_YYTOKENTYPE
  enum zua_yytokentype
  {
    ZUA_JSON_T_NUL = 258,
    ZUA_JSON_T_NAN = 259,
    ZUA_JSON_T_INFINITY = 260,
    ZUA_JSON_T_NEGATIVE_INFINITY = 261,
    ZUA_JSON_T_TRUE = 262,
    ZUA_JSON_T_FALSE = 263,
    ZUA_JSON_T_INT = 264,
    ZUA_JSON_T_DOUBLE = 265,
    ZUA_JSON_T_STRING = 266,
    ZUA_JSON_T_ETRING = 267,
    ZUA_JSON_T_EOI = 268,
    ZUA_JSON_T_ERROR = 269,
    ZUA_JSON_T_COMMENT_NOT_CLOSED = 270
  };
#endif

/* Value type.  */
#if ! defined ZUA_YYSTYPE && ! defined ZUA_YYSTYPE_IS_DECLARED

union ZUA_YYSTYPE
{


    zval value;


};

typedef union ZUA_YYSTYPE ZUA_YYSTYPE;
# define ZUA_YYSTYPE_IS_TRIVIAL 1
# define ZUA_YYSTYPE_IS_DECLARED 1
#endif



int zua_yyparse (zua_json_parser *parser);

#endif /* !YY_ZUA_YY_ZUA_PARSER_H_INCLUDED  */
