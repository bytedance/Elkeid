/* clamav-config.h.cmake.in.  Autoconf compatibility layer for CMake.  */

/* Define if building universal (internal helper macro) */
/* #undef AC_APPLE_UNIVERSAL_BUILD */

/* mmap flag for anonymous maps */
#define ANONYMOUS_MAP MAP_ANONYMOUS

/* bind 8 compatibility mode, required on some systems to get T_TXT, etc from nameser_compat.h */
/* #undef BIND_8_COMPAT */

/* name of the clamav group */
#define CLAMAVGROUP "clamav"

/* name of the clamav user */
#define CLAMAVUSER "clamav"

/* enable debugging */
/* #undef CL_DEBUG */

/* enable experimental code */
/* #undef CL_EXPERIMENTAL */

/* thread safe */
#define CL_THREAD_SAFE 1

/* curses header location */
/* #undef CURSES_INCLUDE */

/* os is aix */
/* #undef C_AIX */

/* os is beos */
/* #undef C_BEOS */

/* Increase thread stack size. */
/* #undef C_BIGSTACK */

/* os is bsd flavor */
/* #undef C_BSD */

/* os is darwin */
/* #undef C_DARWIN */

/* target is gnu-hurd */
/* #undef C_GNU_HURD */

/* os is hpux */
/* #undef C_HPUX */

/* os is interix */
/* #undef C_INTERIX */

/* os is irix */
/* #undef C_IRIX */

/* target is kfreebsd-gnu */
/* #undef C_KFREEBSD_GNU */

/* target is linux */
#define C_LINUX 1

/* os is OS/2 */
/* #undef C_OS2 */

/* os is osf/tru64 */
/* #undef C_OSF */

/* os is QNX 6.x.x */
/* #undef C_QNX6 */

/* os is solaris */
/* #undef C_SOLARIS */

#ifndef _WIN32
/* Path to virus database directory. */
#define DATADIR "/var/lib/clamav"

/* where to look for the config file */
#define CONFDIR "/etc/clamav"
#endif

/* Have sys/fanotify.h */
#define HAVE_SYS_FANOTIFY_H 1

/* whether _XOPEN_SOURCE needs to be defined for fd passing to work */
/* #undef FDPASS_NEED_XOPEN */

/* file i/o buffer size */
#define FILEBUFF 8192

/* scan buffer size */
#define SCANBUFF 131072

/* enable workaround for broken DNS servers */
/* #undef FRESHCLAM_DNS_FIX */

/* use "Cache-Control: no-cache" in freshclam */
/* #undef FRESHCLAM_NO_CACHE */

/* attrib aligned */
#define HAVE_ATTRIB_ALIGNED 1

/* attrib packed */
#define HAVE_ATTRIB_PACKED 1

/* have bzip2 */
#define HAVE_BZLIB_H 1

/* Define to 1 if you have the `ctime_r' function. */
/* #undef HAVE_CTIME_R */

/* ctime_r takes 2 arguments */
/* #undef HAVE_CTIME_R_2 */

/* ctime_r takes 3 arguments */
/* #undef HAVE_CTIME_R_3 */

/* Define to 1 if you have the declaration of `cygwin_conv_path', and to 0 if
   you don't. */
/* #undef HAVE_DECL_CYGWIN_CONV_PATH */

/* Define to 1 if you have a deprecated version of the 'libjson' library
   (-ljson). */
/* #undef HAVE_DEPRECATED_JSON */

/* Define to 1 if you have the <dirent.h> header file. */
#define HAVE_DIRENT_H 1

/* Define if you have the GNU dld library. */
/* #undef HAVE_DLD */

/* Define to 1 if you have the <dld.h> header file. */
/* #undef HAVE_DLD_H */

/* Define to 1 if you have the `dlerror' function. */
/* #undef HAVE_DLERROR */

/* Define to 1 if you have the <dlfcn.h> header file. */
#define HAVE_DLFCN_H 1

/* Define to 1 if you have the <dl.h> header file. */
/* #undef HAVE_DL_H */

/* Define if you have the _dyld_func_lookup function. */
/* #undef HAVE_DYLD */

/* Define to 1 if you have the `enable_extended_FILE_stdio' function. */
/* #undef HAVE_ENABLE_EXTENDED_FILE_STDIO */

/* Define to 1 if the system has the type `error_t'. */
/* #undef HAVE_ERROR_T */

/* have working file descriptor passing support */
/* #undef HAVE_FD_PASSING */

/* Define to 1 if fseeko (and presumably ftello) exists and is declared. */
#define HAVE_FSEEKO 1

/* have getaddrinfo() */
#define HAVE_GETADDRINFO 1

/* Define to 1 if you have the `getnameinfo' function. */
/* #undef HAVE_GETNAMEINFO */

/* Define to 1 if getpagesize() is available */
#define HAVE_GETPAGESIZE 1

/* Define to 1 if you have the <grp.h> header file. */
#define HAVE_GRP_H 1

/* Define if you have the iconv() function and it works. */
#define HAVE_ICONV 1

/* Define to 1 if you have the `initgroups' function. */
#define HAVE_INITGROUPS 1

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* Define to 1 if you have the <inttypes.h> header file (for libjson-c). */
#define JSON_C_HAVE_INTTYPES_H 1

/* Define to 1 if you have the 'libjson' library (-ljson). */
#define HAVE_JSON 1

/* Define to '1' if you have the check.h library */
/* #undef HAVE_LIBCHECK */

/* Define to '1' if you have the ncurses.h library */
/* #undef HAVE_LIBNCURSES */

/* Define to '1' if you have the curses.h library */
/* #undef HAVE_LIBPDCURSES */

/* Define to 1 if you have the `ssl' library (-lssl). */
#define HAVE_LIBSSL 1

/* Define to 1 if you have the 'libxml2' library (-lxml2). */
#define HAVE_LIBXML2 1

/* Define to 1 if you have the `z' library (-lz). */
#define HAVE_LIBZ 1

/* Define to 1 if you have the <limits.h> header file. */
#define HAVE_LIMITS_H 1

/* Define to 1 if you have the `madvise' function. */
/* #undef HAVE_MADVISE */

/* Define to 1 if you have the `mallinfo' function. */
/* #undef HAVE_MALLINFO */

/* Define to 1 if you have the <malloc.h> header file. */
#define HAVE_MALLOC_H 1

/* Define to 1 if you have the `mkstemp' function. */
/* #undef HAVE_MKSTEMP */

/* Define to 1 if you have a working `mmap' system call that supports
   MAP_PRIVATE. */
#define HAVE_MMAP 1

/* Define to 1 if you have a pcre library (-lpcre). */
#define HAVE_PCRE 1

/* Define to 1 if you using the pcre2 library. */
#define USING_PCRE2 1

/* Define to 1 if you have the `poll' function. */
#define HAVE_POLL 1

/* Define to 1 if you have the <poll.h> header file. */
#define HAVE_POLL_H 1

/* "pragma pack" */
/* #undef HAVE_PRAGMA_PACK */

/* "pragma pack hppa/hp-ux style" */
/* #undef HAVE_PRAGMA_PACK_HPPA */

/* Define if libtool can extract symbol lists from object files. */
/* #undef HAVE_PRELOADED_SYMBOLS */

/* Define to 1 if you have the <pthread.h> header file */
#define HAVE_PTHREAD_H 1

/* Define to 1 if you have the <pwd.h> header file. */
#define HAVE_PWD_H 1

/* Define to 1 if you have the `readdir' function. */
/* #undef HAVE_READDIR */

/* Define to 1 if you have the `recvmsg' function. */
#define HAVE_RECVMSG 1

/* have resolv.h */
#define HAVE_RESOLV_H 1

/* Define signed right shift implementation */
/* #undef HAVE_SAR */

/* Define to 1 if you have the `sched_yield' function. */
/* #undef HAVE_SCHED_YIELD */

/* Define to 1 if you have the `sendmsg' function. */
#define HAVE_SENDMSG 1

/* Define to 1 if you have the `setgroups' function. */
#define HAVE_SETGROUPS 1

/* Define to 1 if you have the `setsid' function. */
#define HAVE_SETSID 1

/* Define to 1 if you have the `snprintf' function. */
#define HAVE_SNPRINTF 1

/* enable stat64 */
/* #undef HAVE_STAT64 */

/* Define to 1 if you have the <stdbool.h> header file. */
#define HAVE_STDBOOL_H 1

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the `strcasestr' function. */
/* #undef HAVE_STRCASESTR */

/* Define to 1 if you have the `strerror_r' function. */
#define HAVE_STRERROR_R 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the `strlcat' function. */
#define HAVE_STRLCAT 1

/* Define to 1 if you have the `strlcpy' function. */
#define HAVE_STRLCPY 1

/* Define to 1 if you have the `strndup' function. */
#define HAVE_STRNDUP 1

/* using internal strn functions */
/* #undef HAVE_STRNI */

/* Define to 1 if you have the `strnlen' function. */
#define HAVE_STRNLEN 1

/* Define to 1 if you have the `strnstr' function. */
/* #undef HAVE_STRNSTR */

/* Define to 1 if sysconf(_SC_PAGESIZE) is available */
#define HAVE_SYSCONF_SC_PAGESIZE 1

/* Define to 1 if you have the `sysctlbyname' function. */
/* #undef HAVE_SYSCTLBYNAME */

/* systemd is supported */
/* #undef HAVE_SYSTEMD */

/* Use private fts() implementation which is LFS safe */
/* #undef HAVE_SYSTEM_LFS_FTS */

/* Define to 1 if you have the <sys/cdefs.h> header file. */
/* #undef HAVE_SYS_CDEFS_H */

/* Define to 1 if you have the <sys/dl.h> header file. */
/* #undef HAVE_SYS_DL_H */

/* Define to 1 if you have the <sys/filio.h> header file. */
/* #undef HAVE_SYS_FILIO_H */

/* Define to 1 if you have the <sys/inttypes.h> header file. */
/* #undef HAVE_SYS_INTTYPES_H */

/* Define to 1 if you have the <sys/int_types.h> header file. */
/* #undef HAVE_SYS_INT_TYPES_H */

/* Define to 1 if you have the <sys/mman.h> header file. */
#define HAVE_SYS_MMAN_H 1

/* Define to 1 if you have the <sys/param.h> header file. */
#define HAVE_SYS_PARAM_H 1

/* Define to 1 if you have the <sys/queue.h> header file. */
/* #undef HAVE_SYS_QUEUE_H */

/* "have <sys/select.h>" */
#define HAVE_SYS_SELECT_H 1

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/times.h> header file. */
#define HAVE_SYS_TIMES_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have the <sys/uio.h> header file. */
#define HAVE_SYS_UIO_H 1

/* Define to 1 if you have the <termios.h> header file. */
#define HAVE_TERMIOS_H 1

/* Define to 1 if you have the `timegm' function. */
#define HAVE_TIMEGM 1

/* Define this if uname(2) is POSIX */
/* #undef HAVE_UNAME_SYSCALL */

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Define to 1 if you have the `vsnprintf' function. */
#define HAVE_VSNPRINTF 1

/* This value is set to 1 to indicate that the system argz facility works */
/* #undef HAVE_WORKING_ARGZ */

/* yara sources are compiled in */
#define HAVE_YARA 1

/* Define to 1 if you have the <zlib.h> header file. */
#define HAVE_ZLIB_H 1

/* For internal use only - DO NOT DEFINE */
/* #undef HAVE__INTERNAL__SHA_COLLECT */

/* Define as const if the declaration of iconv() needs const. */
/* #undef ICONV_CONST */

/* Define if UNRAR is linked instead of loaded. */
#define UNRAR_LINKED 1

/* "Full clamav library version number" */
#define LIBCLAMAV_FULLVER "9.1.0"

/* "Major clamav library version number" */
#define LIBCLAMAV_MAJORVER 9

/* "Full freshclam library version number" */
#define LIBFRESHCLAM_FULLVER "2.0.2"

/* "Major freshclam library version number" */
#define LIBFRESHCLAM_MAJORVER 2

/* The archive extension */
#define LT_LIBEXT ".a"

/* The archive prefix */
#define LT_LIBPREFIX "lib"

/* Define to the extension used for runtime loadable modules, say, ".so" or ".dylib". */
#define LT_MODULE_EXT ".so"

/* Define to the name of the environment variable that determines the run-time
   module search path. */
#ifdef _WIN32
#define SEARCH_LIBDIR "/home/zhangjiacheng.111/hids_os/Elkeid/plugins/scanner/clamav/build/install"
#else
#define SEARCH_LIBDIR "/home/zhangjiacheng.111/hids_os/Elkeid/plugins/scanner/clamav/build/install/lib"
#endif

/* Define to the shared library suffix, say, ".dylib". */
#define LT_SHARED_EXT ".so"

/* disable assertions */
/* #undef NDEBUG */

/* Define if dlsym() requires a leading underscore in symbol names. */
/* #undef NEED_USCORE */

/* bzip funtions do not have bz2 prefix */
/* #undef NOBZ2PREFIX */

/* "no fd_set" */
/* #undef NO_FD_SET */

/* Name of package */
#define PACKAGE "ClamAV"

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT "https://github.com/Cisco-Talos/clamav/issues"

/* Define to the full name of this package. */
#define PACKAGE_NAME "ClamAV"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "ClamAV 0.104.3"

/* Define to the one symbol short name of this package. */
/* #undef PACKAGE_TARNAME */

/* Define to the home page for this package. */
#define PACKAGE_URL "https://www.clamav.net/"

/* Define to the version of this package. */
#define PACKAGE_VERSION "0.104.3"

/* Libprelude support enabled */
/* #undef PRELUDE */

/* Define whether application use libtool >= 2.0 */
/* #undef PRELUDE_APPLICATION_USE_LIBTOOL2 */

/* Define to if the `setpgrp' function takes no argument. */
/* #undef SETPGRP_VOID */

/* The number of bytes in type int */
#define SIZEOF_INT 4

/* The number of bytes in type long */
#define SIZEOF_LONG 8

/* The number of bytes in type long long */
#define SIZEOF_LONG_LONG 8

/* The number of bytes in type short */
#define SIZEOF_SHORT 2

/* The number of bytes in type void * */
#define SIZEOF_VOID_P 8

/* Define to if you have the ANSI C header files. */
/* #undef STDC_HEADERS */

/* Support for IPv6 */
/* #undef SUPPORT_IPv6 */

/* enable memory pools */
#define USE_MPOOL 1

/* use syslog */
#define USE_SYSLOG 1

/* Enable extensions on AIX 3, Interix.  */
#ifndef _ALL_SOURCE
/* #undef _ALL_SOURCE */
#endif
/* Enable GNU extensions on systems that have them.  */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
/* Enable threading extensions on Solaris.  */
#ifndef _POSIX_PTHREAD_SEMANTICS
/* #undef _POSIX_PTHREAD_SEMANTICS */
#endif
/* Enable extensions on HP NonStop.  */
#ifndef _TANDEM_SOURCE
/* #undef _TANDEM_SOURCE */
#endif
/* Enable general extensions on Solaris.  */
#ifndef __EXTENSIONS__
/* #undef __EXTENSIONS__ */
#endif

/* LLVM version (if found) */
/* #undef LLVM_VERSION */

/* Version number of package */
#define VERSION "0.104.3"

/* Version suffix for package */
#define VERSION_SUFFIX ""

/* Define WORDS_BIGENDIAN to 1 if your processor stores words with the most
   significant byte first (like Motorola and SPARC, unlike Intel). */
#if defined AC_APPLE_UNIVERSAL_BUILD
# if defined __BIG_ENDIAN__
#  define WORDS_BIGENDIAN 1
# endif
#else
# ifndef WORDS_BIGENDIAN
/* #undef WORDS_BIGENDIAN */
# endif
#endif

/* Define to 1 if `lex' declares `yytext' as a `char *' by default, not a
   `char[]'. */
/* #undef YYTEXT_POINTER */

/* Enable large inode numbers on Mac OS X 10.5.  */
#ifndef _DARWIN_USE_64_BIT_INODE
# define _DARWIN_USE_64_BIT_INODE 1
#endif

/* Number of bits in a file offset, on hosts where this is settable. */
/* #undef _FILE_OFFSET_BITS */

/* Define to 1 to make fseeko visible on some hosts (e.g. glibc 2.2). */
/* #undef _LARGEFILE_SOURCE */

/* Define for large files, on AIX-style hosts. */
/* #undef _LARGE_FILES */

/* Define to 1 if on MINIX. */
/* #undef _MINIX */

/* Define to 2 if the system does not provide POSIX.1 features except with
   this defined. */
/* #undef _POSIX_1_SOURCE */

/* POSIX compatibility */
/* #undef _POSIX_PII_SOCKET */

/* Define to 1 if you need to in order for `stat' and other things to work. */
/* #undef _POSIX_SOURCE */

/* thread safe */
#define _REENTRANT 1

/* Define so that glibc/gnulib argp.h does not typedef error_t. */
/* #undef __error_t_defined */

/* Define to `__inline__' or `__inline' if that's what the C compiler
   calls it, or to nothing if 'inline' is not supported under any name.  */
#ifndef __cplusplus
#define inline inline
#endif

/* Define to `long int' if <sys/types.h> does not define. */
/* #undef off_t */

/* Define to `int' if <sys/types.h> does not define. */
/* #undef ssize_t */

/* Define to the equivalent of the C99 'restrict' keyword, or to
   nothing if this is not supported.  Do not define if restrict is
   supported directly.  */
#define restrict __restrict

/* Work around a bug in Sun C++: it does not support _Restrict or
   __restrict__, even though the corresponding Sun C compiler ends up with
   "#define restrict _Restrict" or "#define restrict __restrict__" in the
   previous line.  Perhaps some future version of Sun C++ will work with
   restrict; if so, hopefully it defines __RESTRICT like Sun C does.  */
#if defined __SUNPRO_CC && !defined __RESTRICT
# define _Restrict
# define __restrict__
#endif

/* Define to "int" if <sys/socket.h> does not define. */
/* #undef socklen_t */

#include "platform.h"
