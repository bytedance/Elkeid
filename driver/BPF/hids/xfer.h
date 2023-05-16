// SPDX-License-Identifier: GPL-2.0

/*
 * xfer.h
 *
 * serialing & deserialing functionalities for ringslot
 */

#ifndef _SD_XFER_INCLUDE_
#define _SD_XFER_INCLUDE_

#ifndef SD_EVENT_MAX
#define SD_EVENT_MAX    (16384)
#define SD_EVENT_MASK   (SD_EVENT_MAX - 1)
#endif

#define SD_STR_MAX      (2048)
#define SD_STR_MASK     (SD_STR_MAX - 1)

#ifndef likely
#define likely(e)  e
#define unlikely(e) e
#endif

#ifndef ALIGN
#define __ALIGN_KERNEL(x, a) __ALIGN_KERNEL_MASK(x, (typeof(x))(a) - 1)
#define __ALIGN_KERNEL_MASK(x, mask) (((x) + (mask)) & ~(mask))
#define ALIGN(x, a) __ALIGN_KERNEL((x), (a))
#endif

#ifndef min_t
#define min_t(type, x, y)	({type __v_x = x, __v_y = y; __v_x > __v_y ? __v_y : __v_x;})
#define max_t(type, x, y)	({type __v_x = x, __v_y = y; __v_x > __v_y ? __v_x : __v_y;})
#endif

#if defined(__SD_XFER_SE__) || defined(__SD_XFER_DE__)

/*
 * defs for event entries
 */

struct sd_item_ent {
    union {
        uint32_t    size; /* data length in bytes */
        uint32_t    meta; /* size of meta head structure */
        uint32_t    item; /* type of the element */
    };
    union {
        uint32_t    xid;  /* id of this event type */
        uint32_t    eid;  /* dynamic sequence id inited by kernel */
        uint32_t    len;  /* length of element */
    };
};

struct sd_event_format {
    uint32_t        size;   /* total size in bytes */
    uint32_t        nids;   /* number of events: xxx_print */
    /* struct sd_item_ent eids[0]; */
};

/*
 * control flags for data serialization
 */

#define SD_TYPE_ARRAY_BIT       (0x80)
#define SD_TYPE_SIGN_BIT        (0x40)
#define SD_TYPE_SIZE_BIT        (0x8000)  /* data size zone: 2 bytes, 0 - 65535 */
#define SD_TYPE_LONG_BIT        (0x4000)  /* data size zone: 4 bytes */
#define SD_TYPE_SIZE_MASK       (0x3F00)

/*
 * basic data types
 */

#define SD_TYPE_U8              (1)
#define SD_TYPE_S8              (SD_TYPE_U8  | SD_TYPE_SIGN_BIT)
#define SD_TYPE_U16	            (2)
#define SD_TYPE_S16             (SD_TYPE_U16 | SD_TYPE_SIGN_BIT)
#define SD_TYPE_U32             (3)
#define SD_TYPE_S32             (SD_TYPE_U32 | SD_TYPE_SIGN_BIT)
#define SD_TYPE_U64             (4)
#define SD_TYPE_S64             (SD_TYPE_U64 | SD_TYPE_SIGN_BIT)

#define SD_TYPE_IP4             (SD_TYPE_U64 + 1)
#define SD_TYPE_IP6             (SD_TYPE_U64 + 2)
#define SD_TYPE_IP4BE           (SD_TYPE_IP4 | SD_TYPE_SIGN_BIT)
#define SD_TYPE_IP6BE           (SD_TYPE_IP6 | SD_TYPE_SIGN_BIT)
#define SD_TYPE_XIDS            (SD_TYPE_IP6 + 1)
#define SD_TYPE_STR             (SD_TYPE_IP6 + 2)
#define SD_TYPE_STRING          SD_TYPE_STR

#define SD_TYPE_MAX             SD_TYPE_STR

/*
 * ip v4/v6 address
 */

struct ipaddr_v6 {
	union {
		uint8_t		v6_addr8[16];
		uint16_t	v6_addr16[8];
		uint32_t	v6_addr32[4];
	};
} __attribute__((packed));

struct ipaddr_v4 {
	union {
		uint8_t		v4_addr8[4];
		uint32_t	v4_addr32;
	};
} __attribute__((packed));

/*
 * user cred info
 */

struct sd_xids {
    uint32_t  xids[8];
} __attribute__((packed));

/*
 * functionalities for data serializing
 */

/*
 * counting variable args (max 69 args supported)
 *
 * https://stackoverflow.com/questions/2124339/c-preprocessor-va-args-number-of-arguments
 */
#define SD_N_ARGS(...) SD_ARGS_C(__VA_ARGS__, SD_ARGS_S())
#define SD_ARGS_C(...) SD_ARGS_N(__VA_ARGS__)
#define SD_ARGS_N(                                              \
          _1, _2, _3, _4, _5, _6, _7, _8, _9,_10,               \
         _11,_12,_13,_14,_15,_16,_17,_18,_19,_20,               \
         _21,_22,_23,_24,_25,_26,_27,_28,_29,_30,               \
         _31,_32,_33,_34,_35,_36,_37,_38,_39,_40,               \
         _41,_42,_43,_44,_45,_46,_47,_48,_49,_50,               \
         _51,_52,_53,_54,_55,_56,_57,_58,_59,_60,               \
         _61,_62,_63,_64,_65,_66,_67,_68,_69,N,...) N
#define SD_ARGS_S()                                             \
         69,68,67,66,65,64,63,62,61,60,                         \
         59,58,57,56,55,54,53,52,51,50,                         \
         49,48,47,46,45,44,43,42,41,40,                         \
         39,38,37,36,35,34,33,32,31,30,                         \
         29,28,27,26,25,24,23,22,21,20,                         \
         19,18,17,16,15,14,13,12,11,10,                         \
         9,8,7,6,5,4,3,2,1,0

/*
 * compiler assertion
 */
#define SD_CLASSERT(cond) typedef int __GS_CL_ASSERTION[- !(cond)]
#define SD_ASSERT_NARGS(nargs, ...) SD_CLASSERT((nargs) == SD_N_ARGS(__VA_ARGS__))

/*
 * interation per parameter (flatted implementation of nested macro)
 */

#define SD_ENTS_NX(n, x, fn, fe, p, a, ...) SD_ENTS_##fn(n, x, p, a)                \
                                            SD_ENTS_N##x(n, fn, fe, pre, ## __VA_ARGS__)

#define SD_ENTS_N60(n, fn, fe, p, a, ...)   SD_ENTS_##fn(n, 59, p, a)  SD_ENTS_N59(n, fn, fe, p, __VA_ARGS__)
#define SD_ENTS_N59(n, fn, fe, p, a, ...)   SD_ENTS_##fn(n, 58, p, a)  SD_ENTS_N58(n, fn, fe, p, __VA_ARGS__)
#define SD_ENTS_N58(n, fn, fe, p, a, ...)   SD_ENTS_##fn(n, 57, p, a)  SD_ENTS_N57(n, fn, fe, p, __VA_ARGS__)
#define SD_ENTS_N57(n, fn, fe, p, a, ...)   SD_ENTS_##fn(n, 56, p, a)  SD_ENTS_N56(n, fn, fe, p, __VA_ARGS__)
#define SD_ENTS_N56(n, fn, fe, p, a, ...)   SD_ENTS_##fn(n, 55, p, a)  SD_ENTS_N55(n, fn, fe, p, __VA_ARGS__)
#define SD_ENTS_N55(n, fn, fe, p, a, ...)   SD_ENTS_##fn(n, 54, p, a)  SD_ENTS_N54(n, fn, fe, p, __VA_ARGS__)
#define SD_ENTS_N54(n, fn, fe, p, a, ...)   SD_ENTS_##fn(n, 53, p, a)  SD_ENTS_N53(n, fn, fe, p, __VA_ARGS__)
#define SD_ENTS_N53(n, fn, fe, p, a, ...)   SD_ENTS_##fn(n, 52, p, a)  SD_ENTS_N52(n, fn, fe, p, __VA_ARGS__)
#define SD_ENTS_N52(n, fn, fe, p, a, ...)   SD_ENTS_##fn(n, 51, p, a)  SD_ENTS_N51(n, fn, fe, p, __VA_ARGS__)
#define SD_ENTS_N51(n, fn, fe, p, a, ...)   SD_ENTS_##fn(n, 50, p, a)  SD_ENTS_N50(n, fn, fe, p, __VA_ARGS__)
#define SD_ENTS_N50(n, fn, fe, p, a, ...)   SD_ENTS_##fn(n, 49, p, a)  SD_ENTS_N49(n, fn, fe, p, __VA_ARGS__)
#define SD_ENTS_N49(n, fn, fe, p, a, ...)   SD_ENTS_##fn(n, 48, p, a)  SD_ENTS_N48(n, fn, fe, p, __VA_ARGS__)
#define SD_ENTS_N48(n, fn, fe, p, a, ...)   SD_ENTS_##fn(n, 47, p, a)  SD_ENTS_N47(n, fn, fe, p, __VA_ARGS__)
#define SD_ENTS_N47(n, fn, fe, p, a, ...)   SD_ENTS_##fn(n, 46, p, a)  SD_ENTS_N46(n, fn, fe, p, __VA_ARGS__)
#define SD_ENTS_N46(n, fn, fe, p, a, ...)   SD_ENTS_##fn(n, 45, p, a)  SD_ENTS_N45(n, fn, fe, p, __VA_ARGS__)
#define SD_ENTS_N45(n, fn, fe, p, a, ...)   SD_ENTS_##fn(n, 44, p, a)  SD_ENTS_N44(n, fn, fe, p, __VA_ARGS__)
#define SD_ENTS_N44(n, fn, fe, p, a, ...)   SD_ENTS_##fn(n, 43, p, a)  SD_ENTS_N43(n, fn, fe, p, __VA_ARGS__)
#define SD_ENTS_N43(n, fn, fe, p, a, ...)   SD_ENTS_##fn(n, 42, p, a)  SD_ENTS_N42(n, fn, fe, p, __VA_ARGS__)
#define SD_ENTS_N42(n, fn, fe, p, a, ...)   SD_ENTS_##fn(n, 41, p, a)  SD_ENTS_N41(n, fn, fe, p, __VA_ARGS__)
#define SD_ENTS_N41(n, fn, fe, p, a, ...)   SD_ENTS_##fn(n, 40, p, a)  SD_ENTS_N40(n, fn, fe, p, __VA_ARGS__)
#define SD_ENTS_N40(n, fn, fe, p, a, ...)   SD_ENTS_##fn(n, 39, p, a)  SD_ENTS_N39(n, fn, fe, p, __VA_ARGS__)
#define SD_ENTS_N39(n, fn, fe, p, a, ...)   SD_ENTS_##fn(n, 38, p, a)  SD_ENTS_N38(n, fn, fe, p, __VA_ARGS__)
#define SD_ENTS_N38(n, fn, fe, p, a, ...)   SD_ENTS_##fn(n, 37, p, a)  SD_ENTS_N37(n, fn, fe, p, __VA_ARGS__)
#define SD_ENTS_N37(n, fn, fe, p, a, ...)   SD_ENTS_##fn(n, 36, p, a)  SD_ENTS_N36(n, fn, fe, p, __VA_ARGS__)
#define SD_ENTS_N36(n, fn, fe, p, a, ...)   SD_ENTS_##fn(n, 35, p, a)  SD_ENTS_N35(n, fn, fe, p, __VA_ARGS__)
#define SD_ENTS_N35(n, fn, fe, p, a, ...)   SD_ENTS_##fn(n, 34, p, a)  SD_ENTS_N34(n, fn, fe, p, __VA_ARGS__)
#define SD_ENTS_N34(n, fn, fe, p, a, ...)   SD_ENTS_##fn(n, 33, p, a)  SD_ENTS_N33(n, fn, fe, p, __VA_ARGS__)
#define SD_ENTS_N33(n, fn, fe, p, a, ...)   SD_ENTS_##fn(n, 32, p, a)  SD_ENTS_N32(n, fn, fe, p, __VA_ARGS__)
#define SD_ENTS_N32(n, fn, fe, p, a, ...)   SD_ENTS_##fn(n, 31, p, a)  SD_ENTS_N31(n, fn, fe, p, __VA_ARGS__)
#define SD_ENTS_N31(n, fn, fe, p, a, ...)   SD_ENTS_##fn(n, 30, p, a)  SD_ENTS_N30(n, fn, fe, p, __VA_ARGS__)
#define SD_ENTS_N30(n, fn, fe, p, a, ...)   SD_ENTS_##fn(n, 29, p, a)  SD_ENTS_N29(n, fn, fe, p, __VA_ARGS__)
#define SD_ENTS_N29(n, fn, fe, p, a, ...)   SD_ENTS_##fn(n, 28, p, a)  SD_ENTS_N28(n, fn, fe, p, __VA_ARGS__)
#define SD_ENTS_N28(n, fn, fe, p, a, ...)   SD_ENTS_##fn(n, 27, p, a)  SD_ENTS_N27(n, fn, fe, p, __VA_ARGS__)
#define SD_ENTS_N27(n, fn, fe, p, a, ...)   SD_ENTS_##fn(n, 26, p, a)  SD_ENTS_N26(n, fn, fe, p, __VA_ARGS__)
#define SD_ENTS_N26(n, fn, fe, p, a, ...)   SD_ENTS_##fn(n, 25, p, a)  SD_ENTS_N25(n, fn, fe, p, __VA_ARGS__)
#define SD_ENTS_N25(n, fn, fe, p, a, ...)   SD_ENTS_##fn(n, 24, p, a)  SD_ENTS_N24(n, fn, fe, p, __VA_ARGS__)
#define SD_ENTS_N24(n, fn, fe, p, a, ...)   SD_ENTS_##fn(n, 23, p, a)  SD_ENTS_N23(n, fn, fe, p, __VA_ARGS__)
#define SD_ENTS_N23(n, fn, fe, p, a, ...)   SD_ENTS_##fn(n, 22, p, a)  SD_ENTS_N22(n, fn, fe, p, __VA_ARGS__)
#define SD_ENTS_N22(n, fn, fe, p, a, ...)   SD_ENTS_##fn(n, 21, p, a)  SD_ENTS_N21(n, fn, fe, p, __VA_ARGS__)
#define SD_ENTS_N21(n, fn, fe, p, a, ...)   SD_ENTS_##fn(n, 20, p, a)  SD_ENTS_N20(n, fn, fe, p, __VA_ARGS__)
#define SD_ENTS_N20(n, fn, fe, p, a, ...)   SD_ENTS_##fn(n, 19, p, a)  SD_ENTS_N19(n, fn, fe, p, __VA_ARGS__)
#define SD_ENTS_N19(n, fn, fe, p, a, ...)   SD_ENTS_##fn(n, 18, p, a)  SD_ENTS_N18(n, fn, fe, p, __VA_ARGS__)
#define SD_ENTS_N18(n, fn, fe, p, a, ...)   SD_ENTS_##fn(n, 17, p, a)  SD_ENTS_N17(n, fn, fe, p, __VA_ARGS__)
#define SD_ENTS_N17(n, fn, fe, p, a, ...)   SD_ENTS_##fn(n, 16, p, a)  SD_ENTS_N16(n, fn, fe, p, __VA_ARGS__)
#define SD_ENTS_N16(n, fn, fe, p, a, ...)   SD_ENTS_##fn(n, 15, p, a)  SD_ENTS_N15(n, fn, fe, p, __VA_ARGS__)
#define SD_ENTS_N15(n, fn, fe, p, a, ...)   SD_ENTS_##fn(n, 14, p, a)  SD_ENTS_N14(n, fn, fe, p, __VA_ARGS__)
#define SD_ENTS_N14(n, fn, fe, p, a, ...)   SD_ENTS_##fn(n, 13, p, a)  SD_ENTS_N13(n, fn, fe, p, __VA_ARGS__)
#define SD_ENTS_N13(n, fn, fe, p, a, ...)   SD_ENTS_##fn(n, 12, p, a)  SD_ENTS_N12(n, fn, fe, p, __VA_ARGS__)
#define SD_ENTS_N12(n, fn, fe, p, a, ...)   SD_ENTS_##fn(n, 11, p, a)  SD_ENTS_N11(n, fn, fe, p, __VA_ARGS__)
#define SD_ENTS_N11(n, fn, fe, p, a, ...)   SD_ENTS_##fn(n, 10, p, a)  SD_ENTS_N10(n, fn, fe, p, __VA_ARGS__)
#define SD_ENTS_N10(n, fn, fe, p, a, ...)   SD_ENTS_##fn(n,  9, p, a)  SD_ENTS_N9( n, fn, fe, p, __VA_ARGS__)
#define SD_ENTS_N9( n, fn, fe, p, a, ...)   SD_ENTS_##fn(n,  8, p, a)  SD_ENTS_N8( n, fn, fe, p, __VA_ARGS__)
#define SD_ENTS_N8( n, fn, fe, p, a, ...)   SD_ENTS_##fn(n,  7, p, a)  SD_ENTS_N7( n, fn, fe, p, __VA_ARGS__)
#define SD_ENTS_N7( n, fn, fe, p, a, ...)   SD_ENTS_##fn(n,  6, p, a)  SD_ENTS_N6( n, fn, fe, p, __VA_ARGS__)
#define SD_ENTS_N6( n, fn, fe, p, a, ...)   SD_ENTS_##fn(n,  5, p, a)  SD_ENTS_N5( n, fn, fe, p, __VA_ARGS__)
#define SD_ENTS_N5( n, fn, fe, p, a, ...)   SD_ENTS_##fn(n,  4, p, a)  SD_ENTS_N4( n, fn, fe, p, __VA_ARGS__)
#define SD_ENTS_N4( n, fn, fe, p, a, ...)   SD_ENTS_##fn(n,  3, p, a)  SD_ENTS_N3( n, fn, fe, p, __VA_ARGS__)
#define SD_ENTS_N3( n, fn, fe, p, a, ...)   SD_ENTS_##fn(n,  2, p, a)  SD_ENTS_N2( n, fn, fe, p, __VA_ARGS__)
#define SD_ENTS_N2( n, fn, fe, p, a, ...)   SD_ENTS_##fn(n,  1, p, a)  SD_ENTS_N1( n, fn, fe, p, __VA_ARGS__)
#define SD_ENTS_N1( n, fn, fe, p, a, ...)   SD_ENTS_##fe(n,  0, p, a)

#define SD_ENTS_ENT(n, x, pre, arg)         pre ## _ ## arg
#define SD_ENTS_ARG(n, x, pre, arg)         SD_ENTS_ENT(n, x, pre, arg),
#define SD_ENTS_EXP(n, x, pre, arg)         SD_ENTS_ENT(n, x, pre, arg);

/*
 * structure definition for event record
 */

#define SD_ITEM_ENTRY_U8( n, v)             uint32_t d_##n
#define SD_ITEM_ENTRY_U16(n, v)             uint32_t d_##n
#define SD_ITEM_ENTRY_U32(n, v)             uint32_t d_##n
#define SD_ITEM_ENTRY_U64(n, v)             uint64_t d_##n
#define SD_ITEM_ENTRY_S8( n, v)             int32_t d_##n
#define SD_ITEM_ENTRY_S16(n, v)             int32_t d_##n
#define SD_ITEM_ENTRY_S32(n, v)             int32_t d_##n
#define SD_ITEM_ENTRY_S64(n, v)             int64_t d_##n

#define SD_ITEM_ENTRY_XID(v)                uint32_t e_xid
#define SD_ITEM_ENTRY_INT(n, v)             SD_ITEM_ENTRY_S32(n, v)
#define SD_ITEM_ENTRY_UINT(n, v)            SD_ITEM_ENTRY_U32(n, v)

#if BITS_PER_LONG == 32
# define SD_ITEM_ENTRY_LONG(n, v)           SD_ITEM_ENTRY_S32(n, v)
# define SD_ITEM_ENTRY_ULONG(n, v)          SD_ITEM_ENTRY_U32(n, v)
#else
# define SD_ITEM_ENTRY_LONG(n, v)           SD_ITEM_ENTRY_S64(n, v)
# define SD_ITEM_ENTRY_ULONG(n, v)          SD_ITEM_ENTRY_U64(n, v)
#endif

#define SD_ITEM_ENTRY_IP4(n, v)             struct ipaddr_v4 d_##n
#define SD_ITEM_ENTRY_IP6(n, v)             struct ipaddr_v6 d_##n

#define SD_ITEM_ENTRY_XIDS(n, v)            struct sd_xids d_##n

#define SD_ITEM_ENTRY_STR(n, v)             union {uint32_t s_##n; struct {uint16_t o_##n, l_##n;};}
#define SD_ITEM_ENTRY_STL(n, v, l)          union {uint32_t s_##n; struct {uint16_t o_##n, l_##n;};}
#define SD_ITEM_ENTRY_KSL(n, v, l)          union {uint32_t s_##n; struct {uint16_t o_##n, l_##n;};}
#define SD_ITEM_ENTRY_USL(n, v, l)          union {uint32_t s_##n; struct {uint16_t o_##n, l_##n;};}

#define SD_ITEM_POINTER_IP4(n, v)           SD_ITEM_ENTRY_IP4(n, v)  
#define SD_ITEM_POINTER_IP6(n, v)           SD_ITEM_ENTRY_IP6(n, v)
#define SD_ITEM_POINTER_XIDS(n, v)          SD_ITEM_ENTRY_XIDS(n, v)
#define SD_ITEM_POINTER_STR(n, v)           SD_ITEM_ENTRY_STR(n, v)
#define SD_ITEM_POINTER_STL(n, v, l)        SD_ITEM_ENTRY_STL(n, v, l)
#define SD_ITEM_POINTER_KSL(n, v, l)        SD_ITEM_ENTRY_KSL(n, v, l)
#define SD_ITEM_POINTER_USL(n, v, l)        SD_ITEM_ENTRY_USL(n, v, l)

#define SD_ITEM_I(n, ...)                   SD_ENTS_N##n(n, EXP, EXP, SD_ITEM, __VA_ARGS__)
#define SD_ITEM_N(n, ...)                   SD_ITEM_I(n, __VA_ARGS__)
#define SD_ITEM_D(...)                      SD_ITEM_N(SD_N_ARGS(__VA_ARGS__), __VA_ARGS__)
#define SD_ITEM_XFER(...)                   SD_ITEM_D(__VA_ARGS__)

#define SD_XFER_PROTO_NAME(n)               sd_event_proto_##n
#define SD_XFER_EVENT_NAME(n)               sd_event_class_##n
#define SD_XFER_DEFINE_E(n, p, x)           \
    struct SD_XFER_EVENT_##n {              \
            struct sd_item_ent e_head;      \
            uint32_t e_meta;                \
            SD_ITEM_##x                     \
            char p_data[0];                 \
    } __attribute__((packed))

#endif /* defined(__SD_XFER_SE__) || defined(__SD_XFER_DE__) */

#if defined(__SD_XFER_SE__)

/*
 * variable definition for string pointers
 */

#define SD_STRP_ENTRY_U8(...)
#define SD_STRP_ENTRY_S8(...)
#define SD_STRP_ENTRY_U16(...)
#define SD_STRP_ENTRY_S16(...)
#define SD_STRP_ENTRY_U32(...)
#define SD_STRP_ENTRY_S32(...)
#define SD_STRP_ENTRY_U64(...)
#define SD_STRP_ENTRY_S64(...)
#define SD_STRP_ENTRY_IP4(...)
#define SD_STRP_ENTRY_IP6(...)
#define SD_STRP_ENTRY_XIDS(...)
#define SD_STRP_ENTRY_XID(...)
#define SD_STRP_ENTRY_INT(...)
#define SD_STRP_ENTRY_UINT(...)
#define SD_STRP_ENTRY_CHAR(...)
#define SD_STRP_ENTRY_UCHAR(...)
#define SD_STRP_ENTRY_SHORT(...)
#define SD_STRP_ENTRY_USHORT(...)
#define SD_STRP_ENTRY_LONG(...)
#define SD_STRP_ENTRY_ULONG(...)
#define SD_STRP_ENTRY_STR(t, s)
#define SD_STRP_ENTRY_STL(t, s, l)
#define SD_STRP_ENTRY_KSL(t, s, l)
#define SD_STRP_ENTRY_USL(t, s, l)

#define SD_STRP_POINTER_U8(...)
#define SD_STRP_POINTER_S8(...)
#define SD_STRP_POINTER_U16(...)
#define SD_STRP_POINTER_S16(...)
#define SD_STRP_POINTER_U32(...)
#define SD_STRP_POINTER_S32(...)
#define SD_STRP_POINTER_U64(...)
#define SD_STRP_POINTER_S64(...)
#define SD_STRP_POINTER_IP4(...)
#define SD_STRP_POINTER_IP6(...)
#define SD_STRP_POINTER_XIDS(...)
#define SD_STRP_POINTER_XID(...)
#define SD_STRP_POINTER_INT(...)
#define SD_STRP_POINTER_UINT(...)
#define SD_STRP_POINTER_CHAR(...)
#define SD_STRP_POINTER_UCHAR(...)
#define SD_STRP_POINTER_SHORT(...)
#define SD_STRP_POINTER_USHORT(...)
#define SD_STRP_POINTER_LONG(...)
#define SD_STRP_POINTER_ULONG(...)
#define SD_STRP_POINTER_STR(t, s)       SD_STRP_ENTRY_STR(t, s)
#define SD_STRP_POINTER_STL(t, s, l)    SD_STRP_ENTRY_STL(t, s, l)
#define SD_STRP_POINTER_KSL(t, s, l)    SD_STRP_ENTRY_KSL(t, s, l)
#define SD_STRP_POINTER_USL(t, s, l)    SD_STRP_ENTRY_USL(t, s, l)

#define SD_STRP_SIZE_I(n, ...)          SD_ENTS_N##n(n, ENT, ENT, SD_STRP, ## __VA_ARGS__)
#define SD_STRP_SIZE_N(n, ...)          SD_STRP_SIZE_I(n, __VA_ARGS__) /* to compute SD_SIZE_ITERS() */
#define SD_STRP_SIZE(...)               SD_STRP_SIZE_N(SD_N_ARGS(__VA_ARGS__), __VA_ARGS__)
#define SD_ENTS_STRP_XFER(...)          SD_STRP_SIZE(__VA_ARGS__)

/*
 * variable definition: length for strings (fixed or flexible)
 */

#define SD_STRS_ENTRY_U8(...)
#define SD_STRS_ENTRY_S8(...)
#define SD_STRS_ENTRY_U16(...)
#define SD_STRS_ENTRY_S16(...)
#define SD_STRS_ENTRY_U32(...)
#define SD_STRS_ENTRY_S32(...)
#define SD_STRS_ENTRY_U64(...)
#define SD_STRS_ENTRY_S64(...)
#define SD_STRS_ENTRY_IP4(...)
#define SD_STRS_ENTRY_IP6(...)
#define SD_STRS_ENTRY_XIDS(...)
#define SD_STRS_ENTRY_XID(...)
#define SD_STRS_ENTRY_INT(...)
#define SD_STRS_ENTRY_UINT(...)
#define SD_STRS_ENTRY_CHAR(...)
#define SD_STRS_ENTRY_UCHAR(...)
#define SD_STRS_ENTRY_SHORT(...)
#define SD_STRS_ENTRY_USHORT(...)
#define SD_STRS_ENTRY_LONG(...)
#define SD_STRS_ENTRY_ULONG(...)
#define SD_STRS_ENTRY_STR(t, s)         int __l_##t = sd_strnlen((s), SD_STR_MAX);
#define SD_STRS_ENTRY_STL(t, s, l)
#define SD_STRS_ENTRY_USL(t, s, l)
#define SD_STRS_ENTRY_KSL(t, s, l)

#define SD_STRS_POINTER_U8(...)
#define SD_STRS_POINTER_S8(...)
#define SD_STRS_POINTER_U16(...)
#define SD_STRS_POINTER_S16(...)
#define SD_STRS_POINTER_U32(...)
#define SD_STRS_POINTER_S32(...)
#define SD_STRS_POINTER_U64(...)
#define SD_STRS_POINTER_S64(...)
#define SD_STRS_POINTER_IP4(...)
#define SD_STRS_POINTER_IP6(...)
#define SD_STRS_POINTER_XIDS(...)
#define SD_STRS_POINTER_XID(...)
#define SD_STRS_POINTER_INT(...)
#define SD_STRS_POINTER_UINT(...)
#define SD_STRS_POINTER_CHAR(...)
#define SD_STRS_POINTER_UCHAR(...)
#define SD_STRS_POINTER_SHORT(...)
#define SD_STRS_POINTER_USHORT(...)
#define SD_STRS_POINTER_LONG(...)
#define SD_STRS_POINTER_ULONG(...)
#define SD_STRS_POINTER_STR(t, s)       SD_STRS_ENTRY_STR(t, s)
#define SD_STRS_POINTER_STL(t, s, l)    SD_STRS_ENTRY_STL(t, s, l)
#define SD_STRS_POINTER_USL(t, s, l)    SD_STRS_ENTRY_USL(t, s, l)
#define SD_STRS_POINTER_KSL(t, s, l)    SD_STRS_ENTRY_KSL(t, s, l)

#define SD_STRS_SIZE_I(n, ...)          SD_ENTS_N##n(n, ENT, ENT, SD_STRS, ## __VA_ARGS__)
#define SD_STRS_SIZE_N(n, ...)          SD_STRS_SIZE_I(n, __VA_ARGS__) /* to compute SD_SIZE_ITERS() */
#define SD_STRS_SIZE(...)               SD_STRS_SIZE_N(SD_N_ARGS(__VA_ARGS__), __VA_ARGS__)
#define SD_ENTS_STRS_XFER(...)          SD_STRS_SIZE(__VA_ARGS__)

/*
 * data size for strings
 */

#define SD_DATA_ENTRY_U8( n, v)
#define SD_DATA_ENTRY_U16(n, v)
#define SD_DATA_ENTRY_U32(n, v)
#define SD_DATA_ENTRY_U64(n, v)
#define SD_DATA_ENTRY_S8( n, v)
#define SD_DATA_ENTRY_S16(n, v)
#define SD_DATA_ENTRY_S32(n, v)
#define SD_DATA_ENTRY_S64(n, v)

#define SD_DATA_ENTRY_XID(v)
#define SD_DATA_ENTRY_INT(n, v)
#define SD_DATA_ENTRY_UINT(n, v)

#define SD_DATA_ENTRY_LONG(n, v)
#define SD_DATA_ENTRY_ULONG(n, v)

#define SD_DATA_ENTRY_IP4(n, v)
#define SD_DATA_ENTRY_IP6(n, v)

#define SD_DATA_ENTRY_XIDS(n, v)

#define SD_DATA_ENTRY_STR(n, v)         + __l_##n + (__l_##n ? 1 : 0) /* strcpy */
#define SD_DATA_ENTRY_STL(n, v, l)      + (l) /* including trailing 0 */
#define SD_DATA_ENTRY_KSL(n, v, l)      + (l)
#define SD_DATA_ENTRY_USL(n, v, l)      + (l)

#define SD_DATA_POINTER_IP4(n, v)       SD_DATA_ENTRY_IP4(n, v)
#define SD_DATA_POINTER_IP6(n, v)       SD_DATA_ENTRY_IP6(n, v)
#define SD_DATA_POINTER_XIDS(n, v)      SD_DATA_ENTRY_XIDS(n, v)
#define SD_DATA_POINTER_STR(n, v)       SD_DATA_ENTRY_STR(n, v)
#define SD_DATA_POINTER_STL(...)        SD_DATA_ENTRY_STL(__VA_ARGS__)
#define SD_DATA_POINTER_KSL(...)        SD_DATA_ENTRY_KSL(__VA_ARGS__)
#define SD_DATA_POINTER_USL(...)        SD_DATA_ENTRY_USL(__VA_ARGS__)

#define SD_DATA_I(n, ...)               SD_ENTS_N##n(n, ENT, ENT, SD_DATA, __VA_ARGS__)
#define SD_DATA_N(n, ...)               SD_DATA_I(n, __VA_ARGS__)
#define SD_DATA_D(...)                  SD_DATA_N(SD_N_ARGS(__VA_ARGS__), __VA_ARGS__)
#define SD_DATA_XFER(...)               SD_DATA_D(__VA_ARGS__)

/*
 * function prototype defintions (using PROTO() or XFER() as parameters)
 */

/* XFER(ENTRY(type, name, value), ENTRY() ...) as parameters */
#define SD_DECL_ENTRY_XID(v)            SD_DECL_ENTRY(uint32_t, xid, v)
#define SD_DECL_ENTRY_U8(n, v)          SD_DECL_ENTRY(uint8_t, n, v)
#define SD_DECL_ENTRY_S8(n, v)          SD_DECL_ENTRY(int8_t, n, v)
#define SD_DECL_ENTRY_U16(n, v)         SD_DECL_ENTRY(uint16_t, n, v)
#define SD_DECL_ENTRY_S16(n, v)         SD_DECL_ENTRY(int16_t, n, v)
#define SD_DECL_ENTRY_U32(n, v)         SD_DECL_ENTRY(uint32_t, n, v)
#define SD_DECL_ENTRY_S32(n, v)         SD_DECL_ENTRY(int32_t, n, v)
#define SD_DECL_ENTRY_U64(n, v)         SD_DECL_ENTRY(uint64_t, n, v)
#define SD_DECL_ENTRY_S64(n, v)         SD_DECL_ENTRY(int64_t, n, v)
#define SD_DECL_ENTRY_IP4(n, v)         SD_DECL_ENTRY(uint32_t, n, v)
#define SD_DECL_ENTRY_IP6(n, v)         SD_DECL_ENTRY(void *, n, v)
#define SD_DECL_ENTRY_XIDS(n, v)        SD_DECL_ENTRY(void *, n, v)
#define SD_DECL_ENTRY_STR(n, v)         SD_DECL_ENTRY(char *, n, v)
#define SD_DECL_ENTRY_STL(n, v, l)      SD_DECL_ENTRY(char *, n, v)
#define SD_DECL_ENTRY_KSL(n, v, l)      SD_DECL_ENTRY(char *, n, v)
#define SD_DECL_ENTRY_USL(n, v, l)      SD_DECL_ENTRY(char *, n, v)

#define SD_DECL_ENTRY_INT(n, v)         SD_DECL_ENTRY_S32(n, v)
#define SD_DECL_ENTRY_UINT(n, v)        SD_DECL_ENTRY_U32(n, v)
#if BITS_PER_LONG == 32
# define SD_DECL_ENTRY_LONG(n, v)       SD_DECL_ENTRY_S32(n, v)
# define SD_DECL_ENTRY_ULONG(n, v)      SD_DECL_ENTRY_U32(n, v)
#else
# define SD_DECL_ENTRY_LONG(n, v)       SD_DECL_ENTRY_S64(n, v)
# define SD_DECL_ENTRY_ULONG(n, v)      SD_DECL_ENTRY_U64(n, v)
#endif

#define SD_DECL_POINTER_IP4(n, v)       SD_DECL_ENTRY_IP4(n, v)
#define SD_DECL_POINTER_IP6(n, v)       SD_DECL_ENTRY_IP6(n, v)
#define SD_DECL_POINTER_XIDS(n, v)      SD_DECL_ENTRY_XIDS(n, v)
#define SD_DECL_POINTER_STR(n, v)       SD_DECL_ENTRY_STR(n, v)
#define SD_DECL_POINTER_STL(n, v, l)    SD_DECL_ENTRY_STL(n, v, l)
#define SD_DECL_POINTER_KSL(n, v, l)    SD_DECL_ENTRY_KSL(n, v, l)
#define SD_DECL_POINTER_USL(n, v, l)    SD_DECL_ENTRY_USL(n, v, l)

#define SD_DECL_ENTRY(type, name, ...)  type name
#define SD_DECL_XFER(...)               __VA_ARGS__

/* proto(ELEMENT(type, name), ELEMENT() ...) as parameters */
#define SD_DECL_ELEMENT(type, name)     type name
#define SD_DECL_PROT(...)               __VA_ARGS__

#define SD_EXPR_N(name, nargs, ...) \
        name(SD_ENTS_N##nargs(nargs, ARG, ENT, SD_DECL, ## __VA_ARGS__))
#define SD_EXPR_M(name, nargs, ...) SD_EXPR_N(name, nargs,  __VA_ARGS__) /* to compute SD_N_ARGS() */
#define SD_XFES_NAME(n) n##__print
#define SD_XFES(name, ...) SD_EXPR_M(SD_XFES_##name, SD_N_ARGS(__VA_ARGS__), __VA_ARGS__)
#define SD_XFER_NAME(n) n##_print
#define SD_XFER(name, ...) SD_EXPR_M(SD_XFER_##name, SD_N_ARGS(__VA_ARGS__), __VA_ARGS__)

/*
 * wrappers of trace_ringbuffer routines
 */

#define SD_PACK_ENTRY_XID(v)            __ev->e_xid = v
#define SD_PACK_ENTRY_U8(n, v)          __ev->d_##n = v
#define SD_PACK_ENTRY_S8(n, v)          __ev->d_##n = v
#define SD_PACK_ENTRY_U16(n, v)         __ev->d_##n = v
#define SD_PACK_ENTRY_S16(n, v)         __ev->d_##n = v
#define SD_PACK_ENTRY_U32(n, v)         __ev->d_##n = v
#define SD_PACK_ENTRY_S32(n, v)         __ev->d_##n = v
#define SD_PACK_ENTRY_U64(n, v)         __ev->d_##n = v
#define SD_PACK_ENTRY_S64(n, v)         __ev->d_##n = v
#define SD_PACK_ENTRY_INT(n, v)         SD_PACK_ENTRY_S32(n, v)
#define SD_PACK_ENTRY_UINT(n, v)        SD_PACK_ENTRY_U32(n, v)
#define SD_PACK_ENTRY_CHAR(n, v)        SD_PACK_ENTRY_S8(n, v)
#define SD_PACK_ENTRY_UCHAR(n, v)       SD_PACK_ENTRY_U8(n, v)
#define SD_PACK_ENTRY_SHORT(n, v)       SD_PACK_ENTRY_S16(n, v)
#define SD_PACK_ENTRY_USHORT(n, v)      SD_PACK_ENTRY_U16(n, v)
#if BITS_PER_LONG == 32
# define SD_PACK_ENTRY_LONG(n, v)       SD_PACK_ENTRY_S32(n, v)
# define SD_PACK_ENTRY_ULONG(n, v)      SD_PACK_ENTRY_U32(n, v)
#else
# define SD_PACK_ENTRY_LONG(n, v)       SD_PACK_ENTRY_S64(n, v)
# define SD_PACK_ENTRY_ULONG(n, v)      SD_PACK_ENTRY_U64(n, v)
#endif
#define SD_PACK_ENTRY_LONGLONG(n, v)    SD_PACK_ENTRY_S64(n, v)
#define SD_PACK_ENTRY_ULONGLONG(n, v)   SD_PACK_ENTRY_U64(n, v)

#define SD_PACK_ENTRY_IP4(n, v)         __ev->d_##n.v4_addr32 = v
#define SD_PACK_ENTRY_IP6(n, v)         __builtin_memcpy(&__ev->d_##n, v, sizeof(struct ipaddr_v6))

#define SD_PACK_ENTRY_XIDS(n, v)        __builtin_memcpy(&__ev->d_##n, v, sizeof(struct sd_xids))

#define SD_PACK_ENTRY_STR(n, s)                                         \
    do {                                                                \
        if (likely(__l_##n)) {                                          \
            __ev->s_##n = ((uint32_t)__l_##n) << 16 | __tr_used;        \
            __tr_used += __l_##n + 1; /* strcpy */                      \
            bpf_probe_read_str(&__ev->p_data[__tr_used & SD_STR_MASK],  \
                               __l_##n & SD_STR_MASK, (s));             \
        } else {                                                        \
            __ev->s_##n = 0;                                            \
        }                                                               \
    } while(0)

#define SD_PACK_ENTRY_STL(n, s, l)                                      \
    do {                                                                \
        if (likely(l)) {                                                \
            int __rc = bpf_probe_read_str(                              \
                               &__ev->p_data[__tr_used & SD_STR_MASK],  \
                                __builtin_constant_p(l) ? (l) :         \
                                      ((l) & SD_STR_MASK), (s));        \
            if (__rc > 1) {                                             \
                __ev->s_##n = ((uint32_t)(__rc - 1)) << 16 | __tr_used; \
                __tr_used += __rc;                                      \
            } else {                                                    \
                __ev->s_##n = 0;                                        \
            }                                                           \
        } else {                                                        \
            __ev->s_##n = 0;                                            \
        }                                                               \
    } while(0)

#define SD_PACK_ENTRY_KSL(n, s, l)                                      \
    do {                                                                \
        if (likely(l)) {                                                \
            __ev->s_##n = ((uint32_t)(l)) << 16 | __tr_used;            \
            __tr_used += (l);                                           \
            bpf_probe_read_kernel(&__ev->p_data[__tr_used & SD_STR_MASK],\
                                __builtin_constant_p(l) ? (l) :         \
                                      ((l) & SD_STR_MASK), (s));        \
        } else {                                                        \
            __ev->s_##n = 0;                                            \
        }                                                               \
    } while(0)

#define SD_PACK_ENTRY_USL(n, s, l)                                      \
    do {                                                                \
        if (likely(l)) {                                                \
            __ev->s_##n = ((uint32_t)(l)) << 16 | __tr_used;            \
            bpf_probe_read_user(&__ev->p_data[__tr_used & SD_STR_MASK], \
                                __builtin_constant_p(l) ? (l) :         \
                                      ((l) & SD_STR_MASK), (s));        \
            __tr_used += (l);                                           \
        } else {                                                        \
            __ev->s_##n = 0;                                            \
        }                                                               \
    } while(0)

/*
 * data assignments for pointer types
 */

#define SD_PACK_POINTER_U8(n, pv)       SD_PACK_ENTRY_U8(n, *(pv))
#define SD_PACK_POINTER_S8(n, pv)       SD_PACK_ENTRY_S8(n, *(pv))
#define SD_PACK_POINTER_U16(n, pv)      SD_PACK_ENTRY_U16(n, *(pv))
#define SD_PACK_POINTER_S16(n, pv)      SD_PACK_ENTRY_S16(n, *(pv))
#define SD_PACK_POINTER_U32(n, pv)      SD_PACK_ENTRY_U32(n, *(pv))
#define SD_PACK_POINTER_S32(n, pv)      SD_PACK_ENTRY_S32(n, *(pv))
#define SD_PACK_POINTER_U64(n, pv)      SD_PACK_ENTRY_U64(n, *(pv))
#define SD_PACK_POINTER_S64(n, pv)      SD_PACK_ENTRY_S64(n, *(pv))

#define SD_PACK_POINTER_INT(n, v)       SD_PACK_POINTER_S32(n, v)
#define SD_PACK_POINTER_UINT(n, v)      SD_PACK_POINTER_U32(n, v)
#define SD_PACK_POINTER_CHAR(n, v)      SD_PACK_POINTER_S8(n, v)
#define SD_PACK_POINTER_UCHAR(n, v)     SD_PACK_POINTER_U8(n, v)
#define SD_PACK_POINTER_SHORT(n, v)     SD_PACK_POINTER_S16(n, v)
#define SD_PACK_POINTER_USHORT(n, v)    SD_PACK_POINTER_U16(n, v)
#if BITS_PER_LONG == 32
# define SD_PACK_POINTER_LONG(n, v)     SD_PACK_POINTER_S32(n, v)
# define SD_PACK_POINTER_ULONG(n, v)    SD_PACK_POINTER_U32(n, v)
#else
# define SD_PACK_POINTER_LONG(n, v)     SD_PACK_POINTER_S64(n, v)
# define SD_PACK_POINTER_ULONG(n, v)    SD_PACK_POINTER_U64(n, v)
#endif
#define SD_PACK_POINTER_LONGLONG(n, v)  SD_PACK_POINTER_S64(n, v)
#define SD_PACK_POINTER_ULONGLONG(n, v) SD_PACK_POINTER_U64(n, v)
#define SD_PACK_POINTER_STR(t, s)       SD_PACK_ENTRY_STR(t, s)
#define SD_PACK_POINTER_STL(t, s, l)    SD_PACK_ENTRY_STL(t, s, l)
#define SD_PACK_POINTER_KSL(t, s, l)    SD_PACK_ENTRY_KSL(t, s, l)
#define SD_PACK_POINTER_USL(t, s, l)    SD_PACK_ENTRY_USL(t, s, l)

#define SD_PACK_POINTER_IP4(n, pv)      SD_PACK_ENTRY_IP4(n, *((uint32_t *)(pv)))
#define SD_PACK_POINTER_IP6(n, pv)      SD_PACK_ENTRY_IP6(n, (void *)(pv))

#define SD_PACK_POINTER_XIDS(n, pv)     SD_PACK_ENTRY_XIDS(n, (void *)(pv))

#define SD_ENTS_PACK(n, x, pre, arg)    pre ## _ ## arg;
#define SD_ENTS_PACK_I(n, ...)          SD_ENTS_N##n(n, PACK, PACK, SD_PACK, ## __VA_ARGS__)
#define SD_ENTS_PACK_N(n, ...)          SD_ENTS_PACK_I(n, __VA_ARGS__) /* to compute SD_SIZE_ITERS() */
#define SD_ENTS_PACK_X(...)             SD_ENTS_PACK_N(SD_N_ARGS(__VA_ARGS__), __VA_ARGS__)
#define SD_ENTS_PACK_XFER(...)          SD_ENTS_PACK_X(__VA_ARGS__)

#endif /* __SD_XFER_SE__ */

#if defined(__SD_XFER_DE__)
extern int sd_init_format(char *sd, int len, int proto, int event);
extern int sd_unpack(void *de, int sde, void *se, int *rec);
extern void sd_hexdump(void *ptr, int len);
extern void sd_show_msg(char *str, int len);
#endif

#define SD_SEP_ENTRY    (0x0)           /* seperation between entries */
#define SD_REC_ENDIAN   (0xFFFE00)      /* seperation between records */

/*
 * magic strings for sd_event_points location in rodata
 */
#define SD_EVENT_PROTO_MAGIC  "\x20\x00\x00\x00\x00\x00\x00\x00<<SD_EVENT_PROTO_START>>"
#define SD_EVENT_POINT_MAGIC  "<SD_EVENT_START>"

#endif /* _SD_XFER_INCLUDE_ */
