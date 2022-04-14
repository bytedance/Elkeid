// SPDX-License-Identifier: GPL-2.0
/*
 * util.c
 *
 */
#include "../include/util.h"
#include <linux/version.h>
#include <linux/kallsyms.h>
#include <linux/prefetch.h>


#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0) || LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)

#include <linux/kprobes.h>

static unsigned long (*kallsyms_lookup_name_sym)(const char *name);

static int _kallsyms_lookup_kprobe(struct kprobe *p, struct pt_regs *regs)
{
        return 0;
}

unsigned long get_kallsyms_func(void)
{
        struct kprobe probe;
        int ret;
        unsigned long addr;

        memset(&probe, 0, sizeof(probe));
        probe.pre_handler = _kallsyms_lookup_kprobe;
        probe.symbol_name = "kallsyms_lookup_name";
        ret = register_kprobe(&probe);
        if (ret)
                return 0;
        addr = (unsigned long)probe.addr;
        unregister_kprobe(&probe);
        return addr;
}

unsigned long smith_kallsyms_lookup_name(const char *name)
{
        /* singleton */
        if (!kallsyms_lookup_name_sym) {
                kallsyms_lookup_name_sym = (void *)get_kallsyms_func();
                if(!kallsyms_lookup_name_sym)
                        return 0;
        }
        return kallsyms_lookup_name_sym(name);
}

#else

unsigned long smith_kallsyms_lookup_name(const char *name)
{
    return kallsyms_lookup_name(name);
}

#endif

u8 *smith_query_sb_uuid(struct super_block *sb)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
    /* uuid_t s_uuid; */
    return (u8 *)&sb->s_uuid;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 39)
    /* s_uuid not defined, using fixed zone of this sb */
    return (u8 *)&sb->s_dev;
#else
    /* u8 s_uuid[16]; */
    return (u8 *)&sb->s_uuid[0];
#endif
}

size_t smith_strnlen (const char *str, size_t maxlen)
{
    const char *char_ptr, *end_ptr = str + maxlen;
    const unsigned long *longword_ptr;
    unsigned long longword, himagic, lomagic;

    if (!str || maxlen == 0)
        return 0;

    if (unlikely (end_ptr < str))
        end_ptr = (const char *) ~0UL;

    /* Handle the first few characters by reading one character at a time.
       Do this until CHAR_PTR is aligned on a longword boundary.  */
    for (char_ptr = str; ((unsigned long)char_ptr & (sizeof(longword) - 1)) != 0;
         ++char_ptr)
    if (*char_ptr == '\0') {
	    if (char_ptr > end_ptr)
	        char_ptr = end_ptr;
        return char_ptr - str;
    }

    /* All these elucidatory comments refer to 4-byte longwords,
       but the theory applies equally well to 8-byte longwords.  */
    longword_ptr = (unsigned long *) char_ptr;

    /* Bits 31, 24, 16, and 8 of this number are zero.  Call these bits
       the "holes."  Note that there is a hole just to the left of
       each byte, with an extra at the end:

       bits:  01111110 11111110 11111110 11111111
       bytes: AAAAAAAA BBBBBBBB CCCCCCCC DDDDDDDD

       The 1-bits make sure that carries propagate to the next 0-bit.
       The 0-bits provide holes for carries to fall into.  */
    himagic = 0x80808080L;
    lomagic = 0x01010101L;
    if (sizeof(longword) > 4) {
        /* 64-bit version of the magic.  */
        /* Do the shift in two steps to avoid a warning if long has 32 bits.  */
        himagic = ((himagic << 16) << 16) | himagic;
        lomagic = ((lomagic << 16) << 16) | lomagic;
    }
    CLASSERT(sizeof(longword) <= 8);

    /* Instead of the traditional loop which tests each character,
       we will test a longword at a time.  The tricky part is testing
       if *any of the four* bytes in the longword in question are zero.  */
    while (longword_ptr < (unsigned long *) end_ptr) {
        /* We tentatively exit the loop if adding MAGIC_BITS to
	       LONGWORD fails to change any of the hole bits of LONGWORD.

	       1) Is this safe?  Will it catch all the zero bytes?
	       Suppose there is a byte with all zeros.  Any carry bits
	       propagating from its left will fall into the hole at its
	       least significant bit and stop.  Since there will be no
	       carry from its most significant bit, the LSB of the
	       byte to the left will be unchanged, and the zero will be
	       detected.

	       2) Is this worthwhile?  Will it ignore everything except
	       zero bytes?  Suppose every byte of LONGWORD has a bit set
	       somewhere.  There will be a carry into bit 8.  If bit 8
	       is set, this will carry into bit 16.  If bit 8 is clear,
	       one of bits 9-15 must be set, so there will be a carry
	       into bit 16.  Similarly, there will be a carry into bit
	       24.  If one of bits 24-30 is set, there will be a carry
	       into bit 31, so all of the hole bits will be changed.

	       The one misfire occurs when bits 24-30 are clear and bit
	       31 is set; in this case, the hole at bit 31 is not
	       changed.  If we had access to the processor carry flag,
	       we could close this loophole by putting the fourth hole
	       at bit 32!

	       So it ignores everything except 128's, when they're aligned
	       properly.  */

        longword = *longword_ptr++;

        if ((longword - lomagic) & himagic)	{
	        /* Which of the bytes was the zero?  If none of them were, it was
	           a misfire; continue the search.  */

	        const char *cp = (const char *) (longword_ptr - 1);

	        char_ptr = cp;
	        if (cp[0] == 0)
	            break;
	        char_ptr = cp + 1;
	        if (cp[1] == 0)
	            break;
	        char_ptr = cp + 2;
	        if (cp[2] == 0)
	            break;
	        char_ptr = cp + 3;
	        if (cp[3] == 0)
	            break;
	        if (sizeof (longword) > 4) {
	            char_ptr = cp + 4;
	            if (cp[4] == 0)
		            break;
	            char_ptr = cp + 5;
	            if (cp[5] == 0)
		            break;
	            char_ptr = cp + 6;
	            if (cp[6] == 0)
		            break;
	            char_ptr = cp + 7;
	            if (cp[7] == 0)
		            break;
	          }
	    }
        char_ptr = end_ptr;
    }

    if (char_ptr > end_ptr)
        char_ptr = end_ptr;
    return char_ptr - str;
}
