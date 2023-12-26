/* SPDX-License-Identifier: GPL-2.0 */

#define PROC_FILE_HOOK 700
#define SYSCALL_HOOK 701
#define LKM_HIDDEN 702
#define INTERRUPTS_HOOK 703


SD_XFER_DEFINE( NAME(fops),

                PROT(ELEMENT(char *, name)),

                XFER(ENTRY_XID(PROC_FILE_HOOK),
                     ENTRY_STL(name, name, MODULE_NAME_LEN))
)

SD_XFER_DEFINE( NAME(syscall),

                PROT(ELEMENT(char *, name), ELEMENT(int, scid)),

                XFER(ENTRY_XID(SYSCALL_HOOK),
                     ENTRY_STL(name, name, MODULE_NAME_LEN),
                     ENTRY_INT(scid, scid))
)

SD_XFER_DEFINE( NAME(mod),

                PROT(ELEMENT(char *, name)),

                XFER(ENTRY_XID(LKM_HIDDEN),
                     ENTRY_STL(name, name, MODULE_NAME_LEN))
)

#if IS_ENABLED(CONFIG_X86)
SD_XFER_DEFINE( NAME(interrupts),

                PROT(ELEMENT(char *, name), ELEMENT(int, intno)),

                XFER(ENTRY_XID(INTERRUPTS_HOOK),
                     ENTRY_STL(name, name, MODULE_NAME_LEN),
                     ENTRY_INT(intno, intno))
)
#endif