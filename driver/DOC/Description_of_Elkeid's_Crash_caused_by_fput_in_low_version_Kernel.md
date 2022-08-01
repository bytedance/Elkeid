# Description of the problem that Elkeid causes Crash on low version Kernel (Fixed)

### 影响范围
小于 Linux Kernel 3.6 的内核会受到影响。
RHEL系仅影响RHEL6(Kernel Version 2.6.32)。


### 情况说明
重启的直接原因是内核的 BUGON 检测所触发，即 `fs/buffer.c L1298: BUGON(irqs_disabled())`。
Elkeid 在 `security_inode_create_pre_handler` 中使用了内核 API 函数 `fput()` ，但 `fput()` 在低版本（Kernel 小于 3.6）存在竞争条件问题，即可能存在多个线程操作同一个文件句柄的情况，在某些正好满足竞争条件的情况下（atomic_long_dec_and_test 为 True），`fput()` 会进一步触发 i/o 操作（ext4文件系统：`ext4_release_file`），结合 Elkeid 上下文（较旧内核中采用的是int 3断点方式），并最终触发上述的 BUGON 条件。该问题需要某些特殊的竞争态条件下才可被触发。
相关内核代码：
[](https://elixir.bootlin.com/linux/v2.6.32/source/fs/file_table.c#L227)
[](https://elixir.bootlin.com/linux/v2.6.32/source/fs/file_table.c#L281)

`fput()` 的实现在3.6内核对此问题进行了修复，全部改成了异步操作，从而规避了些竞争问题，具体讨论：[](https://lwn.net/Articles/494158/)

具体commit：[](https://github.com/torvalds/linux/commit/4a9d4b024a3102fc083c925c242d98ac27b1c5f6)，所以3.6 及之后的内核是没有此竞争问题。


### 修复情况
Elkeid 已针对存在该问题的低版本内核进行规避：[](https://github.com/bytedance/Elkeid/pull/270)


### 其他受该问题影响场景
受此低版本内核问题影响的其他场景还有（部分）：

ima-appraisal patches*：
[](https://lwn.net/Articles/494173/)
SELinux：[](http://realtechtalk.com/Kernel_panic_not_syncing_Attempted_to_kill_init_Pid_1comm_init_Tained_GI2632358el6x86_64_1_Call_Trace_%5Bfffffff8150cfc8%5D_panic0xa00x16f_%5Bfffffff81073ae2%5D_do_exit0x8620x870_%5Bfffffff81182885%5D_fput0x250-1344-articles)
SELinux：
[](https://elixir.bootlin.com/linux/v3.4.113/source/security/selinux/hooks.c#L2240)
BUGON：
[](https://www.spinics.net/lists/kernel/msg1622221.html)