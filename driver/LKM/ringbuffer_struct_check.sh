#!/bin/bash
grep "struct ring_buffer *;" /lib/modules/`uname -r`/build/include/linux/ring_buffer.h