#!/bin/bash
if [ $KVERSION ];then
    grep "struct ring_buffer *;" /lib/modules/$KVERSION/build/include/linux/ring_buffer.h
else
    grep "struct ring_buffer *;" /lib/modules/`uname -r`/build/include/linux/ring_buffer.h
fi