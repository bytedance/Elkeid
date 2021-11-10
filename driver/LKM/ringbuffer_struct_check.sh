#!/bin/bash
if [ $KVERSION ];then
    grep -hs "struct ring_buffer *;" /lib/modules/$KVERSION/build/include/linux/ring_buffer.h /lib/modules/$KVERSION/source/include/linux/ring_buffer.h
else
    grep -hs "struct ring_buffer *;" /lib/modules/`uname -r`/build/include/linux/ring_buffer.h /lib/modules/`uname -r`/source/include/linux/ring_buffer.h
fi
