#!/bin/bash
if [ -f "/lib/modules/$KVERSION/build/include/linux/dcache.h" ];then
  grep -A 2 'd_u;' /lib/modules/$KVERSION/build/include/linux/dcache.h | grep -c d_alias;
else
  grep -A 2 'd_u;' /usr/src/kernels/$KVERSION/include/linux/dcache.h | grep -c d_alias;
fi