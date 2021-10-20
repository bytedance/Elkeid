#!/bin/bash
if [ -f "$KERNEL_DIR/build/include/linux/dcache.h" ];then
  grep -A 2 'd_u;' $KERNEL_DIR/build/include/linux/dcache.h | grep -c d_alias;
else
  grep -A 2 'd_u;' $KERNEL_DIR/include/linux/dcache.h | grep -c d_alias;
fi