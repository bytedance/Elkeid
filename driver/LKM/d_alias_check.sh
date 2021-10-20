#!/bin/bash
grep -A 2 'd_u;' $KERNEL_DIR/include/linux/dcache.h | grep -c d_alias;