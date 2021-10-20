#!/bin/bash
grep -A 2 'd_u;' /lib/modules/$KVERSION/build/include/linux/dcache.h | grep -c d_alias;