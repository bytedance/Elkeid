#!/bin/bash
docker build -t scanner -f docker/Dockerfile ../../ 


# check if libclamav_deps-0.104 success

#2022-04-19 11:57:15 Mussels INFO Successful build of libz-1.2.12 completed in 0:00:19.603455.
#2022-04-19 11:57:15 Mussels INFO Successful build of libbz2-1.1.0 completed in 0:00:13.905545.
#2022-04-19 11:57:15 Mussels INFO Successful build of libjson_c-0.15.0 completed in 0:00:12.207074.
#2022-04-19 11:57:15 Mussels INFO Successful build of libxml2-2.9.13 completed in 0:01:12.586266.
#2022-04-19 11:57:15 Mussels INFO Successful build of libpcre2-10.39 completed in 0:01:00.616148.
#2022-04-19 11:57:15 Mussels INFO Successful build of libopenssl-1.1.1n completed in 0:02:32.163937.
#2022-04-19 11:57:15 Mussels INFO Successful build of libclamav_deps-0.104 completed in 0:00:00.000752.