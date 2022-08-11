#!/usr/bin/python

# python 2.7.3 only

import requests
import re
import os

version_list = [
    r"3.2.0",
    r"3.5.0",
    r"3.8.0",
    r"3.11.0",
]


def find_all_childs(version_list, data):
    pkgs = [each[0] for each in re.findall(
        r'<a href="(linux-headers-(' + '|'.join(version_list) + ').*_(all|amd64).deb)">linux-headers', data)
    ]
    return pkgs


def download(url, filename):
    os.system("wget -q "+url)


ubuntu_kernel_header_url = "https://old-releases.ubuntu.com/ubuntu/pool/main/l/linux/"

response = requests.get(url=ubuntu_kernel_header_url, verify=False)
page_info = str(response.content)

all_versions = find_all_childs(version_list, page_info)
for each in all_versions:
    download(ubuntu_kernel_header_url+each, each)
    break
