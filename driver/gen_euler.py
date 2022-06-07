
vauled_version = ["2.0", "2.0SP3", "2.1", "2.2", "2.3", "2.5", "2.9"]

euler_source = """[base{}]
name=EulerOS-{}
baseurl=http://mirrors.huaweicloud.com/euler/{}/os/x86_64/
enabled=1
gpgcheck=1
gpgkey=http://mirrors.huaweicloud.com/euler/{}/os/RPM-GPG-KEY-EulerOS"""


for each_version in vauled_version:
    f = open("/etc/yum.repos.d/euleros{}.repo".format(each_version), "w")
    f.write(euler_source.format(each_version,
            each_version, each_version, each_version))
    f.close()
