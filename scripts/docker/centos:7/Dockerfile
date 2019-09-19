FROM centos/devtoolset-7-toolchain-centos7
USER root

RUN yum -y install https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm \
    && yum -y clean all       \
    && yum -y install         \
        redhat-rpm-config     \
        cmake3                \
        make                  \
        git                   \
        gcc                   \
        apr-devel             \
        httpd-devel           \
        ORBit2-devel          \
        doxygen               \
    && rm -rf /var/cache/yum

USER 1001

