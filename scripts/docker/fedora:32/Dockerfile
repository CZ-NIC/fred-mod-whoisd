FROM fedora:32

RUN dnf -y install               \
           redhat-rpm-config     \
           cmake                 \
           make                  \
           git                   \
           gcc                   \
           apr-devel             \
           httpd-devel           \
           ORBit2-devel          \
           doxygen               \
    && dnf clean all             \
    && rm -rf /var/cache/yum
