FROM fedora:rawhide
RUN dnf -y clean all                  \
        && dnf -y update              \
        && dnf -y upgrade             \
        && dnf -y install             \
                redhat-rpm-config     \
                cmake                 \
                make                  \
                git                   \
                gcc                   \
                apr-devel             \
                httpd-devel           \
                ORBit2-devel          \
                doxygen
