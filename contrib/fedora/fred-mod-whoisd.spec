Name:           %{project_name}
Version:        %{our_version}
Release:        %{?our_release}%{!?our_release:1}%{?dist}
Summary:        FRED - unix whois server as apache module
Group:          Applications/Utils
License:        GPLv3+
URL:            http://fred.nic.cz
Source0:        %{name}-%{version}.tar.gz
Source1:        idl-%{idl_branch}.tar.gz
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildRequires:  git, gcc, apr-devel, httpd-devel, ORBit2-devel, doxygen
%if 0%{?el7}
BuildRequires: centos-release-scl, llvm-toolset-7-cmake, llvm-toolset-7-build
%else
BuildRequires: cmake
%endif
Requires: httpd, fred-mod-corba, checkpolicy, /usr/sbin/semanage, /usr/sbin/sestatus
# Requires checkpolicy in Fedora 19 because of postinstall script that 
# compile  selinux policy

%description
FRED (Free Registry for Enum and Domain) is free registry system for 
managing domain registrations. This package contains apache module that
implements unix whois server. It can listen on port 43 and answer whois
queries. For real work this module communicate with fred-server via 
CORBA technology as provided by mod_corba apache module.

%prep
%setup -b 1

%build
%if 0%{?el7}
%{?scl:scl enable llvm-toolset-7 - << \EOF}
%global __cmake /opt/rh/llvm-toolset-7/root/usr/bin/cmake
%endif
%cmake -DCMAKE_INSTALL_PREFIX=/ -DVERSION=%{version} -DREVISION=%{our_revision} -DIDL_PROJECT_DIR=%{_topdir}/BUILD/idl-%{idl_branch} .
%if 0%{?el7}
%make_build
%else
%cmake_build
%endif
%if 0%{?el7}
%{?scl:EOF}
%endif

%install
rm -rf ${RPM_BUILD_ROOT}
%if 0%{?el7}
%make_install
%else
%cmake_install
%endif
find ${RPM_BUILD_ROOT}/usr/share/doc/ | cut -c$(echo -n "${RPM_BUILD_ROOT} " | wc -c)- > INSTALLED_FILES

%post
test -f /etc/httpd/conf.d/02-fred-mod-whoisd-apache.conf || ln -s /usr/share/fred-mod-whoisd/02-fred-mod-whoisd-apache.conf /etc/httpd/conf.d/
/usr/sbin/sestatus | grep -q "SELinux status:.*disabled" || {
echo "
module httpd_whois 1.0;

require {
	type httpd_t;
	type whois_port_t;
	class tcp_socket name_bind;
}

#============= httpd_t ==============
allow httpd_t whois_port_t:tcp_socket name_bind;
" > /tmp/httpd_whois.te 
/usr/bin/checkmodule -M -m -o /tmp/httpd_whois.mod /tmp/httpd_whois.te > /dev/null 2>&1
/usr/bin/semodule_package -o /tmp/httpd_whois.pp -m /tmp/httpd_whois.mod > /dev/null 2>&1
/usr/sbin/semodule -i /tmp/httpd_whois.pp > /dev/null 2>&1
rm /tmp/httpd_whois.te
rm /tmp/httpd_whois.mod
rm /tmp/httpd_whois.pp
}

%preun
test ! -f /etc/httpd/conf.d/02-fred-mod-whoisd-apache.conf || rm /etc/httpd/conf.d/02-fred-mod-whoisd-apache.conf

%clean
rm -rf ${RPM_BUILD_ROOT}

%files -f INSTALLED_FILES
%defattr(-,root,root,-)
%{_libdir}/httpd/modules/mod_whoisd.so
/usr/share/fred-mod-whoisd/02-fred-mod-whoisd-apache.conf

%changelog
* Sat Jan 12 2008 Jaromir Talir <jaromir.talir@nic.cz>
- initial spec file
