#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.
# vim: set ts=4 sw=4:

AC_PREREQ(2.59)
AC_INIT([fred-mod-whoisd], 3.5.0, [], [fred-mod-whoisd])
AC_CONFIG_SRCDIR([mod_whoisd.c])
AC_CONFIG_MACRO_DIR([m4])

AH_TOP([#include "unconfig.h" /* why this? See comment in unconfig.h */])

### function to check if APACHE_LIBEXECDIR path contain one or more 
### 'lib' part
### this is bug(feature) on some distributions (e.g. arch) where
### directory for apache modules is /usr/lib/apache. On distros like
### debian, fedora this directory is /usr/lib/apache/1.3 (debian)
### and /usr/lib/httpd/modules. So on debian and fedora code to
### create APACHE_LIBEXECDIR works fine, but on that 'weird' distros
### it produce result like /usr/lib/lib/apache, and that is wrong
AC_DEFUN([AC_CHECK_LIBEXECDIR],
[
 #count number of lib parts in string
 count=`echo $APACHE_LIBEXECDIR | sed 's/\//\n/g' | grep -c 'lib'`
 if test "$count" -gt "1"; then
     #lets trim only last one part (e.g. on arch remain only 'apache')
     APACHE_LIBEXECDIR=${LIBRARYDIR}${APACHE_LEDIR##${APACHE_LEDIR%/*}};
 fi
])

### place where mod_whoisd.so is installed
AC_DEFUN([AC_CREATE_MODULE_INSTALLDIR],
[
 module_installdir=$APACHE_LIBEXECDIR
 AC_SUBST([MODULE_INSTALLDIR], [$module_installdir])
])


# doxygen
DX_HTML_FEATURE(ON)
DX_CHM_FEATURE(OFF)
DX_CHI_FEATURE(OFF)
DX_MAN_FEATURE(OFF)
DX_RTF_FEATURE(OFF)
DX_XML_FEATURE(OFF)
DX_PDF_FEATURE(OFF)
DX_PS_FEATURE(OFF)
DX_INIT_DOXYGEN(fred-mod-whoisd, doxy.conf, [doc])

# init automake
AM_INIT_AUTOMAKE([-Wall -Werror])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_EGREP
AC_PROG_AWK
AC_PROG_INSTALL
AM_PROG_LIBTOOL

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE

# Check for orbit2
AM_PATH_ORBIT2([2.0.0],[],[AC_MSG_ERROR([missing orbit2 header files.])])
AX_PATH_ORBIT2_COSNAME()

# check apxs tool
AX_WITH_APXS([no],[${PATH}:/usr/local/bin:/usr/local/sbin:/usr/sbin:/sbin])
if test "$APXS" = "no"; then
    AC_MSG_ERROR([apxs executable does not exist (use --with-apxs)])
fi
# check for ap_release.h
# if present we have a apache 2.0.x and greater (in lower it's not included)
# syntax of \#define AP_SERVER_MAJORVERSION differ in minor versions
APXS_INCDIR="`${APXS} -q INCLUDEDIR`"
AC_CHECK_FILE([$APXS_INCDIR/ap_release.h],
              [AC_MSG_NOTICE([apache version >=2.0.x found])],
              [AC_MSG_ERROR([apache version >=2.0.x not found.])])

# check apr-config
AC_ARG_WITH([apr-config], [AC_HELP_STRING([[--with-apr-config]],
                          [location of apr-config executable])],
                          [apr_config="$with_val"],
                          [AC_PATH_PROGS([apr_config], 
                          [apr-config apr-0-config apr-1-config], [no],
                          [$PATH:/usr/sbin/:/usr/local/apache2/bin])])
if test "$APR_CONFIG" = "no"; then
    AC_MSG_ERROR([apr-config executable "$APR_CONFIG" does not exist (use --with-apr-config)])
fi
$apr_config --cppflags &> /dev/null
if test "$?" != "0"; then
    AC_MSG_ERROR([$apr_config is not valid apr-config executable])
fi

# set apache flags
APACHE_CFLAGS="-I`${APXS} -q INCLUDEDIR` -I`${apr_config} --includedir`"
APACHE_CPPFLAGS="`${apr_config} --cppflags`"
AC_SUBST(APACHE_CFLAGS)
AC_SUBST(APACHE_CPPFLAGS)

#set apache module path
#hack: replacing lib-part of dir with ${libdir} to support prefix install
APACHE_LEDIR=`${APXS} -q LIBEXECDIR`
AS_AC_EXPAND([LIBRARYDIR], [$libdir])
APACHE_LIBEXECDIR=${LIBRARYDIR}${APACHE_LEDIR##${APACHE_LEDIR%/*/*}};

AC_CHECK_LIBEXECDIR()

AC_SUBST(APACHE_LIBEXECDIR)

AC_CREATE_MODULE_INSTALLDIR()

AS_AC_EXPAND([DATAROOTDIR], [$datarootdir])

# check IDL dir
AC_ARG_WITH([idldir], [AS_HELP_STRING([--with-idldir],
                        [Directory with idl [DATAROOTDIR/idl/fred/]])],
                        [AC_SUBST([IDLDIR], [$withval])],
                        [AC_SUBST([IDLDIR], [$DATAROOTDIR/idl/fred/])])

# unittests
AC_ARG_WITH([unittests], [AS_HELP_STRING([--with-unittests], 
			[Whether to include unittests [default=no]])],
			[case "${withval}" in 
				yes) UNITTESTS=true;;
				no) UNITTESTS=false;;
				*)  AC_MSG_ERROR(bad value ${withval} for --with-unittests);;
			esac],
			[with_unittests=true])

AC_MSG_NOTICE([ -------variable UNITTESTS value : $UNITTESTS ])

AM_CONDITIONAL(WITH_UNITTESTS, test x$UNITTESTS = xtrue)

#whois port
AC_ARG_WITH([port], [AS_HELP_STRING([--with-port],
            [Port where mod_whoisd listen [43]])],
            [AC_SUBST([PORT], [$withval])],
            [AC_SUBST([PORT], [43])])

#nameservice host
AC_ARG_WITH([nshost], [AS_HELP_STRING([--with-nshost],
            [Location of CORBA nameservice host (host[:port]) [localhost]])],
            [AC_SUBST([NSHOST], [$withval])],
            [AC_SUBST([NSHOST], [localhost])])

#whois object name
AC_ARG_WITH([whois_objectname], [AS_HELP_STRING([--with-whois-objectname],
            [Name of whois object [Whois]])],
            [AC_SUBST([OBJECTNAME], [$withval])],
            [AC_SUBST([OBJECTNAME], [Whois])])

#logger object name
AC_ARG_WITH([logger_objectname], [AS_HELP_STRING([--with-logger-objectname],
            [Name of logger object [Logger]])],
            [AC_SUBST([LOGGER_OBJECTNAME], [$withval])],
            [AC_SUBST([LOGGER_OBJECTNAME], [Logger])])

# check IDL files
AC_CHECK_FILE(
	[$IDLDIR/_dataTypes.idl],
	[],
	[AC_MSG_ERROR(
		[directory "$IDLDIR" does not contain _dataTypes.idl
		(use --with-idldir)]
	)]
)

AC_CHECK_FILE(
	[$IDLDIR/Filters.idl],
	[],
	[AC_MSG_ERROR(
		[directory "$IDLDIR" does not contain Filters.idl
		(use --with-idldir)]
	)]
)

AC_CHECK_FILE(
	[$IDLDIR/Admin.idl],
	[],
	[AC_MSG_ERROR(
		[directory "$IDLDIR" does not contain Admin.idl
		(use --with-idldir)]
	)]
)

AC_CHECK_FILE(
	[$IDLDIR/Registry.idl],
	[],
	[AC_MSG_ERROR(
		[directory "$IDLDIR" does not contain Registry.idl
		(use --with-idldir)]
	)]
)

AC_CHECK_FILE(
	[$IDLDIR/Whois.idl],
	[],
	[AC_MSG_ERROR(
		[directory "$IDLDIR" does not contain Whois.idl
		(use --with-idldir)]
	)]
)

AC_CHECK_FILE(
	[$IDLDIR/Logger.idl],
	[],
	[AC_MSG_ERROR(
		[directory "$IDLDIR" does not contain Logger.idl
		(use --with-idldir)]
	)]
)


# check svn revision (if available)
AC_SUBST([SVNREV], [unknown])
AC_MSG_NOTICE([trying to get svn revision])
AC_PATH_PROG([SVN], [svn], [false])
if test "$SVN" != "false"; then
	AC_CHECK_FILE([.svn], [AC_SUBST([SVNREV],
				  [`$SVN info | $EGREP Revision |  $AWK '{ print $2;};'`])])
	AC_MSG_CHECKING([SVN revision])
	AC_MSG_RESULT([$SVNREV])
else
	AC_MSG_CHECKING([SVN revision])
	AC_MSG_RESULT([$SVNREV])
fi
AC_DEFINE_UNQUOTED([SVN_REV], [["]$SVNREV["]], [SVN revision])

# finalization
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile
		 fred-mod-whoisd.spec
         conf/02-fred-mod-whoisd-apache.conf
         unittests/test_whois.py])
AC_OUTPUT
