ChangeLog
=========


2019-11-20 (3.12.1)
-------------------

* Update spec file for F31 and Centos/RHEL 8
* Gitlab CI


2019-03-18 (3.12.0)
-------------------

* CMake fixes
* Autotools removal
* License GNU GPLv3+


2018-11-20 (3.11.0)
-------------------

* CMake build
* COPR build
* AUTHORS file update


2016-09-12 Jan Zima, Zuzana Ansorgova (3.10.2)
----------------------------------------------

* Build fix (gcc 6.1.1)
* Configuration documentation


2016-03-21 Jaromir Talir (3.10.1)
---------------------------------

* Fix rpm build


2014-06-12 Jan Korous (3.10.0)
------------------------------

* build adapted to idl changes (separation of common types)


2013-10-09 Jiri Sadek (3.9.0)
-----------------------------

* Hide data of contact not linked to other object (also used for not linked mojeid contacts), message changed


2013-08-14 Zdeněk Böhm (3.8.0)
------------------------------

* Removed artificial status 'paid and in zone' from domain info output


2013-07-16 Jaromir Talir (3.7.1)
--------------------------------

* fix in Fedora 19 dependancies


2013-06-07 Jaromir Talir (3.7.0)
--------------------------------

* allow compilation with both apache 2.2 and 2.4


2012-09-06 Jiri Sadek, Juraj Vicenik, Jan Zima (3.6.0)
------------------------------------------------------

* logger - removed output flag from properties interface
* mojeid contacts display is now based on dedicated contact state rather than registrar name


2012-06-15 Jaromir Talir (3.5.0)
---------------------------------

* fixing unit tests
* fixing some build process and dependencies


2011-05-20 Juraj Vicenik, Vit Vomacko (3.4.0)
---------------------------------------------

* Logger fixing uninitialized parameters
* re-add object specific tests to testsuite


2011-03-11 Jan Zima (3.3.1)
---------------------------

* whois tests install fix


2011-02-24 Jan Zima (3.3.0)
---------------------------

* renaming due whois idl interface split (separate interface now)


2010-11-24 Juraj Vicenik, Jan Zima (3.2.5)
------------------------------------------

* mojeid contacts display fix
* bugfixes (missing initialization, double free)


2010-10-18 Juraj Vicenik (3.2.4)
--------------------------------

* Implemented refactored logging interface


2010-06-21 Jiri Sadek (3.2.3)
-----------------------------

* Project configuration changes


2010-04-29 Jaromir Talir (3.2.2)
--------------------------------

* Added missing autotools files


2010-03-12 Juraj Vicenik (3.2.1)
--------------------------------

* bugfixes
* Logger usage is not mandatory


2010-02-16 Juraj Vicenik (3.2.0)
----------------------------------------

* Audit (Logger client) component integration


2009-02-05 Juraj Vicenik (version 3.1.1)
----------------------------------------

* Added glue information (ip adresses) to nameservers


2008-10-19 Juraj Vicenik (version 3.1.0)
----------------------------------------

* DNSKEY record detail updated


2008-09-19 Juraj Vicenik (version 3.0.1)
----------------------------------------

* DS record detail updated
* testing support


2008-08-15 Juraj Vicenik (version 3.0.0)
----------------------------------------

* DNSSEC keyset object support


2008-06-20 Jaromir Talir (version 2.2.0)
----------------------------------------

* Minor configuration and build enhancments


2008-02-08 Jiri Sadek (version 2.1.0)
-------------------------------------

* Release 2.1.0


2008-01-12 Jaromir Talir
------------------------

* RPM support added and other small autotools changes


2008-01-10 Jiri Sadek
---------------------

* Automake support and autoconf somewhat rewritten
* Log message after successfuly initialization uniformalized with other modules


2007-11-07 Jan Kryl (version 2.0.5)
-----------------------------------

* New configure option --with-idldir.
* Bug which led to SEGFAULT in whois option parser fixed.


2007-10-10 Jan Kryl (version 2.0.4)
-----------------------------------

* URL pointing to detailed description of whois implementation added to usage message.
* Basic set of unittests is ready.


2007-10-02 Jan Kryl (version 2.0.3)
-----------------------------------

* Characters in request must be in interval from 32 to 126 (printable ASCII).
* Code handling exceptional cases was redesigned.
* New whois error 108 "invalid request" introduced.


2007-10-01 Jan Kryl (version 2.0.2)
-----------------------------------

* Email of object registrar is not displayed in whois output.
* Updated copyright URL.


2007-09-27 Jan Kryl (version 2.0.1)
-----------------------------------

* mod_whoisd crashed apache when there were more than 2 search keywords, which is invalid usage. This condition
  now triggers response with usage information.


2007-09-26 Jan Kryl (version 2.0.0)
-----------------------------------

* Major code rewrite to fit new specification (see README) for whois.
* Whois gives information for objects domains, nssets, contacts and registrars in classic forward and reverse manner.
* IDL interface was completely changed from Whois.idl to Admin.idl.
* Server side options were implemented.
* Disclaimer changed.
* Whois test program is no more maintained and was deleted.


2007-09-19 Jan Kryl (version 1.3.2)
-----------------------------------

* Fix bashism in Makefile (output redirection).


2007-06-11 Jan Kryl (version 1.3.2)
-----------------------------------

* Enhancement of configure script.
* Better documentation.


2007-03-21 Jan Kryl (version 1.3.1)
-----------------------------------

* Change of CORBA nameservice context from old ccReg to new Fred.
* Subtle changes in test program test.py.


version 1.3.0
-------------

* New reference manager mod_corba was added, mod_whoisd was adapted to changed reference
  management policy. Now each connection has its own unique CORBA reference.

* As a side effect of changes in reference management code, the apache can be started without
  omninames running. The object references are obtained and resolved upon request arrival.


version 1.2.0
-------------

* In IDL was added flag 'enum' which tells if it is enum domain or not. A link to web site is displayed only if this flag is false.
