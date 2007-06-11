/**
 * @file mainpage.h
 *
 * This file contains only the main page of doxygen documentation.
 */

/**
 * @mainpage package mod_whoisd
 *
 * @section overview Overview
 *
 * Purpose of this package is to translate incomming requests in form of
 * traditional whois request to CORBA requests, which are further processed 
 * by central register. And also the way back - translate CORBA responses of
 * central register to whois responses to client. The interface to central
 * register is defined by IDL file.
 *
 * @section config Module's configuration
 *
 * List of configuration directives recognized by mod_whoisd:
 * 
 *   name: WhoisProtocol
 *   - value:        On, Off
 *   - default:      Off
 *   - context:      global config, virtual host
 *   - description:
 *         Activates whois module for this connection. This means that any
 *         data comming from network connection on ip address of virtual host
 *         are assummed to be whois requests.
 *   .
 * 
 *   name: WhoisDisclaimer
 *   - value:        PATH
 *   - default:      none
 *   - context:      global config, virtual host
 *   - description:
 *         File containing comment which preceeds every whois response.
 *         This argument is mandatory. The file is read only once during
 *         startup and then it is cached in memory. Whois comment character
 *         '%' is prepended to every line automatically by module. Those
 *         characters must not be already present in disclaimer file!
 *         Otherwise they would be displayed twice.
 *   .
 * 
 *   name: WhoisWebURL
 *   - value:        URL
 *   - default:      none
 *   - context:      global config, virtual host
 *   - description:
 *         URL is part of a note in whois response, which redirects user
 *         to web whois, in order to get more detailed information about
 *         registrant of domain name. URL is not part of answers for ENUM
 *         domains because of political reasons. This argument is mandatory.
 *   .
 * 
 *   name: WhoisDelay
 *   - value:        number from interval 0..9999
 *   - default:      0
 *   - context:      global config, virtual host
 *   - description:
 *         Number of miliseconds a response to client is deffered
 *         in order to prevent data-mining.
 *   .
 * 
 *   name: WhoisObject
 *   - value:        alias
 *   - default:      Whois
 *   - context:      global config, virtual host
 *   - description:
 *         Alias under which is exported corba object reference from mod_corba
 *         module.
 *   .
 * 
 * File httpd-whois.conf is example of mod_whoisd's configuration.
 *
 * @section make Building and installing the module
 *
 * Module comes with configure script, which should hide differences
 * among Fedora, Gentoo, Debian and Ubuntu linux distributions. Other
 * distribution let alone UNIX-like operating systems where not tested.
 * The following parameters in addition to standard ones are recognized
 * by the configure script:
 *
 *     - --with-idl             Location of IDL file.
 *     .
 * Following options doesn't have to be ussualy specified since tools'
 * location is automatically found by configure in most cases:
 *
 *     - --with-apr-config      Location of apr-config tool.
 *     - --with-apxs            Location of apxs tool.
 *     - --with-orbit-idl       Location of ORBit IDL compiler.
 *     - --with-pkg-config      Location of pkg-config tool.
 *     - --with-doc             Location of doxygen if you want to generate documentation.
 *     .
 *
 * The installation directories are not taken into account. The installation
 * directories are given by apxs tool.
 *
 * The module is installed by the traditional way: ./configure && make && make
 * install. The module is installed in directory where other apache modules
 * reside.
 *
 * @section trouble Troubleshooting
 *
 * There is apache's log file where mod_whoisd puts log messages.
 * If you can't localize error by log and source code inspection there is a
 * test program "whois_test". This binary is easy to debug in gdb and in 80%
 * of cases are the bugs from mod_whoisd reproducible by this simplified
 * binary. If you decided to use gdb, don't forget to configure mod_whoisd
 * with CFLAGS='-g -O0'.
 *
 * The test utility returns just a status for each domain listed on a command
 * line.
 */
