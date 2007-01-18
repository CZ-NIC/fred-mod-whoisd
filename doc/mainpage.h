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
 *
 * Example configuration suited for production might look like this:
 *
 @verbatim
 #
 # mod_whoisd virtual host
 #
 Listen 43      # Whois port, assigned by IANA
 LoadModule whoisd_module modules/mod_whoisd.so
 <VirtualHost 192.168.2.1:43>
   WhoisProtocol     On
   WhoisDisclaimer   "/etc/apache2/disclaimer.txt"
   WhoisWebURL       "http://whois.nic.cz/"
   WhoisDelay        400
   WhoisObject       "Whois"
 </VirtualHost>
 @endverbatim
 *
 * Note that configuration of mod_corba module must be part of virtual host's
 * configuration.
 */
