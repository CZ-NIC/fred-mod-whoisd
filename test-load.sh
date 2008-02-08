#!/bin/sh

# This test script issues all types of queries to whois server. All types
# of queries compose one round and number of rounds is configureable.
# This test is used for detecting memory leaks. If the size of apache grows
# when test is running, then there is probably a memory leak in whois
# module, which must be located by more sofisticated tool (e.g. valgrind).
# It is recommended to run the test several hours, so that the memory leak
# gets visible.

# Desription of test suite (all command use recursive search):
#   1a) Lookup $DOMAIN with no type specification
#   1b) Lookup $NSSET with no type specification
#   1c) Lookup $CONTACT with no type specification
#   1d) Lookup $REGISTRAR with no type specification
#   2a) Lookup $DOMAIN with correct type specification
#   2b) Lookup $NSSET with correct type specification
#   2c) Lookup $CONTACT with correct type specification
#   2d) Lookup $REGISTRAR with correct type specification
#   3a) Lookup $DOMAIN by domain:registrant index
#   3b) Lookup $DOMAIN by domain:admin-c index
#   3c) Lookup $DOMAIN by domain:temp-c index
#   3d) Lookup $DOMAIN by domain:nsset index
#   3e) Lookup $NSSET by nsset:nserver index
#   3f) Lookup $NSSET by nsset:tech-c index
#   4a) Use whois with invalid parameter (prints usage)
#   4b) Ask whois server for its version
#   4c) Ask whois server for possible indexes for reverse search
#   4d) Ask whois server for object templates
#

# General configuration
WHOIS=whois
HOST=localhost
ROUNDS=100
ROUNDS_INIT=$ROUNDS
VERBOSE=1

# Testing data
DOMAIN=TEST.CZ
NSSET=NSSID:TEST
CONTACT=CID:FEELA
REGISTRAR=REG-UNITTEST1
REGISTRANT=CID:SURY-CZ.NIC
ADMIN_C=$CONTACT
TEMP_C=$CONTACT
NS=A.NS.NIC.CZ
TECH_C=$REGISTRANT


WHOIS_CMD="$WHOIS -h $HOST"

function rw() {
	$WHOIS_CMD " $1" >/dev/null 2>&1
	if [ $? -ne 0 ]
	then
		echo "Whois command exited with error status (round $ROUNDS)"
		exit 1
	fi
}


#
# main
#
if [ $# -gt 0 ]
then
	ROUNDS=$1
    ROUNDS_INIT=$ROUNDS
fi

MEM_PRE=`ps axo comm,vsz | grep apache | awk 'BEGIN { max = 0; } { if ( $2 > max ) max = $2; } END { print max; }'`

while [ $ROUNDS -gt 0 ]
do
    tmp=`expr $ROUNDS % 10`;
    if [ $VERBOSE -eq 1 ]; then
        if [ $tmp -eq 0 ]; then echo -n -e "Rounds left: $ROUNDS (total: $ROUNDS_INIT)              \r"; fi;
    fi
	# Test set 1
	rw " $DOMAIN"
	rw " $NSSET"
	rw " $CONTACT"
	rw " $REGISTRAR"
	# Test set 2
	rw " -T domain  $DOMAIN"
	rw " -T nsset   $NSSET"
	rw " -T contact $CONTACT"
	rw " -T registrar  $REGISTRAR"
	# Test set 3
	rw " -i registrant $REGISTRANT"
	rw " -i admin-c $ADMIN_C"
	rw " -i temp-c  $TEMP_C"
	rw " -i nsset   $NSSET"
	rw " -i nserver $NS"
	rw " -i tech-c  $TECH_C"
	# Test set 4
	rw " -q invalid"
	rw " -q version"
	rw " -q indexes"
	rw " -q templates"

	ROUNDS=`expr $ROUNDS - 1`
done

MEM_POST=`ps axo comm,vsz | grep apache | awk 'BEGIN { max = 0; } { if ( $2 > max ) max = $2; } END { print max; }'`

echo "Memory usage of apache increased by " `expr $MEM_POST - $MEM_PRE` "KB"
echo "  (before $MEM_PRE and after $MEM_POST)."
