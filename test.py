#!/usr/bin/env python

import commands, sys

set_valid   = ["domain.cz", "super.CZ", "ne-eXistuje.cz",
"0.0.3.2.7.7.2.0.2.4.e164.arpa"]
set_invalid = ["d_in.cz", "dom.cz/", "domain", "dom..cz",
"b.0.3.a.7.7.2.0.2.4.e164.arpa",
"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
"mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmain.cz"]
set_badzone = ["domain.com", "0.0.3.2.7.7.2.3.2.4.e164.arpa"]
set_long    = ["sub.ne-eXistuje.cz"]

testprog   = "./whois_test -h curlew "
verbose    = 0

def vbprint(str):
	if verbose: print str

def test_routine(domain, keywords):
	print "    %s ... " % (domain[0:30]),
	vbprint(testprog + domain)
	rc, output = commands.getstatusoutput(testprog + domain)
	vbprint("return code:    %d" % rc)
	vbprint("program output: %s" % output)
	# check serious failure (ussualy CORBA failure)
	if rc != 0:
		print "failed"
		return 0
	# inspect the output of program
	for key in keywords:
		if output.find(key) != -1:
			print "ok"
			return 1
	print "failed"
	return 0

if __name__ == "__main__":
	# very simple and not correct test for verbose flag
	if len(sys.argv) > 1:
		if sys.argv[1] in ("-v", "--verbose"):
			verbose = 1
		if sys.argv[1] in ("-l", "--list"):
			print "List of all domains which would had been tested:"
			list = set_valid + set_invalid + set_badzone + set_long
			for domain in list: print domain,
			print
			sys.exit()
	print "Start of the test"
	success = 0
	total = 0
	print "Testing valid domains:"
	for domain in set_valid:
		total   += 1
		success += test_routine(domain, ["REGISTERED", "FREE"])
	print "Testing invalid domains:"
	for domain in set_invalid:
		total   += 1
		success += test_routine(domain, ["INVALID"])
	print "Testing domains in bad zone:"
	for domain in set_badzone:
		total   += 1
		success += test_routine(domain, ["BAD ZONE"])
	print "Testing long domains:"
	for domain in set_long:
		total   += 1
		success += test_routine(domain, ["LONG"])
	print "End of the test"
	print
	print "Total number of tests performed: %d" % total
	print "Number of passed tests: %d" % success
	print "Number of failed tests: %d" % (total - success)
