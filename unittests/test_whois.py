#!/usr/bin/env python
#
# vim:ts=4 sw=4:

'''
Unittests for unix whois.

Here is a hierarchy of test suites and test cases:

whois_suite
	|-- LongRequest
	|-- NotCRLF
	|-- InvalidChar
	|-- ManyArguments
	|-- FlagRecursive
	|
	|-- FlagType
	|		|-- test_domain
	|		|-- test_nsset
	|		|-- test_contact
	|		|-- test_registrar
	|		|-- test_unknowntype
	|
	|-- FlagInverse
	|		|-- test_registrant
	|		|-- test_admin_c
	|		|-- test_temp_c
	|		|-- test_nsset
	|		|-- test_nserver
	|		|-- test_tech_c
	|		|-- test_unknowninverse
	|
	|-- FlagQuery
	|		|-- test_version
	|		|-- test_indexes
	|		|-- test_templates
	|		|-- test_withother

See comments in appropriate classes and methods for more information
about their operation. General description follows. For inserting
and deleting test data from central register we use epp_client (EPP protocol).
The changes made by this unittest are not reversible! Because the EPP
operations remain in a history and may influence result of some operations in
future. So it must be run on test instance of central register. The tests
are specific for '.cz' zone and won't work with other zones.
'''

import commands, ConfigParser, sys, getopt, os, re, random, os, socket
import pgdb
import unittest

MAX_REQLEN = 1000
BUFFSIZE   = 64000

def usage():
	print '%s [-v LEVEL | --verbose=LEVEL]' % sys.argv[0]
	print
	print 'verbose level number is handed over to unittest function as it is.'
	print

class Answer(object):
	def __init__(self, str):
		'''
		Process whois answer.
		'''
		self.comment = ''
		self.objects = []
		self.error = None
		self.error_text = ''
		obj_record = False
		obj_type = None
		obj_lines = ''
		for line in str.split('\r\n'):
			if line.startswith('% '):
				#print 'checkpoint 1'
				obj_record = False
				self.comment += line + '\n'
			elif line.startswith('%ERROR:'):
				#print 'checkpoint 2'
				obj_record = False
				self.error = int(line[7:10])
				self.error_text = line[12:]
			elif not line:
				#print 'checkpoint 3'
				if obj_record:
					break;
				obj_record = True
				if obj_type:
					if obj_type == type(Domain):
						self.objects.append(Domain(obj_lines))
					elif obj_type == type(Nsset):
						self.objects.append(Nsset(obj_lines))
					elif obj_type == type(Contact):
						self.objects.append(Contact(obj_lines))
					elif obj_type == type(Registrar):
						self.objects.append(Registrar(obj_lines))
					obj_type = None
			else:
				#print 'checkpoint 4'
				obj_record = False
				if not obj_type:
					if line.startswith('domain'):
						obj_type = type(Domain)
					elif line.startswith('nsset'):
						obj_type = type(Nsset)
					elif line.startswith('contact'):
						obj_type = type(Contact)
					elif line.startswith('registrar'):
						obj_type = type(Registrar)
					else:
						raise Exception('Unknown object type: %s' % line)
				obj_lines += line + '\n'

	def __str__(self):
		str = ''
		str += 'Error: %s\n' % self.error
		if self.error:
			str += 'Error text: %s\n' % self.error_text
		str += 'Count of objects: %d\n' % len(self.objects)
		return str


def getval(key, pattern, input, mustbe = True, list = False):
	pattern = '^' + key + ':' + '\s+(' + pattern + ')$'
	result = re.compile(pattern, re.MULTILINE).search(input)
	if not result or len(result.groups() == 0):
		if mustbe:
			raise Exception('Mandatory argument missing\n%s\n%s' %
					(pattern, input))
		if list: return []
		else: return None
	elif len(result.groups()) == 1:
		if list: return [ result.groups()[0] ]
		else: return result.groups()[0]
	else:
		if list: return [ item for item in result.groups() ]
		else: raise Exception('Expected 1 value and got %d values\n%s\n%s' %
				(len(result.groups()), pattern, input))

def gettimeval(key, input, mustbe = True, list = False):
	datpat = '\d\d\.\d\d\.\d\d\d\d \d\d:\d\d:\d\d'
	return time.strptime(
			getval(key, datpat, input, mustbe, list), '%d.%m.%Y %H:%M:%S')

class Domain(object):
	def __init__(self, str):
		self.domain = getval('domain', '[a-zA-Z0-9]+\.cz', str)
		self.registrant = getval('registrant', '[^\W]+', str, mustbe=False)
		self.admin_c = getval('admin-c', '[^\W]+', str, mustbe=False, list=True)
		self.temp_c = getval('temp-c', '[^\W]+', str, mustbe=False, list=True)
		self.nsset = getval('nsset', '[^\W]+', str, mustbe=False)
		self.registrar = getval('registrar', '[^\W]+', str)
		self.status = getval('status', '.+', str, mustbe=False, list=True)
		self.registered = gettimeval('registered', str)
		self.changed = gettimeval('changed', str, mustbe=False)
		self.expire = gettimeval('expire', str)
		self.validated_to = gettimeval('validated-to', str, mustbe=False)

class Nsset(object):
	def __init__(self, str):
		self.nsset = getval('nsset', '[^\W]+', str)
		self.nserver = getval('nserver', '([a-zA-Z0-9]+\.?)+', str, list=True)
		self.tech_c = getval('tech-c', '[^\W]+', str, list=True)
		self.registrar = getval('registrar', '[^\W]+', str)
		self.created = gettimeval('created', str)
		self.changed = gettimeval('changed', str, mustbe=False)

class Contact(object):
	def __init__(self, str):
		self.contact = getval('contact', '[^\W]+', str)
		self.org = getval('org', '.+', str, mustbe=False)
		self.name = getval('name', '.+', str)
		self.address = getval('address', '.+', str, list=True)
		self.phone = getval('phone', '.+', str, mustbe=False)
		self.fax_no = getval('fax-no', '.+', str, mustbe=False)
		self.e_mail = getval('e-mail', '[^\W]+', str)
		self.registrar = getval('registrar', '\w+', str)
		self.created = gettimeval('created', str)
		self.changed = gettimeval('changed', str, mustbe=False)

class Registrar(object):
	def __init__(self, str):
		self.registrar = getval('registrar', '[^\W]+', str)
		self.org = getval('org', '.+', str)
		self.url = getval('url', 'http://[^\W]+', str)
		self.phone = getval('phone', '.+', str, mustbe=False)
		self.address = getval('address', '.+', str, list=True)


class NotObjectSpecificTests(unittest.TestCase):
	'''
	The class gathers tests which are not object specific.
	'''

	def setUp(self):
		'''
		Connect to whois server.
		'''
		self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.s.connect(('localhost', 43))

	def tearDown(self):
		self.s.close()

	def test_longRequest(self):
		'''
		Send long request.
		'''
		self.s.send('x' * MAX_REQLEN + '\r\n')
		rawans = self.s.recv(BUFFSIZE)
		ans = Answer(rawans)
		self.assertEqual(ans.error, 108, 'Too long request not detected\n%s' %
				ans)

	def test_notCRLF(self):
		'''
		Send request not terminated by CR LF.
		'''
		self.s.send('domena.cz' + '\n')
		rawans = self.s.recv(BUFFSIZE)
		ans = Answer(rawans)
		self.assertEqual(ans.error, 108, 'Not properly terminated request '
				'not detected\n%s' % ans)

	def test_invalidChar(self):
		'''
		Send invalid char in domain name.
		'''
		self.s.send('domeína.cz' + '\n')
		rawans = self.s.recv(BUFFSIZE)
		ans = Answer(rawans)
		self.assertEqual(ans.error, 108, 'Invalid char in request not '
				'detected\n%s' % ans)


if __name__ == '__main__':
	# parse command line parameters
	try:
		(opts, args) = getopt.getopt(sys.argv[1:], 'v:', ['verbose='])
	except getopt.GetoptError:
		usage()
		sys.exit(2)
	level = 2 # default verbose level
	for o,a in opts:
		if o in ('-v', '--verbose'):
			level = int(a)

	# put together test suite
	whois_suite = unittest.TestLoader().loadTestsFromTestCase(NotObjectSpecificTests)
	#fm_suite.addTest(SearchTest())

	# Run unittests
	unittest.TextTestRunner(verbosity = level).run(whois_suite)
