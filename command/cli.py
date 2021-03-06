from __future__ import absolute_import

import argparse

import re
import socket

import dns.query
import dns.tsigkeyring
import dns.update
import dns.reversename
import dns.resolver
from dns.exception import SyntaxError

from config import Config

# Matt's DNS management tool with some improvements
# Manage DNS using DDNS features
#
# See http://planetfoo.org/blog/archive/2012/01/24/a-better-nsupdate/

class Cli(object):
    """
    usage: dnsupdate.py [-h] [-c CONFIG] [-o ZONE] [-x] [-v]

    optional arguments:
    -h, --help            show this help message and exit
    -c CONFIG, --config CONFIG
                            Config file JSON format (Required)
    -o ZONE               Specify the origin. Optional, if not provided origin
                            will be determined
    -x                    Also modify the PTR for a given A or AAAA record.
                            Forward and reverse zones must be on the same server.
    -v                    Print the rcode returned with for each update
    """

    def __init__(self):
        # self.args = ''

        # self.config = ''
        # self.key = ''
        # self.zone = ''
        # self.verbose = ''
        # self.server = ''
        # self.do_ptr = False

        # self.cmd = {}

        # self.address = ''
        # self.name = ''
        # self.ptr = ''
        # self.ttl = ''

        # self.ptr_target = ''
        # self.ptr_zone = ''
        # self.ptr_name = ''
        # self.ptr_update = ''

        # self.update = ''
        # self.response = ''
        # self.ptr_response = ''

        super(Cli, self).__init__()

    def get_args(self):
        """Get arguments

        """

        self.parser = argparse.ArgumentParser(usage='%(prog)s [-h] {-s} {-k} {-z} [-x] {add|delete|update} {Name} {TTL} {Type} {Target}', description='Add, Delete, Replace DNS records using DDNS.')

        self.parser.add_argument('-s', '--server', dest='server', required=True, help='DNS server to update (Required)')
        self.parser.add_argument('-c', '--config', dest='config', required=False, help='Config file JSON format (Required)')
        self.parser.add_argument('--key-file', dest='key_file', required=False, help='TSIG key. The TSIG key file should be in DNS KEY record format. (Required)')
        self.parser.add_argument('--key-name', dest='key_name', required=False, help='The name of the TSIG key to use (Required)')
        self.parser.add_argument('--key-algorithm', dest='key_algorithm', required=False, help='The TSIG algorithm to use; defaults to dns.tsig.default_algorithm.')
        self.parser.add_argument('--key-secret', dest='key_secret', required=False, help='The TSIG algorithm to use; defaults to dns.tsig.default_algorithm.')
        self.parser.add_argument('-z', '--zone', dest='zone', required=True, help='Specify the origin. Optional, if not provided origin will be determined')
        self.parser.add_argument('-x', '--with-ptr', dest='do_ptr', action='store_true', help='Also modify the PTR for a given A or AAAA record. Forward and reverse zones must be on the same server.')
        self.parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='Print the rcode returned with for each update')

        self.parser.add_argument('cmd', action='store', nargs='+', metavar='add|delete|update', help='{Name} {TTL} {Type} {Target}.')

        self.args = self.parser.parse_args(namespace=self)

        return self.args

    def _is_valid_ttl(self, ttl):
        """
        validate TTL
        """

        self.ttl = ttl

        try:
            ttl = dns.ttl.from_text(self.ttl)
        except:
            print 'Error:', self.ttl, 'is not a valid TTL value'
            exit(-1)
        return self.ttl

    def _is_valid_ptr(self, ptr):
        """
        validate PTR
        """

        self.ptr = ptr

        if re.match(r'^((?:\d{1,3}\.){3}\d{1,3}\.in-addr\.arpa)$', self.ptr):
            return True
        else:
            print 'Error:', self.ptr, 'is not a valid PTR record'
            exit(-1)

    def _is_valid_ipv4_addr(self, address):
        """
        validate IPV4
        """

        self.address = address

        try:
            try:
                dns.ipv4.inet_aton(self.address)
                return True

            except dns.exception.SyntaxError:
                print 'Error:', self.address, 'is not a valid IPv4 address'

        except socket.error:
            print 'Error:', self.address, 'is not a valid IPv4 address'
            exit(-1)


    def _is_valid_ipv6_addr(self, address):
        """
        validate IPV6
        """

        self.address = address

        try:
            dns.ipv6.inet_aton(self.address)
            return True

        except SyntaxError:
            print 'Error:', self.address, 'is not a valid IPv6 address'
            exit(-1)

    def _is_valid_name(self, name):
        """
        validate hosts
        """

        self.name = name

        if re.match(r'^(([a-zA-Z]|[a-zA-Z][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z]|[A-Za-z][A-Za-z0-9\-]*[A-Za-z0-9]\.?)$', self.name):
            return True
        else:
            print 'Error:', self.name, 'is not a valid name'
            exit(-1)

    def _validate_cmd(self, cmd):
        """
        ACTION  NAME                     TTL    TYPE      TARGET
        ---------------------------------------------------------------
        add     test02.home.local.       600    A         172.17.0.4
        add     4.0.17.172.in-addr.arpa. 300    PTR       test03.home.local.
        add     home.local               86400  MX    10  mail.home.local
        add     home.local	             86400	NS	      ns2.home.local.

        ACTION  NAME                     TYPE
        delete  test03.home.local        A
        delete  test02.home.local        CNAME
        delete  4.0.17.172.in-addr.arpa  PTR
        """

        if self.cmd[0] == 'add' or self.cmd[0] == 'update':
            if len(self.cmd) < 5:
                print 'Error: not enough options for adding a record'
                print 'Usage: dnsupdate -z zone -s server -k key add|update Name TTL A|PTR Target'
                print 'dnsupdate -s server -k key add test02.home.local 600 A test01.home.local'
                exit(-1)
            self.cmd = {
                'action': cmd[0].lower(),
                'name':   cmd[1],
                'ttl':    cmd[2],
                'type':   cmd[3].upper(),
                'target': cmd[4]
            }
            self._is_valid_ttl(self.cmd['ttl'])

        elif self.cmd[0] == 'del' or self.cmd[0] == 'delete':
            if len(self.cmd) < 5:
                print 'Error: not enough options for an A record'
                print 'Usage: dnsupdate -z zone -s server -k key delete Name TTL A Target'
                exit(-1)
            self.cmd = {
                'action': cmd[0].lower(),
                'name':   cmd[1],
                'ttl':    cmd[2],
                'type':   cmd[3].upper(),
                'target': cmd[4]
            }

        elif self.cmd[0] != 'add' and self.cmd[0] != 'delete' and self.cmd[0] != 'del' and self.cmd[0] != 'update':
            print 'Error: Invalid action'
            print 'Usage: dnsupdate -s server -k key [add|delete|update] [Name] [Type] [TTL] [Target]'
            exit(-1)

        if self.cmd['type'] == 'A':
            self._is_valid_ipv4_addr(self.cmd['target'])

        elif self.cmd['type'] == 'AAAA':
            self._is_valid_ipv6_addr(self.cmd['target'])

        elif self.cmd['type'] == 'CNAME':
            self._is_valid_name(self.cmd['name'])
            self._is_valid_name(self.cmd['target'])

        elif self.cmd['type'] == 'PTR':
            self._is_valid_ptr(self.cmd['name'])
            self._is_valid_name(self.cmd['target'])

        # elif self.cmd['type'] == 'TXT':
        #     # Wrap the TXT string in quotes since the quotes get stripped
        #     self.cmd['target'] = '"%s"' % self.cmd['target']

        # elif self.cmd['type'] == 'MX':
        #     if len(cmd) < 4:
        #         print 'Error: not enough options for an MX record'
        #         print 'Usage: dnsupdate -o origin -s server -k key add|delete|update Name TTL MX Weight Target'
        #     if int(cmd[4]) > 65535 or int(cmd[4]) < 0:
        #         print 'Error: Preference must be between 0 - 65535'
        #         exit()
        #     self._is_valid_name(self.cmd['name'])(self.cmd['name'])
        #     self._is_valid_name(self.cmd['name'])(self.cmd['address'])

        # elif self.cmd['type'] == 'SRV':
        #     if len(cmd) < 7:
        #         print 'Error: not enough options for a SRV record'
        #         print 'Usage: dnsupdate -o origin -s server -k key add|delete|update Name TTL SRV Priority Weight Port Target'
        #     if int(cmd[4]) > 65535 or int(cmd[4]) < 0:
        #         print 'Error: Priority must be between 0 - 65535'
        #         exit()
        #     if int(cmd[5]) > 65535 or int(cmd[5]) < 0:
        #         print 'Error: Weight must be between 0 - 65535'
        #         exit()
        #     if int(cmd[6]) > 65535 or int(cmd[6]) < 0:
        #         print 'Error: Port must be between 0 - 65535'
        #         exit()
        #     self._is_valid_name(self.cmd['name'])(self.cmd['name'])
        #     self._is_valid_name(self.cmd['name'])(self.cmd['target'])

        # elif self.cmd['type'] == 'NS':

        return self.cmd

    def get_key(self, key_file=None, key_name=None, key_algorithm=None, key_secret=None):
        """generate key

        """

        if key_file is not None:
            f = open(key_file)
            self.keyfile = f.read().splitlines()
            f.close()

            self.keyname = self.keyfile[0].strip().rsplit(' ')[1].replace('"', '')
            self.algorithm = self.keyfile[1].strip().rsplit(' ')[1].replace(';', '').replace('-', '_').upper()
            self.secret = self.keyfile[2].strip().rsplit(' ')[1].replace('}', '').replace(';', '').replace('"', '')

        elif key_name and key_algorithm and key_secret is not None:
            self.keyname = key_name
            self.algorithm = key_algorithm.replace('-', '_').upper()
            self.secret = key_secret

        k = {self.keyname: self.secret}
        try:
            keyring = dns.tsigkeyring.from_text(k)
        except:
            print k, 'is not a valid key. The file should be in DNS KEY record format. See dnssec-keygen(8)'
            exit()
        return [keyring, self.algorithm]

    def _gen_ptr(self, address):
        self.address = address

        try:
            a = dns.reversename.from_address(self.address)
        except:
            print 'Error:', self.address, 'is not a valid IP adresss'
        return a

    def _parse_name(self, zone, name):
        try:
            n = dns.name.from_text(name)
        except:
            print 'Error:', n, 'is not a valid name'
            exit(-1)

        if zone is None:
            self.zone = dns.resolver.zone_for_name(n)
            self.name = n.relativize(self.zone)
        else:
            try:
                self.zone = dns.name.from_text(zone)
            except:
                print 'Error:', self.name, 'is not a valid origin'
                exit(-1)
            self.name = n - self.zone
        return self.zone, self.name

    def _validate_config(self, config):
        cfg = Config()
        if config is not None:
            self.config = cfg.parse_json(config)

            try:
                if self.config['zones'][self.zone] is not None:
                    self.key_name = self.config['zones'][self.zone]

                    self.my_config = self.config['keys'][self.key_name]
                    self.my_config.update({'name': self.key_name})

            except KeyError:
                print 'KeyError: ', [self.key_name]
        else:
            self.my_config = None

        return self.my_config


    # def do_update(self, server, keyring=None, keyname=None, keyalgorithm, zone, do_ptr, cmd):
    def do_update(self, server, zone, key_file, key_name, key_algorithm, key_secret, do_ptr, cmd, config):
        """Updates

        """
        self.config = self._validate_config(config)
        self.cmd = self._validate_cmd(cmd)

        self.server = server
        self.zone = zone
        self.do_ptr = do_ptr

        if key_file is not None:
            self.key, self.key_algorithm = self.get_key(key_file=key_file)
        elif key_name and key_algorithm and key_secret is not None:
            self.key, self.key_algorithm = self.get_key(key_name=key_name, key_algorithm=key_algorithm, key_secret=key_secret)
        elif self.config['name'] and self.config['secret'] and self.config['algorithm'] is not None:
            self.key, self.key_algorithm = self.get_key(key_name=self.config['name'], key_algorithm=self.config['algorithm'], key_secret=self.config['secret'])
        else:
            print 'Error: missing dns key'
            exit(-1)

        # Get the hostname and the zone
        self.zone, self.name = self._parse_name(self.zone, self.cmd['name'])

        # Start constructing the DDNS Query
        self.update = dns.update.Update(zone, keyring=self.key, keyalgorithm=getattr(dns.tsig, self.key_algorithm))

        if self.cmd['type'] == 'A' or self.cmd['type'] == 'AAAA':
            if self.do_ptr is True:
                self.ptr_target = self.name.to_text() + '.' + self.zone.to_text()
                self.ptr_zone, self.ptr_name = self._parse_name(None, self._gen_ptr(self.cmd['target']).to_text())
                self.ptr_update = dns.update.Update(self.ptr_zone, keyring=self.key, keyalgorithm=getattr(dns.tsig, self.key_algorithm))

        if self.cmd['type'] == 'CNAME' or self.cmd['type'] == 'NS' or self.cmd['type'] == 'TXT' or self.cmd['type'] == 'PTR':
            self.do_ptr = False

        # elif Type == 'SRV':
        #     payload = self.cmd['target']+' '+self.cmd[5]+' '+self.cmd[6]+' '+self.cmd[7]
        #     self.do_ptr = False
        # elif Type == 'MX':
        #     payload = self.cmd[4]+' '+self.cmd[5]
        #     self.do_ptr = False

        # Build the update
        if self.cmd['action'] == 'add':
            self.update.add(self.cmd['name'], self.cmd['ttl'], self.cmd['type'], self.cmd['target'])
            if self.do_ptr is True:
                self.ptr_update.add(self.ptr_name, self.cmd['ttl'], 'PTR', self.ptr_target)

        elif self.cmd['action'] == 'delete' or self.cmd['action'] == 'del':
            self.update.delete(self.cmd['name'], self.cmd['type'], self.cmd['target'])
            if self.do_ptr is True:
                self.ptr_update.delete(self.ptr_name, 'PTR', self.ptr_target)

        elif self.cmd['action'] == 'update':
            self.update.replace(self.cmd['name'], self.cmd['ttl'], self.cmd['type'], self.cmd['target'])
            if self.do_ptr is True:
                self.ptr_update.replace(self.ptr_name, self.cmd['ttl'], 'PTR', self.ptr_target)

        # Do the update
        try:
            self.response = dns.query.tcp(self.update, self.server)
        except dns.tsig.PeerBadKey:
            print 'ERROR: The server is refusing our key'
            exit(-1)

        if self.verbose is True:
            print 'Creating', self.cmd['type'], 'record for', self.cmd['name'], 'resulted in:', dns.rcode.to_text(self.response.rcode())

        if self.do_ptr is True:
            try:
                self.ptr_response = dns.query.tcp(self.ptr_update, self.server)
            except dns.tsig.PeerBadKey:
                print 'ERROR: The server is refusing our key'
                exit(-1)
            if self.verbose is True:
                print 'Creating PTR record for', self.cmd['name'], 'resulted in:', dns.rcode.to_text(self.response.rcode())
