from __future__ import absolute_import

import argparse

# import textwrap
import re
import socket
import dns.query
import dns.tsigkeyring
import dns.update
import dns.reversename
import dns.resolver
from dns.exception import DNSException, SyntaxError

from config import Config

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
        self.parser = argparse.ArgumentParser()
        self.config = ''
        self.key = ''
        self.zone = ''
        self.verbose = ''
        self.server = ''

        self.cmd = {}

        self.address = ''
        self.name = ''

    def get_args(self):
        # parser = argparse.ArgumentParser(usage='%(prog)s [-h] {-s} {-k} {-o} [-x] {add|delete|update} {Name} {TTL} {Type} {Target}', description='Add, Delete, Replace DNS records using DDNS.')

        self.parser.add_argument('-s', '--server', dest='server', required=True, help='DNS server to update (Required)')

        self.parser.add_argument('-c', '--config', dest='config', required=False, help='Config file JSON format (Required)')

        self.parser.add_argument('-k', '--key', dest='key', required=True, help='TSIG key. The TSIG key file should be in DNS KEY record format. (Required)')

        self.parser.add_argument('-z', '--zone', dest='zone', required=True, help='Specify the origin. Optional, if not provided origin will be determined')

        self.parser.add_argument('-p', '--ptr', dest='ptr', action='store_true', help='Also modify the PTR for a given A or AAAA record. Forward and reverse zones must be on the same server.')

        self.parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='Print the rcode returned with for each update')

        self.parser.add_argument('cmd', action='store', nargs='+', metavar='add|delete|update', help='{hostname} {TTL} {Type} {Target}.')

        args = self.parser.parse_args(namespace=self)

        # print args

        cfg = Config()
        if self.config:
            load_config = cfg.parse_json(self.config)
        else:
            load_config = cfg.parse_json('config/config.json')

        try:
            if load_config['zones'][self.zone] != load_config['keys'][self.key]:
                print 'key does not match the one'
                # print load_config['zones'][self.zone]
                # print load_config['keys']
        except KeyError:
            print 'KeyError: ', [self.key]

        return args

    def is_valid_TTL(self, ttl):
        self.ttl = ttl
        try:
            ttl = dns.ttl.from_text(self.ttl)
        except:
            print 'TTL:', self.ttl, 'is not valid'
            exit(-1)
        return self.ttl

    # def isValidPTR(ptr):
    #     if re.match(r'\b(?:\d{1,3}\.){3}\d{1,3}.in-addr.arpa\b', ptr):
    #         return True
    #     else:
    #         print 'Error:', ptr, 'is not a valid PTR record'
    #         exit()

    def is_valid_V4_Addr(self, address):
        """
        validate the address
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


    def is_valid_V6_Add(self, address):
        """
        validate the address
        """

        self.address = address

        try:
            dns.ipv6.inet_aton(self.address)
            return True

        except SyntaxError:
            print 'Error:', self.address, 'is not a valid IPv6 address'
            exit(-1)

    def is_valid_Name(self, name):
        """
        validate the host
        """

        self.name = name

        if re.match(r'^(([a-zA-Z]|[a-zA-Z][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z]|[A-Za-z][A-Za-z0-9\-]*[A-Za-z0-9]\.?)$', self.name):
            return True
        else:
            print 'Error:', self.name, 'is not a valid name'
            exit(-1)

    def validate_input(self, cmd):
        """
        ['add', 'test02.home.local.', '600', 'A', '172.17.0.4']
        """

        if len(self.cmd) < 5:
            print 'Error: not enough options for an A record'
            print 'Usage: dnsupdate -o origin -s server -k key add|delete|update Name TTL A Address'
            exit(-1)

        self.cmd = {'action': cmd[0].lower(), 'hostname': cmd[1], 'ttl': cmd[2], 'type': cmd[3].upper(), 'address': cmd[4]}


        if self.cmd['action'] != 'add' and self.cmd['action'] != 'delete' and self.cmd['action'] != 'del' and self.cmd['action'] != 'update':
            print 'Error: Invalid action'
            print 'Usage: dnsupdate -s server -k key [add|delete|update] [Name] [Type] [TTL] [Address]'
            exit(-1)

        self.is_valid_TTL(self.cmd['ttl'])

        self.is_valid_Name(self.cmd['hostname'])

        if self.cmd['type'] == 'A':
            self.is_valid_V4_Addr(self.cmd['address'])
        elif self.cmd['type'] == 'AAAA':
            self.is_valid_V6_Add(self.cmd['address'])

    #     if type == 'CNAME' or type == 'NS':
    #         if len(cmd) < 4:
    #             print 'Error: not enough options for a CNAME record'
    #             print 'Usage: dnsupdate -o origin -s server -k key add|delete|update Name TTL CNAME Target'
    #             exit()
    #         isValidName(cmd[1])
    #         isValidName(cmd[4])

    #     if type == 'PTR':
    #         if len(cmd) < 4:
    #             print 'Error: not enough options for a PTR record'
    #             print 'Usage: dnsupdate -o origin -s server -k key add|delete|update Name TTL PTR Target'
    #             exit()
    # #        isValidPTR(cmd[1])
    #         isValidName(cmd[4])

    #     if type == 'TXT':
    #         # Wrap the TXT string in quotes since the quotes get stripped
    #         cmd[4] = '"%s"' % cmd[4]

    #     if type == 'MX':
    #         if len(cmd) < 4:
    #             print 'Error: not enough options for an MX record'
    #             print 'Usage: dnsupdate -o origin -s server -k key add|delete|update Name TTL MX Weight Target'
    #         if int(cmd[4]) > 65535 or int(cmd[4]) < 0:
    #             print 'Error: Preference must be between 0 - 65535'
    #             exit()
    #         isValidName(cmd[1])
    #         isValidName(cmd[5])

    #     if type == 'SRV':
    #         if len(cmd) < 7:
    #             print 'Error: not enough options for a SRV record'
    #             print 'Usage: dnsupdate -o origin -s server -k key add|delete|update Name TTL SRV Priority Weight Port Target'
    #         if int(cmd[4]) > 65535 or int(cmd[4]) < 0:
    #             print 'Error: Priority must be between 0 - 65535'
    #             exit()
    #         if int(cmd[5]) > 65535 or int(cmd[5]) < 0:
    #             print 'Error: Weight must be between 0 - 65535'
    #             exit()
    #         if int(cmd[6]) > 65535 or int(cmd[6]) < 0:
    #             print 'Error: Port must be between 0 - 65535'
    #             exit()
    #         isValidName(cmd[1])
    #         isValidName(cmd[7])

        # return action, ttl, type
        return self.cmd

    # def getKey(FileName):
    #     f = open(FileName)
    #     key = f.readline()
    #     f.close()
    #     k = {key.rsplit(' ')[0]:key.rsplit(' ')[6]}
    #     try:
    #         KeyRing = dns.tsigkeyring.from_text(k)
    #     except:
    #         print k, 'is not a valid key. The file should be in DNS KEY record format. See dnssec-keygen(8)'
    #         exit()
    #     return KeyRing

    # def genPTR(Address):
    #     try:
    #         a = dns.reversename.from_address(Address)
    #     except:
    #         print 'Error:', Address, 'is not a valid IP adresss'
    #     return a

    # def parseName(Origin, Name):
    #     try:
    #         n = dns.name.from_text(Name)
    #     except:
    #         print 'Error:', n, 'is not a valid name'
    #         exit()
    #     if Origin is None:
    #         Origin = dns.resolver.zone_for_name(n)
    #         Name = n.relativize(Origin)
    #         return Origin, Name
    #     else:
    #         try:
    #             Origin = dns.name.from_text(Origin)
    #         except:
    #             print 'Error:', Name, 'is not a valid origin'
    #             exit()
    #         Name = n - Origin
    #         return Origin, Name

    def doUpdate(self, server, key, zone, ptr, cmd):

        # action, ttl, type_entry = self.validate_input(cmd)
        action = self.validate_input(cmd)

        print action

        # Get the hostname and the zone
        # zone, name = parseName(Origin, myInput[1])

        # KeyRing = getKey(KeyFile)

        # Start constructing the DDNS Query
        # update = dns.update.Update(zone, keyring=key)

        # # Put the payload together.
        # if Type == 'A' or Type == 'AAAA':
        #     myPayload = myInput[4]
        #     if ptr is True:
        #         ptrTarget = name.to_text() + '.' + zone.to_text()
        #         ptrOrigin, ptrName = parseName(None, genPTR(myPayload).to_text())
        #         ptrUpdate = dns.update.Update(ptrOrigin, keyring=KeyRing)
        # if Type == 'CNAME' or Type == 'NS' or Type == 'TXT' or Type == 'PTR':
        #     myPayload = myInput[4]
        #     do_PTR = False
        # elif Type == 'SRV':
        #     myPayload = myInput[4]+' '+myInput[5]+' '+myInput[6]+' '+myInput[7]
        #     do_PTR = False
        # elif Type == 'MX':
        #     myPayload = myInput[4]+' '+myInput[5]
        #     do_PTR = False

        # # Build the update
        # if Action == 'add':
        #     update.add(name, TTL, Type, myPayload)
        #     if ptr is True:
        #         ptrUpdate.add(ptrName, TTL, 'PTR', ptrTarget)

        # elif Action == 'delete' or Action == 'del':
        #     update.delete(name, Type, myPayload)
        #     if ptr is True:
        #         ptrUpdate.delete(ptrName, 'PTR', ptrTarget)

        # elif Action == 'update':
        #     update.replace(Name, TTL, Type, myPayload)
        #     if ptr is True:
        #         ptrUpdate.replace(ptrName, TTL, 'PTR', ptrTarget)

        # # Do the update
        # try:
        #     Response = dns.query.tcp(update, server)
        # except dns.tsig.PeerBadKey:
        #     print 'ERROR: The server is refusing our key'
        #     exit()

        # if Verbose == True:
        #     print 'Creating', Type, 'record for', Name, 'resulted in:', dns.rcode.to_text(Response.rcode())

        # if doPTR == True:
        #     try:
        #         ptrResponse = dns.query.tcp(ptrUpdate, Server)
        #     except dns.tsig.PeerBadKey:
        #         print 'ERROR: The server is refusing our key'
        #         exit()
        #     if Verbose == True:
        #         print 'Creating PTR record for', Name, 'resulted in:', dns.rcode.to_text(Response.rcode())
