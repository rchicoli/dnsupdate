import argparse

class Cli(object):

    config = None

    def __init__(self):
        # parser = argparse.ArgumentParser(usage='%(prog)s [-h] {-s} {-k} {-o} [-x] {add|delete|update} {Name} {TTL} [IN] {Type} {Target}', description='Add, Delete, Replace DNS records using DDNS.')
        self.parser = argparse.ArgumentParser()

        # parser.add_argument('-s', dest='server', required=True, help='DNS server to update (Required)')

        self.parser.add_argument('-c', '--config', dest='config', required=False, help='Config file JSON format (Required)')

        # parser.add_argument('-k', dest='key', required=True, help='TSIG key. The TSIG key file should be in DNS KEY record format. (Required)')

        self.parser.add_argument('-o', dest='zone', required=False, help='Specify the origin. Optional, if not provided origin will be determined')

        self.parser.add_argument('-x', dest='PTR', action='store_true', help='Also modify the PTR for a given A or AAAA record. Forward and reverse zones must be on the same server.')

        self.parser.add_argument('-v', dest='verbose', action='store_true', help='Print the rcode returned with for each update')

        # parser.add_argument('myInput', action='store', nargs='+', metavar='add|delete|update', help='{hostname} {TTL} [IN] {Type} {Target}.')

        args = self.parser.parse_args(namespace=self)

        if self.config is None:
            print('None config file')
            exit(1)
    
    # def get_args(self):
    #     """
    #     usage: dnsupdate.py [-h] {-s} {-k} {-o} [-x] {add|delete|update} {Name} {TTL} [IN] {Type} {Target}

    #     Add, Delete, Replace DNS records using DDNS.

    #     optional arguments:
    #     -h, --help            show this help message and exit
    #     -s SERVER             DNS server to update (Required)
    #     -k KEY                TSIG key. The TSIG key file should be in DNS KEY
    #                             record format. (Required)
    #     -o ZONE               Specify the origin. Optional, if not provided origin
    #                             will be determined
    #     -x                    Also modify the PTR for a given A or AAAA record.
    #                             Forward and reverse zones must be on the same server.
    #     -v                    Print the rcode returned with for each update
    #     -t add|delete|update [add|delete|update ...]
    #                             {hostname} {TTL} [IN] {Type} {Target}.
    #     """

        

    #     return self.args

