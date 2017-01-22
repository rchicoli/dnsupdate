#!/usr/bin/env python2.7
#
# Usage: dnstool -s server -k key add foo.example.com 300 a 1.2.3.4
# -h HELP!
# -s the server
# -k the key
# the action (add, delete, replace) and record specific parameters

from command.cli import Cli

if __name__ == '__main__':

    cli = Cli()
    args = cli.get_args()
    # cli = Cli()

    print args.zone
    cli.doUpdate(args.server, args.key, args.zone, args.ptr, args.cmd)
