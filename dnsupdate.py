#!/usr/bin/env python2.7

from command.cli import Cli

if __name__ == '__main__':

    cli = Cli()
    args = cli.get_args()

    cli.doUpdate(args.server, args.key, args.zone, args.ptr, args.cmd)
