#!/usr/bin/env python2.7

# docker run --name bind --rm --publish 53:53/tcp --publish 53:53/udp --publish 10000:10000/tcp -e ROOT_PASSWORD=secret sameersbn/bind:9.9.5-20170115

from command.cli import Cli

if __name__ == '__main__':

    cli = Cli()
    args = cli.get_args()

    # print args

    cli.do_update(
        server=args.server,
        zone=args.zone,
        key_file=args.key_file,
        key_name=args.key_name,
        key_algorithm=args.key_algorithm,
        key_secret=args.key_secret,
        do_ptr=args.do_ptr,
        cmd=args.cmd,
        config=args.config
    )
