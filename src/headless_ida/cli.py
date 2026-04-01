import argparse
import code

from rpyc.utils.server import ThreadedServer
from . import HeadlessIda, HeadlessIdaRemote, HeadlessIdaServer


def headlessida_cli():
    parser = argparse.ArgumentParser(description='Headless IDA')
    parser.add_argument(
        'idat_path', help='Path to IDA Pro executable or host:port of remote server')
    parser.add_argument('binary_path', help='Path to binary or .i64 to analyze')
    parser.add_argument('script_path', nargs='?', help='Path to script to run')
    parser.add_argument('-f', '--ftype', nargs='?',
                        help='File type (prefix visible in IDA "load file" dialog)')
    parser.add_argument('-p', '--processor', nargs='?',
                        help='Processor type (e.g. arm:ARMv7-A, mips:R3000)')
    parser.add_argument('-c', '--command', help='Python command to execute')
    parser.add_argument('-o', '--output', metavar='OUTPUT',
                        help='Save .i64 database to OUTPUT (includes script modifications)')

    args = parser.parse_args()
    has_script = args.script_path or args.command

    # Detect host:port remote syntax.  Plain rsplit(":") would misfire
    # on Windows drive letters like C:\IDA\idat.exe, so we also check
    # that the part after the last colon is a valid port number.
    host, _, port_str = args.idat_path.rpartition(":")
    is_remote = bool(host) and port_str.isdigit()

    if is_remote:
        port = port_str

        if args.output and not has_script:
            # -o only: analyze and download, no IDA session needed
            from .client import download_i64
            download_i64(
                host, int(port), args.binary_path, args.output,
                ftype=args.ftype, processor=args.processor,
            )
            print(f'Saved to {args.output}')
            return

        headlessida = HeadlessIdaRemote(
            host, int(port), args.binary_path,
            ftype=args.ftype, processor=args.processor,
        )
    else:
        headlessida = HeadlessIda(
            args.idat_path, args.binary_path,
            ftype=args.ftype, processor=args.processor,
        )

    headlessida_dict = {"headlessida": headlessida, "HeadlessIda": HeadlessIda}

    try:
        if args.script_path:
            with open(args.script_path) as f:
                exec(compile(f.read(), args.script_path, 'exec'), headlessida_dict)
        elif args.command:
            exec(compile(args.command, '<string>', 'exec'), headlessida_dict)
        else:
            code.interact(local=locals())

        # Save database after script execution (includes modifications)
        if args.output and has_script:
            if hasattr(headlessida, 'conn') and headlessida.conn:
                i64_data = headlessida.conn.root.save_database()
                with open(args.output, "wb") as f:
                    f.write(i64_data)
                print(f'Saved to {args.output}')
    finally:
        headlessida.clean_up()


def headlessida_server_cli():
    parser = argparse.ArgumentParser(description='Headless IDA Server')
    parser.add_argument('idat_path', help='Path to IDA Pro executable')
    parser.add_argument('host', help='Host to bind to')
    parser.add_argument('port', type=int, help='Port to listen on')

    args = parser.parse_args()

    ThreadedServer(HeadlessIdaServer(args.idat_path), hostname=args.host, port=args.port,
                   protocol_config={"allow_all_attrs": True}).start()
