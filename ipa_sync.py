import argparse
import multiprocessing
import time

from twisted.python import log
from twisted.internet import reactor
import sys

from lib.add_ldap_repl import sync
from lib.ldap_server import LDAPServerFactory


def parse_options():
    parser = argparse.ArgumentParser(
        description="Add LDAP replication agreement entry with automatic DN construction",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    parser.add_argument('-d', '--debug', action='store_true',
                        help="Enable debug mode")
    parser.add_argument('-t', '--timeout', default=5, type=int,
                        help="Timeout in seconds for wait for replication")

    # Connection parameters
    parser.add_argument('-H', '--ldap-url', required=True,
                        help="LDAP server url (ldap://...)")
    parser.add_argument('-u', '--bind-dn', required=True,
                        help="Bind DN for authentication")
    parser.add_argument('-p', '--bind-pw', required=True,
                        help="Bind password")

    # Replication parameters
    parser.add_argument('--replica-host', required=True,
                        help="Replica host IP")
    parser.add_argument('--replica-port', default=389, type=int,
                        help="Replica port")
    parser.add_argument('--replica-root', required=True,
                        help="Replica root (e.g. dc=test,dc=local)")

    # Dump parameters
    parser.add_argument('-a', '--all', help="Dump all data to file (-a /path/to/file). By default only password hash.")

    return parser.parse_args()


if __name__ == "__main__":
    args = parse_options()
    factory = LDAPServerFactory(args.bind_dn, args.bind_pw, args.all, args.ldap_url)
    if args.debug:
        log.startLogging(sys.stderr)
        factory.debug = True
    else:
        factory.debug = False

    q = multiprocessing.Queue()
    p = multiprocessing.Process(target=sync, args=(args, q, args.timeout))

    p.start()
    result = q.get(timeout=10)
    if result == "All ok":
        print(f"Added complete. Start LDAP server.")

        reactor.listenTCP(args.replica_port, factory)
        server = multiprocessing.Process(target=reactor.run, args=(False,))
        server.start()
        print("Wait replication...")
        time.sleep(args.timeout)
        print("Server terminated. Delete replication agreement")
        q.put("Delete agreement")
        if p.is_alive():
            p.join()
        server.terminate()
    if p.is_alive():
        p.join()