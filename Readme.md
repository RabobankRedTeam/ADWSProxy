# ADWSProxy

## Usage

```
  --adwsdcport             (Default: 9389) The ADWS port to proxy to on the domain controller
  --adwsgcport             (Default: 9389) The ADWS port to proxy to on the global catalog
  --consoleloglevel        (Default: INFO) Set the log level for the console output
  --dnsport                (Default: 53) The DNS port to proxy from
  -D, --domain             The domain to authenticate to ADWS
  --domaincontroller       Required. The domain controller to proxy to
  --exitondnsstarterror    (Default: true) Exit the application if the DNS port is already in use
  --gcinstance             (Default: ldap:3268) The GC instance within ADWS
  --gcport                 (Default: 3268) The GC port to proxy from
  --globalcatalog          The global catalog to proxy to
  --ldapinstance           (Default: ldap:389) The LDAP instance within ADWS
  --ldapport               (Default: 389) The LDAP port to proxy from
  --logdirectory           (Default: .) The log directory to output runtime logs. Defaults to the current working directory.
  -p, --password           The password to authenticate to ADWS
  -u, --username           The username to authenticate to ADWS
  --usewindowsauth         (Default: true) Use Windows Authentication or Username/Password with TLS
  --help                   Display this help screen.
  --version                Display version information.
```

The Proxy can be started with the following command. Make sure that if either of `--domain`, `--username` or `--password` is set that all three values are set and corrent. These three values can be ommited if the Proxy is executed within the context of a domain joined user.

```
PS> .\ADWSProxy.exe --domain [...] --username [...] --password [...] --domaincontroller dc01.[...] --globalcatalog dc01.[...]
[ INFO ] Starting LDAP2ADWS proxy.
[ INFO ] Constructing new ADWSProxy.LDAP.Listener
[ INFO ] Constructing new ADWSProxy.ADWS.Connection
[ INFO ] Succesfully started the LDAPListener on 0.0.0.0:389
[ INFO ] Constructing new ADWSProxy.LDAP.Listener
[ INFO ] Constructing new ADWSProxy.ADWS.Connection
[ INFO ] Succesfully started the GCListener on 0.0.0.0:3268
[ INFO ] Constructing new ADWSProxy.DNS.Resolver
[ INFO ] Succesfully started the DNSListener on 0.0.0.0:53
[ INFO ] Succesfully got RootDSE
Pressing Enter will close the application
```

[Bloodhound-Python](https://github.com/dirkjanm/BloodHound.py) can be run by setting the `-ns` argument to the DNS resolver of the Proxy. This proxy will return the machine hosting the Proxy as the Domain Controller and the Global Catalog for the domain.  
The values for `-u` and `-p` does not matter as the Proxy does not check credentials. `--auth ntlm` needs to be used as the Proxy only supports Simple and NTLM authentication at this point.

```
PS> hostname
WinDev
PS> python -m bloodhound -u x -p x -d [...] --auth ntlm -ns 127.0.0.1 -c dconly
INFO: Found AD domain: [...]
INFO: Connecting to LDAP server: WinDev
INFO: Found 1 domains
INFO: Found 2 domains in the forest
INFO: Found 2495 users
INFO: Connecting to GC LDAP server: WinDev
INFO: Connecting to LDAP server: WinDev
INFO: Found 552 groups
INFO: Found 2 gpos
INFO: Found 223 ous
INFO: Found 19 containers
INFO: Found 102 computers
INFO: Found 1 trusts
INFO: Done in 00M 41S
```

## About

[ActiveDirectoryWebService.cs](ADWSProxy/ADWS/ActiveDirectoryWebService.cs) was the only generated code used within the tool. The following command was used to generate this code:

```
SvcUtil.exe /nologo /noconfig /t:code /n:*,ADWSProxy.ADWS net.tcp://[...]:9389/ActiveDirectoryWebServices/mex /serializer:XmlSerializer
```
