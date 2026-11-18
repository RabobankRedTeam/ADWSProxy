# ADWSProxy (.NET 10.0)

A high-performance, cross-platform Active Directory Web Services (ADWS) proxy built on **.NET 10.0 LTS**. This tool bridges the gap for LDAP-based tools in environments where traditional LDAP ports (389/636) are blocked, but ADWS (9389) remains open.

---

## Key Features
* **Cross-Platform:** Runs on Windows, Linux, and macOS.
* **Docker Ready:** Optimized for lightweight Linux containers (Alpine/Debian).
* **Native SID Parsing:** Includes a custom binary-to-string SID parser, eliminating dependencies on Windows-only system libraries.
* **Modern Tooling:** Built using .NET 10 (LTS) SDK and `dotnet-svcutil`.

---

## Usage

### Command Line Arguments
```text
  -dc, --domaincontroller <fqdn>     (Required) The domain controller to proxy to for NTDS
  -gc, --globalcatalog <fqdn>        The global catalog to proxy to (Default: only the DC/NTDS is used)
       --ldapport <port>             LDAP port to listen on (Default: 389)
       --gcport <port>               GC port to listen on (Default: 3268)
       --adwsdcport <port>           ADWS port on the domain controller (Default: 9389)
       --adwsgcport <port>           ADWS port on the global catalog (Default: 9389)
       --onlyusegcbackend <bool>     Use the GC instance (ldap:3268) for all backend communication (Default: false)
       --listenip <ip>               The IP to listen on for LDAP/GC requests (Default: 0.0.0.0)
       --hostip <ip>                 The IP returned in DNS responses (Default: system IPv4)
       --skipdns <bool>              Skip starting the DNS listener (Default: false)
       --exitondnsstarterror <bool>  Exit if the DNS listener cannot start, e.g. port 53 in use (Default: false)
       --skiprootdse <bool>          Skip querying the RootDSE during startup (Default: false)
  -m,  --mode <Windows|Username>     ADWS endpoint mode (Default: Windows)
       --consoleloglevel <level>     Log level for the console output (Default: INFO)
       --logdirectory <dir>          Directory for runtime logs (Default: .)
       --logpasswords <bool>         Log captured LDAP bind passwords at debug level (Default: true)

Credentials: omit all three to use the current Windows session, or supply all three.
  -u,  --username <user>             Username to authenticate to ADWS
  -p,  --password <pass>             Password to authenticate to ADWS
  -D,  --domain <domain>             Domain to authenticate to ADWS
  -h,  --help                        Show this help message
```

### Starting the Proxy

The proxy requires valid credentials if executed outside of a domain-joined Windows session (e.g., when running on Linux or in Docker).

#### Server 2025

Windows Server 2025 has removed the `/UserName` endpoints so only `--mode Windows` is supported.

This mode can be used without explicitly noting credentials by using the current Windows session:

```powershell
.\ADWSProxy.exe --domaincontroller "corpdc01.corp.internal"
```

It's also possible to explicitly set credentials to use, for instance when running from a non-domain-joined machine or a machine that is joined to a different domain.

```powershell
.\ADWSProxy.exe -u "user" -p "password" --domain "corp.internal" --domaincontroller "corpdc01.corp.internal"
```

#### Older versions

Older versions of Windows do support the `/UserName` endpoints so we can also use those to obtain data via ADWS:

```powershell
.\ADWSProxy.exe -m "Username" -u "user" -p "password" --domain "corp.internal" --domaincontroller "corpdc01.corp.internal"
```

### Linux/Docker Example:

Building the image from source:

```bash
$ git clone https://github.com/RabobankRedTeam/ADWSProxy.git
$ cd ADWSProxy
$ docker build -f ADWSProxy/Dockerfile -t adwsproxy -q .
$ docker images
REPOSITORY   TAG       IMAGE ID       CREATED         SIZE
adwsproxy    latest    [...]
```

Using the image:

```bash
$ docker run \
  -p 53:53/tcp -p 53:53/udp -p 389:389/tcp -p 3268:3268/tcp \
  --hostname ADWSPROXY \
  -it adwsproxy:latest \
  --mode Windows \
  --username "user" \
  --password "password" \
  --domaincontroller corpdc01.corp.internal \
  --domain corp.internal
```

## Technical Details

### Binary SID Parsing

To ensure full Linux compatibility, this version of ADWSProxy bypasses the `System.Security.Principal.Windows` namespace. It manually decodes the 28-byte binary `objectSid` blobs returned by ADWS into the standard string format (`S-1-5-21-...`) using a zero-dependency bit-shifter.

### Code Generation

The ADWS client proxy code (`ActiveDirectoryWebService.cs`) is generated with `dotnet-svcutil` against a live ADWS domain controller's WS-MetadataExchange endpoint, which keeps it compatible with the .NET 10.0 `System.ServiceModel` stack. The metadata is the same on every DC, so any reachable DC works.

`dotnet-svcutil` is pinned as a local tool in [.config/dotnet-tools.json](.config/dotnet-tools.json), so no global install or machine-specific path is needed. The pinned `8.0.0` is the current release of the tool; `--serializer XmlSerializer` is required for the ADWS contracts and `--targetFramework net10.0` matches the projects. Its `rollForward` is set to `true` because the tool's host targets the .NET 9 runtime; that lets it run on a newer installed runtime instead. Regenerate with the helper script:

```powershell
./ServiceReference/Regenerate.ps1 -DomainController corpdc01.corp.internal
```

which is equivalent to:

```powershell
dotnet tool restore
dotnet tool run dotnet-svcutil `
  net.tcp://corpdc01.corp.internal:9389/ActiveDirectoryWebServices/mex `
  --namespace "*,ADWSProxy.ADWS" `
  --outputFile "ActiveDirectoryWebService.cs" `
  --serializer XmlSerializer `
  --targetFramework net10.0 `
  --sync
```

The script writes to `ServiceReference/` rather than over the source file: the committed `ActiveDirectoryWebService.cs` has been formatted after generation and carries `CS8981` pragmas, so review the output and apply the project formatting before replacing it. The `GetDefaultEndpointAddress` helpers in the generated file embed the DC host name you generate against, but those defaults are unused at run time — [Connection.cs](ADWSProxy/ADWS/Connection.cs) builds its own `EndpointAddress` from the configured server.

### Mandatory RPC Sealing and Signing

Server 2025 enforces strict integrity requirements. All NTLM/Kerberos tokens must negotiate 128-bit encryption and message signing (Seal & Sign).

>Technical Note: This tool automatically configures ProtectionLevel.EncryptAndSign to meet this requirement. If you encounter 0x80090302 (Invalid Token), ensure your client machine's clock is synchronized with the Domain Controller.

### NTLMv1 Retirement

Server 2025 has effectively retired NTLMv1. If running this tool from a Linux environment, ensure you have the `gss-ntlmssp` package installed to support modern NTLMv2/Negotiate handshakes.

## Integration Testing (Bloodhound)

[Bloodhound-Python](https://github.com/dirkjanm/BloodHound.py) can be used with this proxy by setting the `-ns` argument to the proxy's IP. The proxy spoofs the LDAP response to make itself appear as the Domain Controller.

```bash
# Example using NTLM authentication through the proxy
python3 -m bloodhound -u x -p x -d corp.internal --auth ntlm -ns 127.0.0.1 -c DCOnly
```

>Technical Note: Bloodhound-Python can't run with `only-use-gc-backend` set to true as the dataset returned by the GC is less complete than the default dataset.

## Blog Post & Background

Detailed research into ADWS exploitation and the architecture of this tool is available on the [Rabobank TechBlog](https://rabobank.jobs/en/techblog/adws-an-unconventional-path-into-active-directory-luc-kolen/).

## Test client

A test client that can run queries via the following methods; ADWS, ADWS-Global Catalog, LDAP(S), and LDAP(S)-Global Catalog is available. A sample [tests.json](TestClient/tests.json) file is included with the repository.

Run a tests file with `-f` and, optionally, credentials with `-u/-p/-d` (otherwise the current Windows session is used):

```powershell
TestClient.exe -f tests.json -u <user> -p <password> -d <domain>
```

The tests JSON is written to `trace.log` at debug level. By default any `Password` values it contains are written as-is; pass `--logpasswords false` to mask them (and, in generate mode, to write credentials with an empty password).

Credentials resolve per query as per-query JSON → config-level JSON → CLI (`-u/-p/-d`) → Windows session, and by default each source is used whole or not at all. Pass `--mergecredentials` to fill a JSON `Credentials` block's missing fields from the CLI per field — for example, keep the username and domain in the tests file and supply only the password with `-p`. Each merge is logged as a warning, and a set of fields that is still incomplete after merging aborts the run.

### Generate mode

`-g <server>` discovers the forest's partitions and trusts from `<server>` and writes a reviewable tests file, then exits without running anything. It is fully CLI-driven and reads no tests JSON:

```powershell
TestClient.exe -g corpdc01.corp.internal -u <user> -p <password> -d <domain> -o forest.tests.json
```

- `-o <file>` — output path (default `./forest.tests.json`).
- `-e <csv>` — engines stamped onto each generated query (default `ADWS,LDAP,LDAPS`, e.g. `-e LDAP-GC`). Valid engines: `ADWS`, `LDAP`, `LDAPS`, `ADWS-GC`, `LDAP-GC`, `LDAPS-GC`. Generate Global Catalog and direct files separately.
- `-c` — also write the `-u/-p/-d` credentials into the file so it can be run with just `-f`. Off by default so no secret is persisted; the password is stored in plaintext, so protect or delete the file afterwards. Combine with `--logpasswords false` to write the username and domain but leave the password empty (you then supply `-p` at run time).

Generate does all the discovery; the file it writes does none. Every query pins a concrete DC in its `Server` field, so running the file only contacts the servers listed in it:

- **Direct engines** (`ADWS`/`LDAP`/`LDAPS`): one query per partition (domains, Configuration, Schema, DNS application partitions), each targeting a DC that holds that partition.
- **Global Catalog engines**: every in-forest query targets the DC generate ran against. A GC subtree search spans child naming contexts, so nested partitions are dropped and the forest root's query covers the whole forest once.
- **Cross-forest trusts**: listed with a DC resolved from the partner forest, plus an empty `Credentials` block to fill in when that forest needs its own account.

The file's `_serverDescription` field explains how the top-level `Server` (a fallback) and each query's `Server` relate. Discovery credentials come from `-u/-p/-d` (otherwise the Windows session). Review the generated file, then run the collection with `-f forest.tests.json`.

## BloodHound converter

`BloodHoundConverter` turns the test client's result chunks (`*_part*.json`) into BloodHound CE ingest files. Pass the folder the collection ran in, a single chunk file, or a wildcard pattern:

```powershell
BloodHoundConverter.exe C:\collections\corp
```

Output is written to `<folder>\BloodHoundOutput\<yyyyMMdd_HHmmss>\`: one set of JSON files per domain (users, groups, computers, domains, OUs, GPOs, containers, ADCS objects, ...) and a `BloodHound.zip` of them, ready to upload. Objects collected more than once (for example by overlapping queries) are merged by distinguished name, keeping the most complete copy.

## Test environment

Steps to setup the test environment can be found in [forest-lab-setup.md](docs/forest-lab-setup.md)
