# ADWSProxy (.NET 8.0)

A high-performance, cross-platform Active Directory Web Services (ADWS) proxy built on **.NET 8.0 LTS**. This tool bridges the gap for LDAP-based tools in environments where traditional LDAP ports (389/636) are blocked, but ADWS (9389) remains open.

---

## Key Features
* **Cross-Platform:** Runs on Windows, Linux, and macOS.
* **Docker Ready:** Optimized for lightweight Linux containers (Alpine/Debian).
* **Native SID Parsing:** Includes a custom binary-to-string SID parser, eliminating dependencies on Windows-only system libraries.
* **Modern Tooling:** Built using .NET 8 (LTS) SDK and `dotnet-svcutil`.

---

## Usage

### Command Line Arguments
```text
  --adwsdcport             (Default: 9389) The ADWS port to proxy to on the domain controller
  --adwsgcport             (Default: 9389) The ADWS port to proxy to on the global catalog
  --consoleloglevel        (Default: INFO) Set the log level for the console output
  --dnsport                (Default: 53) The DNS port to proxy from
  -D, --domain             The domain to authenticate to ADWS
  --domaincontroller       Required. The domain controller to proxy to
  --exitondnsstarterror    (Default: true) Exit if the DNS port is already in use
  --gcinstance             (Default: ldap:3268) The GC instance within ADWS
  --gcport                 (Default: 3268) The GC port to proxy from
  --globalcatalog          The global catalog to proxy to
  --ldapinstance           (Default: ldap:389) The LDAP instance within ADWS
  --ldapport               (Default: 389) The LDAP port to proxy from
  --logdirectory           (Default: .) The log directory for runtime logs
  -p, --password           The password to authenticate to ADWS
  -u, --username           The username to authenticate to ADWS
  --usewindowsauth         (Default: true) Use Windows Session (Kerberos/NTLM) or explicit credentials
  --help                   Display this help screen.
  --version                Display version information.
  ```

 ### Starting the Proxy

The proxy requires valid credentials if executed outside of a domain-joined Windows session (e.g., when running on Linux or in Docker).

Windows Example:
```text
# Using current session credentials
.\ADWSProxy.exe --domaincontroller dc01 --domain [...]

# Using explicit credentials
.\ADWSProxy.exe --usewindowsauth true -u "luc" -p "password" --domaincontroller dc01 --domain [...]
```

### Linux/Docker Example:
```bash
docker run -p 389:389 -p 9389:9389 adwsproxy:latest \
  --usewindowsauth false \
  --username "luc" \
  --password "password" \
  --domaincontroller dc01 \
  --domain [...]
```

## Technical Details

### Binary SID Parsing

To ensure full Linux compatibility, this version of ADWSProxy bypasses the `System.Security.Principal.Windows` namespace. It manually decodes the 28-byte binary `objectSid` blobs returned by ADWS into the standard string format (`S-1-5-21-...`) using a zero-dependency bit-shifter.

### Code Generation

The ADWS client proxy code (`ActiveDirectoryWebService.cs`) is generated using `dotnet-svcutil`. This ensures compatibility with the .NET 8.0 `System.ServiceModel` stack.

```powershell
dotnet --fx-version 8.0.23 "C:\Users\luc\.dotnet\tools\.store\dotnet-svcutil\8.0.0\dotnet-svcutil\8.0.0\tools\net8.0\any\dotnet-svcutil.dll" \
  net.tcp://dc01.[...]:9389/ActiveDirectoryWebServices/mex \
  --namespace "*,ADWSProxy.ADWS" \
  --outputFile "ActiveDirectoryWebService.cs" \
  --serializer XmlSerializer \
  --targetFramework net8.0
```

## Integration Testing (Bloodhound)

[Bloodhound-Python](https://github.com/dirkjanm/BloodHound.py) can be used with this proxy by setting the `-ns` argument to the proxy's IP. The proxy spoofs the LDAP response to make itself appear as the Domain Controller.

```bash
# Example using NTLM authentication through the proxy
python3 -m bloodhound -u x -p x -d [...] --auth ntlm -ns 127.0.0.1 -c All
```

## Blog Post & Background

Detailed research into ADWS exploitation and the architecture of this tool is available on the [Rabobank TechBlog](https://rabobank.jobs/en/techblog/adws-an-unconventional-path-into-active-directory-luc-kolen/).
