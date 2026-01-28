# ADWSProxy (.NET 8.0)

A high-performance, cross-platform Active Directory Web Services (ADWS) proxy built on **.NET 8.0 LTS**. This tool bridges the gap for LDAP-based tools in environments where traditional LDAP ports (389/636) are blocked, but ADWS (9389) remains open.

---

## Key Features
* **Cross-Platform:** Runs on Windows, Linux, and MacOS.
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
  --domaincontroller       Required. The domain controller to proxy to for NTDS
  --exitondnsstarterror    (Default: true) Exit if the DNS port is already in use
  --gcport                 (Default: 3268) The GC port to proxy from
  --globalcatalog          (Default: only DC/NTDS is used) The global catalog to proxy to
  --hostip                 (Default: system IP) Override the IP in the DNS respones
  --ldapport               (Default: 389) The LDAP port to proxy from
  --logdirectory           (Default: .) The log directory for runtime logs
  -m, --mode               (Default: Windows) Set the ADWS endpoint mode: Windows or Username.
  --only-use-gc-backend    (Default: false) Force ADWS to use GC instance (ldap:3268) for all backend communication

These credentials can either be ommited or all need to be filled in. If empty then the current Windows domain session will be used.
  -u, --username           The username to authenticate to ADWS
  -p, --password           The password to authenticate to ADWS
  -D, --domain             The domain to authenticate to ADWS
  --help                   Display this help screen.
  --version                Display version information.
  ```

 ### Starting the Proxy

The proxy requires valid credentials if executed outside of a domain-joined Windows session (e.g., when running on Linux or in Docker).

#### Server 2025

Windows Server 2025 has removed the `/UserName` endpoints so only `--mode Windows` is supported.

This mode can be used without explicitly noting credentials by using the current Windows session:

```powershell
.\ADWSProxy.exe --domaincontroller "dc01.[...]"
```

It's also possible to explicitly set credentials to use, for instance when running from a non domain joined machine or a machine that is joined to a different domain.

```powershell
.\ADWSProxy.exe -u "user" -p "password" --domain "[...]" --domaincontroller "dc01.[...]"
```

#### Older versions

Older versions of Windows do support the `/UserName` endpoints so we can also use those to obtain data via ADWS:

```powershell
.\ADWSProxy.exe -m "Username" -u "user" -p "password" --domain "[...]" --domaincontroller "dc01.[...]"
```

### Linux/Docker Example:
```bash
docker run -p 389:389 -p 9389:9389 adwsproxy:latest \
  --mode Windows \
  --username "user" \
  --password "password" \
  --domaincontroller dc01.[...] \
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

### Mandatory RPC Sealing and Signing

Server 2025 enforces strict integrity requirements. All NTLM/Kerberos tokens must negotiate 128-bit encryption and message signing (Seal & Sign).

>Technical Note: This tool automatically configures ProtectionLevel.EncryptAndSign to meet this requirement. If you encounter 0x80090302 (Invalid Token), ensure your client machine's clock is synchronized with the Domain Controller.

### NTLMv1 Retirement

Server 2025 has effectively retired NTLMv1. If running this tool from a Linux environment, ensure you have the `gss-ntlmssp` package installed to support modern NTLMv2/Negotiate handshakes.

## Integration Testing (Bloodhound)

[Bloodhound-Python](https://github.com/dirkjanm/BloodHound.py) can be used with this proxy by setting the `-ns` argument to the proxy's IP. The proxy spoofs the LDAP response to make itself appear as the Domain Controller.

```bash
# Example using NTLM authentication through the proxy
python3 -m bloodhound -u x -p x -d [...] --auth ntlm -ns 127.0.0.1 -c All
```

>Technical Note: Bloodhound-Python can't run with `only-use-gc-backend` set to true as the dataset returned by the GC is less complete than the default dataset.

## Blog Post & Background

Detailed research into ADWS exploitation and the architecture of this tool is available on the [Rabobank TechBlog](https://rabobank.jobs/en/techblog/adws-an-unconventional-path-into-active-directory-luc-kolen/).
