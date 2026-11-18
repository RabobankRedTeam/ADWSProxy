# Forest Trust Lab — build runbook

A three-DC lab for exercising the TestClient forest/trust features (`{{allContexts}}`, the
`-g` forest-file generator, and per-query/per-forest credentials).

## Topology

| VM | Windows name | FQDN | Domain | Role | IP |
|---|---|---|---|---|---|
| corpdc01 | `CORPDC01` | `corpdc01.corp.internal` | `corp.internal` | Forest A root | 192.168.10.91 |
| devdc01 | `DEVDC01` | `devdc01.dev.corp.internal` | `dev.corp.internal` | Child of A | 192.168.10.92 |
| partdc01 | `PARTDC01` | `partdc01.partner.internal` | `partner.internal` | Forest B root | 192.168.10.93 |
| (test client) | — | — | — | runs `TestClient` | 192.168.10.20 |

- Two-way **forest trust** between `corp.internal` and `partner.internal`, forest-wide authentication.
- One account, `recon@corp.internal`, reads all three domains (forest A natively + the child via the
  intra-forest trust, forest B via the forest trust).
- `.internal` is the ICANN-reserved private-use TLD (never delegated publicly) — no collisions, and no
  `.local`/mDNS clash.
- NetBIOS names are unique (`CORPDC01`/`DEVDC01`/`PARTDC01`) because all three DCs share one L2 segment;
  duplicate flat names on the same subnet would conflict.

All commands run in an **elevated PowerShell** on the named server.

---

## Part 0 — Virtualization & network prep

This lab is shown on **Proxmox** with an **OPNsense** firewall/resolver and a `192.168.10.0/24` segment as
a concrete example. Any hypervisor, and any router/resolver that can forward per-zone DNS and serve NTP,
works just as well — adapt the vendor-specific steps and addresses to your environment.

**Hypervisor, per VM** (Proxmox shown):
- NIC on the lab segment (e.g. a VirtIO NIC on a VLAN-tagged bridge); assign each DC a static IP.
- 6 vCPU, 8 GB RAM, ~32 GB disk, Windows Server 2025.
- Snapshot each VM right after its promotion reboot.

**Router / DNS / NTP** (OPNsense shown):
- **Per-zone DNS forwarding** (OPNsense: Services → Unbound DNS → Overrides → Domain overrides) so the
  resolver and any non-domain-joined host can resolve the AD zones:
  - `corp.internal` → 192.168.10.91
  - `partner.internal` → 192.168.10.93
  - `dev.corp.internal` → 192.168.10.92 (optional; it is delegated under corp, so the corp override
    usually covers it)
- **DHCP:** exclude the DC static IPs from the lab pool. Domain-joined clients should use a DC
  (192.168.10.91) for DNS, not the general resolver.
- **NTP:** run an NTP service on the lab and point the forest-root PDC (`CORPDC01`) at it. A >5 min skew
  silently breaks Kerberos and trust verification.
- **Firewall:** all three DCs + the test client share the lab segment, so their traffic is not filtered —
  AD replication and the trust work with no rules. Only if something sits on a *different* segment do you
  open AD ports to it: 53, 88, 135, 389, 445, 636, 3268, 3269, 9389 (ADWS), plus the RPC ephemeral range.

---

## Part A — Base setup (each VM)

Set the Windows computer name (`CORPDC01` / `DEVDC01` / `PARTDC01` per VM):

```powershell
Rename-Computer -NewName "CORPDC01" -Restart
```

After reboot, static IP (change the last octet per VM: .91 / .92 / .93):

```powershell
New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress 192.168.10.91 -PrefixLength 24 -DefaultGateway 192.168.10.1
```

For a lab you can drop the firewall to avoid surprises (optional):

```powershell
Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled False
```

DNS client settings are set per server in the parts below.

---

## Part B — CORPDC01: create Forest A (`corp.internal`)

```powershell
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 127.0.0.1

Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
Import-Module ADDSDeployment

Install-ADDSForest `
  -DomainName "corp.internal" `
  -DomainNetbiosName "CORP" `
  -ForestMode "WinThreshold" -DomainMode "WinThreshold" `
  -InstallDns `
  -SafeModeAdministratorPassword (Read-Host -AsSecureString "DSRM password") `
  -Force
```

`WinThreshold` = 2016 functional level — safe and sufficient. The server reboots automatically.

---

## Part C — DEVDC01: add child domain (`dev.corp.internal`)

DNS must point at CORPDC01 first so it can find the parent forest:

```powershell
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 192.168.10.91

Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
Import-Module ADDSDeployment

Install-ADDSDomain `
  -NewDomainName "dev" `
  -ParentDomainName "corp.internal" `
  -NewDomainNetbiosName "DEV" `
  -DomainType "ChildDomain" `
  -InstallDns `
  -Credential (Get-Credential "corp.internal\Administrator") `
  -SafeModeAdministratorPassword (Read-Host -AsSecureString "DSRM password") `
  -Force
```

`-Credential` needs **Enterprise Admin** of `corp.internal`, supplied in **DNS/FQDN form**
(`corp.internal\Administrator`, **not** `CORP\Administrator`) — the NetBIOS form fails credential
verification with *"You must supply a DNS resolvable domain name to which this user account belongs."*
DNS on DEVDC01 must already point at `192.168.10.91` (`nltest /dsgetdc:corp.internal` must find CORPDC01)
before this runs. The parent-child trust and a DNS delegation
for `dev.corp.internal` are created automatically. After reboot, point DEVDC01 at CORPDC01 first —
the child DC must resolve the forest-root `corp.internal` zone, which it does **not** hold a copy of —
then itself as secondary:

```powershell
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 192.168.10.91,127.0.0.1
```

---

## Part D — PARTDC01: create Forest B (`partner.internal`)

```powershell
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 127.0.0.1

Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
Import-Module ADDSDeployment

Install-ADDSForest `
  -DomainName "partner.internal" `
  -DomainNetbiosName "PARTNER" `
  -ForestMode "WinThreshold" -DomainMode "WinThreshold" `
  -InstallDns `
  -SafeModeAdministratorPassword (Read-Host -AsSecureString "DSRM password") `
  -Force
```

PARTDC01 keeps its DNS pointed at **itself** (127.0.0.1, set above) — it is a *separate forest root*,
so it must be its own DNS authority. It resolves `corp.internal` through the conditional forwarder in
Part E, **not** by pointing its DNS client at CORPDC01. Never set PARTDC01's DNS to 192.168.10.91.

---

## Part E — Cross-forest DNS (conditional forwarders, both ways)

```powershell
# On CORPDC01 (corp.internal): resolve partner.internal via PARTDC01
Add-DnsServerConditionalForwarderZone -Name "partner.internal" -MasterServers 192.168.10.93 -ReplicationScope "Forest"
```

```powershell
# On PARTDC01 (partner.internal): resolve corp.internal via CORPDC01
Add-DnsServerConditionalForwarderZone -Name "corp.internal" -MasterServers 192.168.10.91 -ReplicationScope "Forest"
```

`-ReplicationScope "Forest"` makes the forwarder AD-integrated so it reaches every DNS server in that
forest (including DEVDC01). Verify before creating the trust:

```powershell
Resolve-DnsName partner.internal -Type SOA   # on CORPDC01
nltest /dsgetdc:partner.internal              # should find PARTDC01
```

**Internet access for the DCs:** do **not** add the lab resolver or a public resolver to a DC's NIC DNS
list — a DC's client DNS must list only AD DNS (itself / other DCs), or it will intermittently misresolve
AD SRV/locator records (DNS client failover does not trigger on NXDOMAIN, only on timeout). Instead add
the lab's upstream resolver as a **server-level forwarder** on each DC, so names the DC isn't
authoritative for (and has no conditional forwarder for) go upstream:

```powershell
Add-DnsServerForwarder -IPAddress 192.168.10.1   # on each DC; the lab resolver's IP (or a public one like 1.1.1.1)
Resolve-DnsName www.microsoft.com                # confirm internet resolution
```

Without a forwarder the DCs still resolve the internet via root hints as long as they can reach it; the
forwarder is cleaner and cached. It leaves the NIC DNS untouched, so AD stays healthy.

---

## Part F — Two-way forest trust

**GUI (recommended first time):** on CORPDC01 open **Active Directory Domains and Trusts** → right-click
`corp.internal` → **Properties** → **Trusts** → **New Trust…** → Name `partner.internal` → **Forest
trust** → **Two-way** → **Both this domain and the specified domain** (supply EA creds for
`partner.internal`) → **Forest-wide authentication** on both sides → finish and confirm verification.

**Or netdom** (one line from CORPDC01; prompts for both forests' EA passwords):

```powershell
netdom trust corp.internal /Domain:partner.internal /add /twoway /ForestTRANSitive:Yes /UserD:PARTNER\Administrator /PasswordD:* /UserO:CORP\Administrator /PasswordO:*
```

**netdom is unreliable for the *forest* type** — it often creates an **external** trust (`ForestTransitive=False`)
even with `/ForestTRANSitive:Yes` and DNS resolving both ways, and its `/verify` then reports *"Access is
denied"* on the Domain Admins group lookup (that is the external trust's SID filtering, not a broken
channel). If you hit that, remove it and switch to the GUI above or the .NET method below:

```powershell
netdom trust corp.internal /Domain:partner.internal /remove /twoway /UserD:PARTNER\Administrator /PasswordD:* /UserO:CORP\Administrator /PasswordO:*
```

**Or PowerShell (.NET — scripted, reliably creates a *forest* trust), from CORPDC01:**

```powershell
$corpCred    = Get-Credential "corp.internal\Administrator"
$partnerCred = Get-Credential "partner.internal\Administrator"
$corpCtx     = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Forest','corp.internal',$corpCred.UserName,$corpCred.GetNetworkCredential().Password)
$partnerCtx  = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Forest','partner.internal',$partnerCred.UserName,$partnerCred.GetNetworkCredential().Password)
$corpForest    = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($corpCtx)
$partnerForest = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($partnerCtx)
$corpForest.CreateTrustRelationship($partnerForest,[System.DirectoryServices.ActiveDirectory.TrustDirection]::Bidirectional)
```

Keep **forest-wide** authentication (default), not selective. Verify:

```powershell
netdom trust corp.internal /Domain:partner.internal /verify
Get-ADTrust -Filter * -Server corp.internal | Format-Table Name,Direction,ForestTransitive,TrustType
```

You want `partner.internal` → **`ForestTransitive=True`**. Don't rely on `netdom /verify` (it false-fails
with *"Access is denied"* across a SID-filtered trust) — confirm functionally instead, from CORPDC01 with
your corp creds:

```powershell
Get-ADDomain -Server partner.internal | Format-List DNSRoot,NetBIOSName   # returns partner's info over the trust
```

If `ForestTransitive` is still `False` it is an external trust — remove it (`/remove /twoway`, above) and
recreate via the GUI or .NET method; an external trust cannot be upgraded in place. Make sure PARTDC01
resolves `corp.internal` (Part E) and the two PDCs' clocks are within 5 minutes before retrying.

Confirm the `trustedDomain` object the generator reads:

```powershell
Get-ADObject -Server corp.internal -SearchBase "CN=System,DC=corp,DC=internal" `
  -Filter "objectClass -eq 'trustedDomain'" `
  -Properties trustPartner,trustDirection,trustAttributes |
  Format-List trustPartner,trustDirection,trustAttributes
```

---

## Part G — One account for all three domains

With a two-way, forest-wide trust, a normal `corp.internal` user is seen as *Authenticated Users* in
`partner.internal`, so one account reads everything.

```powershell
# On CORPDC01 (corp.internal)
New-ADUser -Name "recon" -SamAccountName "recon" -UserPrincipalName "recon@corp.internal" `
  -AccountPassword (Read-Host -AsSecureString "recon password") `
  -Enabled $true -PasswordNeverExpires $true -Server corp.internal
```

`recon@corp.internal` authenticates to `corp.internal` (native), `dev.corp.internal` (intra-forest), and
`partner.internal` (forest trust). In `tests.json` / `forest.tests.json`, set the **config-level**
credentials to `recon` / `CORP` once and every entry inherits it. (To exercise the *per-forest* path
instead, create a separate user in `partner.internal` and put it only on that query.)

---

## Part H — Verify with the harness

Quick cross-forest bind as `recon` (from the test client at 192.168.10.20):

```powershell
$de = New-Object System.DirectoryServices.DirectoryEntry("LDAP://partner.internal/DC=partner,DC=internal","recon@corp.internal","<password>")
$de.distinguishedName   # returns DC=partner,DC=internal if trust + creds work
```

Generate a forest file against CORPDC01:

```powershell
TestClient.exe -g corpdc01.corp.internal -u recon -p <password> -d corp.internal -o forest.tests.json
```

Generate mode is fully CLI-driven and reads no tests JSON: `-g` is the server to discover from, `-o` is the
output file (default `./forest.tests.json`), and `-e` optionally sets the engines stamped on each query
(default `ADWS,LDAP,LDAPS`, e.g. `-e LDAP-GC`). Ensure ADWS/TCP 9389 is reachable on each DC.

Every query pins a concrete DC. With the default (direct) engines, confirm the file lists eight queries:

| Query | `Server` |
|---|---|
| `corp.internal`, Configuration, Schema, `DomainDnsZones.corp.internal`, `ForestDnsZones.corp.internal` | `corpdc01.corp.internal` |
| `dev.corp.internal`, `DomainDnsZones.dev.corp.internal` | `devdc01.dev.corp.internal` |
| `Trusted Domain - partner.internal` | `partdc01.partner.internal` |

With a Global Catalog engine (`-e LDAP-GC`) it lists two: `corp.internal` on CORPDC01 (a GC subtree search
there spans `dev.corp.internal`, Configuration and Schema, so those are dropped) and `partner.internal` on
PARTDC01.

By default no credentials are written to the file, so review it and then run the collection with the same
`-u/-p/-d` credentials, and convert the result for BloodHound. The chunk files land in the current folder:

```powershell
TestClient.exe -f forest.tests.json -u recon -p <password> -d corp.internal
BloodHoundConverter.exe .
```

The converter writes `.\BloodHoundOutput\<timestamp>\` with per-domain JSON files and a `BloodHound.zip` to
upload to BloodHound CE.

Add `-c` to bake the `-u/-p/-d` credentials into the generated file so it can be run with just
`-f forest.tests.json` — convenient in a throwaway lab, but the password is stored in plaintext, so protect
or delete the file afterwards:

```powershell
TestClient.exe -g corpdc01.corp.internal -u recon -p <password> -d corp.internal -c -o forest.tests.json
```

---

## Part I — AD CS (Enterprise CA): enable LDAPS and ADCS/ESC data

LDAPS (636) and LDAPS-GC (3269) need a **Server Authentication** certificate on each DC. A forest with no
CA has none, so a DC accepts the TCP connection on 636/3269 but **resets the TLS handshake** — those
protocols fail. This is true on every Windows Server version (2016–2025); it is **not** a 2025 difference.
An Enterprise CA fixes it: every DC in that forest **autoenrolls** a Server-Auth cert (no per-DC or manual
step) and LDAPS lights up on its own. It also creates the cert templates / CA / NTAuthStore objects that
exercise the converter's ADCS/ESC writers.

Install an Enterprise Root CA. In this lab it goes on CORPDC01 for simplicity (production puts the CA on a
dedicated member server, never a DC). Run as `CORP\Administrator` (Enterprise Admin):

```powershell
Install-WindowsFeature AD-Certificate -IncludeManagementTools
Install-AdcsCertificationAuthority `
  -CAType EnterpriseRootCA `
  -CACommonName "corp-Root-CA" `
  -KeyLength 2048 -HashAlgorithmName SHA256 `
  -ValidityPeriod Years -ValidityPeriodUnits 10 `
  -Force
```

Force and verify DC autoenrollment on each DC that should serve LDAPS (CORPDC01, DEVDC01):

```powershell
certutil -pulse
gpupdate /force
Get-ChildItem Cert:\LocalMachine\My |
  Where-Object { $_.EnhancedKeyUsageList.FriendlyName -contains 'Server Authentication' } |
  Format-List Subject, Issuer, NotAfter
```

You want a cert issued by `corp-Root-CA` carrying Server Authentication. The DC answers LDAPS as soon as
the cert is in the store (reboot the DC if 636 still resets after a minute).

Verify LDAPS end to end — the TestClient accepts any server cert, so the client does **not** need to trust
the corp CA (handy from a non-corp-joined collection box):

```powershell
$id = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier('corpdc01.corp.internal',636)
$c  = New-Object System.DirectoryServices.Protocols.LdapConnection($id)
$c.SessionOptions.SecureSocketLayer = $true
$c.SessionOptions.VerifyServerCertificate = { param($conn,$cert) $true }
$c.Bind(); "LDAPS bind OK"
```

All six engines are then testable — generate one file per engine with `-e` (e.g. `-e LDAPS-GC`) and
collect each: `ADWS`, `LDAP`, `LDAPS`, `ADWS-GC`, `LDAP-GC`, `LDAPS-GC` (the two `3268` GC engines already
work without a cert; the CA is what unblocks `LDAPS` and `LDAPS-GC`).

**Caveats:**
- The corp Enterprise CA autoenrolls DCs in the **corp.internal forest only** (CORPDC01, DEVDC01).
  **partner.internal is a separate forest** — PARTDC01 gets no cert from it, so LDAPS/LDAPS-GC against
  `partner.internal` still fail. To cover it, install a second Enterprise CA in the partner forest (same
  steps on PARTDC01).
- Installing the CA on a DC is a lab shortcut; keep the CA off DCs in production.
- Re-running the collection after this now includes cert templates, the CA, and NTAuthStore, so the
  converter's ADCS/ESC node writers finally get real data.

---

## Part J — Test objects (exercise the collector and converter)

These deliberately populate ACEs and attributes the default directory does not, so a re-collection
(Part H) and conversion exercise the ACL edges, the SPN/shadow-credential/DCSync paths, and the ADCS
template fields (`certificatepolicy`, `issuancepolicies`, `applicationpolicies`) that no stock template
carries. **Lab-only — these ACLs are intentionally weak; never do this in production.** Run on CORPDC01,
elevated; the ADCS part needs the CA from Part I. Run section by section so one failure doesn't block the
rest.

```powershell
Import-Module ActiveDirectory
$domainDn = (Get-ADDomain).DistinguishedName
$configNc = (Get-ADRootDSE).configurationNamingContext
```

### J.1 — OU, users, groups, a computer, SPNs

```powershell
New-ADOrganizationalUnit -Name "Lab" -Path $domainDn -ProtectedFromAccidentalDeletion:$false
$labOu = "OU=Lab,$domainDn"
$pw = Read-Host -AsSecureString "password for the lab accounts"

New-ADUser -Name "alice"   -SamAccountName alice   -Path $labOu -AccountPassword $pw -Enabled $true   # target
New-ADUser -Name "bob"     -SamAccountName bob     -Path $labOu -AccountPassword $pw -Enabled $true   # operator
New-ADUser -Name "svc_sql" -SamAccountName svc_sql -Path $labOu -AccountPassword $pw -Enabled $true   # kerberoastable
New-ADComputer -Name "SQL01" -SamAccountName "SQL01$" -DNSHostName "sql01.corp.internal" -Path $labOu -Enabled $true
Set-ADUser svc_sql -ServicePrincipalNames @{ Add = "MSSQLSvc/sql01.corp.internal:1433" }   # -> hasspn + SPNTargets

New-ADGroup -Name "Widgets-Admins" -SamAccountName Widgets-Admins -GroupScope Universal -Path $labOu   # Universal: required for the ESC13 OID link in J.3
New-ADGroup -Name "Helpdesk"       -SamAccountName Helpdesk       -GroupScope Global -Path $labOu
Add-ADGroupMember -Identity Widgets-Admins -Members Helpdesk   # nested group
Add-ADGroupMember -Identity Helpdesk -Members bob
New-ADGroup -Name "ESC13-Group" -SamAccountName ESC13-Group -GroupScope Universal -Path $labOu   # stays EMPTY: OID-mapped target (J.3)
Add-ADGroupMember -Identity Widgets-Admins -Members ESC13-Group   # chain: ESC13-Group -> Widgets-Admins
```

### J.2 — ACEs (one representative per BloodHound edge)

```powershell
function Add-Ace {
  param([string]$TargetDN,[string]$IdentitySid,[System.DirectoryServices.ActiveDirectoryRights]$Rights,[guid]$ObjectType=[guid]::Empty)
  $acl = Get-Acl "AD:\$TargetDN"
  $id  = [System.Security.Principal.SecurityIdentifier]$IdentitySid
  $ace = if ($ObjectType -eq [guid]::Empty) {
    New-Object System.DirectoryServices.ActiveDirectoryAccessRule($id,$Rights,'Allow')
  } else {
    New-Object System.DirectoryServices.ActiveDirectoryAccessRule($id,$Rights,'Allow',$ObjectType)
  }
  $acl.AddAccessRule($ace); Set-Acl "AD:\$TargetDN" $acl
}

$bobSid = (Get-ADUser bob).SID.Value
$aliceSid = (Get-ADUser alice).SID.Value
$hdSid  = (Get-ADGroup Helpdesk).SID.Value
$aliceDn = (Get-ADUser alice).DistinguishedName
$waDn    = (Get-ADGroup 'Widgets-Admins').DistinguishedName

# One representative ACE per edge. The control-access / property-write GUIDs are inlined per call so a
# partially-pasted block cannot leave a GUID reference null.

# On alice (user)
Add-Ace $aliceDn $bobSid GenericAll                                                     # GenericAll
Add-Ace $aliceDn $bobSid ExtendedRight ([guid]'00299570-246d-11d0-a768-00aa006e0529')   # ForceChangePassword
Add-Ace $aliceDn $bobSid WriteProperty ([guid]'5b47d60f-6090-40b2-9f37-2a4de88f3063')   # AddKeyCredentialLink (shadow creds)
Add-Ace $aliceDn $bobSid WriteProperty ([guid]'f3a64788-5306-11d1-a9c5-0000f80367c1')   # WriteSPN
Add-Ace $aliceDn $hdSid  GenericWrite                                                   # GenericWrite

# On Widgets-Admins (group)
Add-Ace $waDn $hdSid    WriteProperty ([guid]'bf9679c0-0de6-11d0-a285-00aa003049e2')    # AddMember
Add-Ace $waDn $bobSid   WriteDacl                                                       # WriteDacl
Add-Ace $waDn $aliceSid WriteOwner                                                      # WriteOwner
$g = Get-Acl "AD:\$waDn"; $g.SetOwner([System.Security.Principal.SecurityIdentifier]$bobSid); Set-Acl "AD:\$waDn" $g   # Owns

# On the Lab OU and the domain root
Add-Ace $labOu    $bobSid WriteProperty ([guid]'f30e3bbe-9ff0-11d1-b603-0000f80367c1')  # WriteGPLink
Add-Ace $domainDn $bobSid ExtendedRight ([guid]'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2')  # DCSync (1/2)
Add-Ace $domainDn $bobSid ExtendedRight ([guid]'1131f6ad-9c07-11d1-f79f-00c04fc2dcd2')  # DCSync (2/2)
```

### J.3 — ADCS: ESC13 issuance policy + a mapping-test template

```powershell
$pkiServices  = "CN=Public Key Services,CN=Services,$configNc"
$oidContainer = "CN=OID,$pkiServices"
$templates    = "CN=Certificate Templates,$pkiServices"
$issuanceOid  = "1.3.6.1.4.1.311.21.8.9999999.1.1.1.400.1"   # arbitrary, unique to the lab
$tmplOid      = "1.3.6.1.4.1.311.21.8.9999999.1.1.1.400.2"
$esc13Dn      = (Get-ADGroup 'ESC13-Group').DistinguishedName

# 1) Issuance-policy OID linked to a group (ESC13: OID -> group). msDS-OIDToGroupLink requires a
#    Universal, security-enabled group that is EMPTY (ESC13-Group, J.1) — membership is conferred by the
#    cert. ESC13-Group is a member of Widgets-Admins, so the chain is cert -> OID -> ESC13-Group ->
#    Widgets-Admins (which carries the J.2 ACEs).
New-ADObject -Type 'msPKI-Enterprise-Oid' -Name "LabIssuancePolicy" -Path $oidContainer -OtherAttributes @{
  'msPKI-Cert-Template-OID' = $issuanceOid
  'flags'                   = 2               # issuance policy ( (flags & 2) == 2 )
  'msDS-OIDToGroupLink'     = $esc13Dn        # ESC13 link (must be an empty Universal group)
  'displayName'             = "Lab Issuance Policy"
}

# 2) Schema-4 template asserting that policy, with RA policy + RA application-policy composite.
#    Exercises certificatepolicy, issuancepolicies, and the schema-3/4 applicationpolicies parser.
#    (A mapping-validation object; not meant to be enrolled.) Binary period blobs copied from a stock one.
$stock = Get-ADObject -SearchBase $templates -LDAPFilter '(cn=User)' -Properties pKIExpirationPeriod,pKIOverlapPeriod,flags
New-ADObject -Type 'pKICertificateTemplate' -Name "LabPolicyTest" -Path $templates -OtherAttributes @{
  'displayName'                          = "Lab Policy Test"
  'revision'                             = 100
  'msPKI-Template-Schema-Version'        = 4
  'msPKI-Minimal-Key-Size'               = 2048
  'flags'                                = [int]$stock.flags
  'pKIExtendedKeyUsage'                  = '1.3.6.1.5.5.7.3.2'          # Client Authentication
  'msPKI-Certificate-Application-Policy' = '1.3.6.1.5.5.7.3.2'
  'msPKI-Certificate-Policy'             = $issuanceOid                 # -> certificatepolicy
  'msPKI-RA-Policies'                    = $issuanceOid                 # -> issuancepolicies
  'msPKI-RA-Signature'                   = 1
  'msPKI-RA-Application-Policies'        = 'msPKI-RA-Application-Policies`PZPWSTR`1.3.6.1.4.1.311.20.2.1`'  # schema-3/4 -> applicationpolicies
  'msPKI-Certificate-Name-Flag'          = 1                            # ENROLLEE_SUPPLIES_SUBJECT
  'msPKI-Enrollment-Flag'                = 0
  'msPKI-Cert-Template-OID'              = $tmplOid
  'pKIExpirationPeriod'                  = $stock.pKIExpirationPeriod
  'pKIOverlapPeriod'                     = $stock.pKIOverlapPeriod
}
```

For a BloodHound-flagged, enrollable **ESC1** edge (optional, GUI is most reliable): in `certtmpl.msc`
duplicate the stock **User** template, on the copy set *Subject Name → Supply in the request*, keep
Client Authentication, drop manager approval, grant **Enroll** to `Widgets-Admins`, then issue it via
`certsrv.msc → Certificate Templates → New → Certificate Template to Issue`.

### J.4 — Re-collect and verify

Re-run Part H's collection and the conversion, then confirm in the output:
- ACE edges on `alice`: `GenericAll`, `ForceChangePassword`, `AddKeyCredentialLink`, `WriteSPN`,
  `GenericWrite`; on `Widgets-Admins`: `AddMember`, `WriteDacl`, `WriteOwner`, `Owns`; `WriteGPLink` on
  the Lab OU; `DCSync` (GetChanges + GetChangesAll) on the domain.
- `svc_sql`: `hasspn=true`, and an `MSSQLSvc` → `SQL01` entry in `SPNTargets`.
- `LabPolicyTest`: `certificatepolicy=[<issuanceOid>]`, `issuancepolicies=[<issuanceOid>]`,
  `applicationpolicies=[1.3.6.1.4.1.311.20.2.1]`.
- `LabIssuancePolicy`: an IssuancePolicy node with an OID-to-group link to `ESC13-Group` (which is a
  member of `Widgets-Admins`) — ESC13.

To clean up later: `Remove-ADOrganizationalUnit "OU=Lab,$domainDn" -Recursive -Confirm:$false` and delete
the two `CN=Lab*` objects under `CN=OID` and `CN=Certificate Templates`.

---

## Lab tips
- Snapshot each VM after promotion — trust/DNS experiments break easily and revert cleanly.
- Keep time consistent across all three (a single lab NTP source); >5 min skew breaks Kerberos and the trust.
- RAM: 2 GB per DC runs; 4 GB is comfortable.
