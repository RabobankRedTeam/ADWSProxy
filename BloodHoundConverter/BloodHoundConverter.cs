using BloodHoundConverter.Writers;
using log4net;
using Newtonsoft.Json;
using System.IO.Compression;

namespace BloodHoundConverter
{
    internal partial class BloodHoundConverter
    {
        // Case-insensitive because AD distinguished names compare case-insensitively, and lookups
        // (ContainedBy parent DN, group member/memberOf DNs) arrive with inconsistent casing.
        internal static Dictionary<string, ObjectIdentity> DnToIdentityMap { get; set; } = new(StringComparer.OrdinalIgnoreCase);
        internal static Dictionary<string, ObjectType> IdToTypeMap { get; set; } = [];
        // Parent DN -> its direct children, the inverse of the ContainedBy lookup. Drives the
        // ChildObjects array (Contains edges) on domains, OUs and containers. Case-insensitive to
        // match DN comparison.
        internal static Dictionary<string, List<ObjectIdentity>> ChildObjectsByParentDn { get; set; } = new(StringComparer.OrdinalIgnoreCase);

        // ObjectIdentifiers that the third pass actually writes as nodes. A collected object that is not
        // emitted (schema object, attribute-less stub, the flags-less CN=OID container, a well-known
        // principal handled by injection) is excluded, so containment resolution never points an edge at
        // a node absent from the output. Populated in the first pass from the shared route classifier.
        internal static HashSet<string> EmittedIds { get; set; } = new(StringComparer.OrdinalIgnoreCase);

        // Universal well-known principals (raw SID) referenced within each domain (domain FQDN upper ->
        // raw SIDs). After the real objects are written, a domain-scoped node is injected for each so no
        // scoped ACE/membership reference dangles. BUILTIN groups (S-1-5-32-RID) are excluded because they
        // exist as real group objects in every domain.
        internal static readonly Dictionary<string, HashSet<string>> ReferencedWellKnownByDomain = new(StringComparer.OrdinalIgnoreCase);

        internal static void RecordWellKnownReference(string? domainUpper, string? rawSid)
        {
            if (string.IsNullOrEmpty(domainUpper) || string.IsNullOrEmpty(rawSid)) return;
            if (!WellKnownSids.Table.ContainsKey(rawSid)) return;
            if (!ReferencedWellKnownByDomain.TryGetValue(domainUpper, out var set))
            {
                ReferencedWellKnownByDomain[domainUpper] = set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            }
            set.Add(rawSid);
        }

        // The forest root for a domain: the shortest SID-bearing domain it is a suffix of (the top of its
        // domain tree in the dataset). Used to scope forest-wide principals (S-1-5-9) to the forest root.
        internal static string ForestRootOf(string? domainUpper)
        {
            if (string.IsNullOrEmpty(domainUpper)) return domainUpper ?? string.Empty;
            string best = domainUpper;
            int bestLen = int.MaxValue;
            foreach (var known in DomainToSidMap.Keys)
            {
                var k = known.ToUpperInvariant();
                if ((domainUpper.Equals(k, StringComparison.OrdinalIgnoreCase) ||
                     domainUpper.EndsWith("." + k, StringComparison.OrdinalIgnoreCase)) && k.Length < bestLen)
                {
                    best = k;
                    bestLen = k.Length;
                }
            }
            return best;
        }

        // The BloodHound node kind an object is written as (or Skip when it is not emitted). The first
        // pass uses this to build EmittedIds and the third pass switches on it to pick the writer, so a
        // single classifier keeps "what is emitted" and "how it is emitted" from drifting apart.
        internal enum BhRoute
        {
            Skip, Domain, User, Computer, Group, OU, GPO, Container, Others,
            EnterpriseCA, RootCA, AIACA, NTAuthStore, CertTemplate, IssuancePolicy
        }

        // Mirrors AD's objectClass superclass ordering: subclasses are matched before their base classes
        // (gMSA/sMSA before computer, computer before user, groupPolicyContainer before container) so the
        // route matches the most specific class.
        internal static BhRoute ClassifyRoute(IEnumerable<string> objectClasses, string dn, string? sid, string? flags, bool hasNtSecurityDescriptor)
        {
            bool Has(string c) => objectClasses.Contains(c, StringComparer.OrdinalIgnoreCase);

            if ((Has("domain") || Has("domainDNS")) && !string.IsNullOrEmpty(sid)) return BhRoute.Domain;
            if (Has("msDS-GroupManagedServiceAccount") || Has("msDS-ManagedServiceAccount")) return BhRoute.User;
            if (Has("foreignSecurityPrincipal"))
            {
                // Genuine cross-domain principals (domain-relative SID) become Base ("others") nodes;
                // universal/well-known identities are emitted by the injection pass, not here.
                return !string.IsNullOrEmpty(sid) && sid.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase)
                    ? BhRoute.Others : BhRoute.Skip;
            }
            if (Has("computer")) return BhRoute.Computer;
            if (Has("user")) return BhRoute.User;
            if (Has("group")) return BhRoute.Group;
            if (Has("organizationalUnit")) return BhRoute.OU;
            if (Has("groupPolicyContainer")) return BhRoute.GPO;
            if (Has("container")) return BhRoute.Container;
            if (Has("pKIEnrollmentService")) return BhRoute.EnterpriseCA;
            if (Has("certificationAuthority"))
            {
                if (dn.Contains("CN=Certification Authorities", StringComparison.OrdinalIgnoreCase)) return BhRoute.RootCA;
                if (dn.Contains("CN=AIA", StringComparison.OrdinalIgnoreCase)) return BhRoute.AIACA;
                if (dn.Contains("CN=NTAuthCertificates", StringComparison.OrdinalIgnoreCase)) return BhRoute.NTAuthStore;
                return BhRoute.Skip;
            }
            if (Has("pKICertificateTemplate")) return BhRoute.CertTemplate;
            if (Has("msPKI-Enterprise-Oid"))
            {
                // Only OID objects flagged as issuance policies (flags bit 1) are emitted; the container
                // OID and the per-template OID assignments are not.
                return flags != null && long.TryParse(flags, out long oidFlags) && (oidFlags & 2) == 2
                    ? BhRoute.IssuancePolicy : BhRoute.Skip;
            }

            // Catch-all: any remaining object with its own security descriptor is emitted as a Base
            // ("others") node, except the schema/display-specifier scaffolding that carries no ACL meaning.
            bool isSchema = objectClasses.Any(oc =>
                oc.Equals("classSchema", StringComparison.OrdinalIgnoreCase) ||
                oc.Equals("attributeSchema", StringComparison.OrdinalIgnoreCase) ||
                oc.Equals("displaySpecifier", StringComparison.OrdinalIgnoreCase) ||
                oc.Equals("dSUISettings", StringComparison.OrdinalIgnoreCase) ||
                oc.Equals("subSchema", StringComparison.OrdinalIgnoreCase));
            return !isSchema && hasNtSecurityDescriptor ? BhRoute.Others : BhRoute.Skip;
        }

        // Walks up the DN one RDN at a time and returns the nearest ancestor that is an emitted node, or
        // null when none is (the object sits directly under a non-emitted root). Non-emitted ancestors are
        // transparent, so an emitted object always attaches to an emitted container and no Contains /
        // ContainedBy edge dangles.
        internal static string? FindEmittedAncestorDn(string childDn)
        {
            string dn = childDn;
            while (true)
            {
                int comma = dn.IndexOf(',');
                if (comma <= 0 || comma >= dn.Length - 1) return null;
                dn = dn[(comma + 1)..].Trim();
                if (DnToIdentityMap.TryGetValue(dn, out var identity) && EmittedIds.Contains(identity.Id))
                {
                    return dn;
                }
            }
        }

        // GPO distinguished name -> its ObjectIdentifier (objectGUID), for resolving gPLink targets.
        // Case-insensitive because gPLink stores the GPO DN with inconsistent casing (e.g. "cn=").
        internal static Dictionary<string, string> GpoDnToGuidMap { get; set; } = new(StringComparer.OrdinalIgnoreCase);
        // Domain name -> the trusts declared by that domain's trustedDomain objects.
        internal static Dictionary<string, List<DomainTrust>> DomainTrustsByDomain { get; set; } = new(StringComparer.OrdinalIgnoreCase);
        internal static Dictionary<string, string> DomainToSidMap { get; set; } = [];
        // dNSHostName -> computer ObjectIdentifier, for resolving SPN hosts (AllowedToDelegate,
        // SPNTargets) and a CA's HostingComputer. Case-insensitive because DNS names and SPN host
        // components compare case-insensitively.
        internal static Dictionary<string, string> DnsNameToIdMap { get; set; } = new(StringComparer.OrdinalIgnoreCase);
        internal static Dictionary<string, string> CertTemplateCnToGuidMap { get; set; } = [];
        internal static Dictionary<string, HashSet<ObjectIdentity>> GroupMembersMap { get; set; } = [];

        private static readonly ILog log = LogManager.GetLogger(typeof(BloodHoundConverter));

        private static readonly List<string> EmptyList = [];
        private static List<string> GetAttributeValues(Dictionary<string, List<string>> attributes, string key)
        {

            return attributes.TryGetValue(key, out var values) ? values : EmptyList;
        }

        private static string? GetFirstAttributeValue(Dictionary<string, List<string>> attributes, string key)
        {
            if (attributes.TryGetValue(key, out var values) && values.Count > 0)
            {
                return values[0];
            }
            return null;
        }

        public static string ExtractDomainFromDn(string dn)
        {
            if (string.IsNullOrWhiteSpace(dn)) return string.Empty;

            try
            {
                var parts = dn.Split(',')
                    .Select(part => part.Trim())
                    .ToArray();

                var domainComponents = new List<string>();

                // Iterate backwards from the rightmost component
                for (int i = parts.Length - 1; i >= 0; i--)
                {
                    if (parts[i].StartsWith("DC=", StringComparison.OrdinalIgnoreCase))
                    {
                        // Prepend to preserve natural domain order (e.g. BadBlood.test)
                        domainComponents.Insert(0, parts[i][3..]);
                    }
                    else
                    {
                        // Stop as soon as we hit a non-DC component (e.g. CN=System, OU=Users)
                        break;
                    }
                }

                return domainComponents.Count == 0
                    ? string.Empty
                    : string.Join(".", domainComponents).ToUpperInvariant();
            }
            catch
            {
                return string.Empty;
            }
        }

        public static IEnumerable<DataHolder> StreamDataHoldersFromChunkList(IEnumerable<string> sourceChunkFilePaths)
        {
            foreach (var filePath in sourceChunkFilePaths.Order())
            {
                log.Info($"Opening stream for chunk: {Path.GetFileName(filePath)}");
                using StreamReader sr = new(filePath);
                using JsonTextReader reader = new(sr);
                JsonSerializer serializer = new();
                while (reader.Read())
                {
                    if (reader.TokenType == JsonToken.PropertyName &&
                        (reader.Value?.ToString() ?? string.Empty).Equals("Values", StringComparison.OrdinalIgnoreCase))
                    {
                        reader.Read();
                        if (reader.TokenType != JsonToken.StartArray) continue;
                        while (reader.Read() && reader.TokenType != JsonToken.EndArray)
                        {
                            if (reader.TokenType == JsonToken.StartObject &&
                                reader.Path.StartsWith("Values", StringComparison.Ordinal))
                            {
                                var record = serializer.Deserialize<DataHolder>(reader);
                                if (record != null)
                                {
                                    yield return record;
                                }
                            }
                        }
                    }
                }
            }
        }

        public static void ProcessJsonChunks(List<string> sourceChunkFilePaths, string outputDirectoryPath)
        {
            Directory.CreateDirectory(outputDirectoryPath);

            // 🎯 Establish clean, dynamic output base naming patterns derived from the first file matching string
            string referenceFileName = Path.GetFileNameWithoutExtension(sourceChunkFilePaths[0]);

            // Safely extract a base prefix (strips out trailing '_partX' or '_engine' naming tags)
            string baseFileTarget = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            string finalOutPrefix = Path.Combine(outputDirectoryPath, $"{baseFileTarget}_bloodhound");
            string infoDirectory = Path.Combine(outputDirectoryPath, "info");
            Directory.CreateDirectory(infoDirectory);

            log.Info($"Initializing BloodHound output files with target prefix: {finalOutPrefix}");

            var results = StreamDataHoldersFromChunkList(sourceChunkFilePaths).ToList();

            if (results.Count == 0)
            {
                log.Warn("No valid JSON objects were found in the provided source chunk files.");
                return;
            }
            else
            {
                log.Info($"Total JSON objects found across all chunks: {results.Count}");
            }

            // The same object can be collected more than once (overlapping queries, e.g. a Global Catalog subtree
            // search that spans child naming contexts). Every pass below iterates this list, so a repeat would become
            // a duplicate node, child or member. Keep one copy per DN, preferring the one with the most attributes
            // (a full replica over a GC partial one), in order of first appearance.
            var indexByDn = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            var uniqueResults = new List<DataHolder>(results.Count);
            foreach (var obj in results)
            {
                if (string.IsNullOrEmpty(obj.DistinguishedName))
                {
                    uniqueResults.Add(obj);
                    continue;
                }
                if (indexByDn.TryGetValue(obj.DistinguishedName, out int existing))
                {
                    if (obj.Attributes.Count > uniqueResults[existing].Attributes.Count)
                    {
                        uniqueResults[existing] = obj;
                    }
                    continue;
                }
                indexByDn[obj.DistinguishedName] = uniqueResults.Count;
                uniqueResults.Add(obj);
            }
            if (uniqueResults.Count < results.Count)
            {
                log.Info($"Collapsed {results.Count - uniqueResults.Count} duplicate objects (same distinguishedName collected more than once); {uniqueResults.Count} unique objects remain");
            }
            results = uniqueResults;

            // Active Directory Standard Primary Group RIDs
            const string RID_DOMAIN_USERS = "513";
            const string RID_DOMAIN_GUESTS = "514";
            const string RID_DOMAIN_COMPUTERS = "515";
            const string RID_DOMAIN_CONTROLLERS = "516";
            const string RID_READONLY_DCS = "521";

            // UserAccountControl Flags
            const int UAC_SERVER_TRUST_ACCOUNT = 0x2000;  // Domain Controller
            const int UAC_PARTIAL_SECRETS_ACCOUNT = 0x08000000;

            int processedCount = 0;
            log.Info("Started first pass - Mapping objects");
            foreach (var obj in results)
            {
                string dn = obj.DistinguishedName;
                if (string.IsNullOrEmpty(dn)) continue;

                var attributes = obj.Attributes;
                string rawGuidStr = GetFirstAttributeValue(attributes, "objectGUID") ?? string.Empty;
                string guidString = Helpers.ResolveGuid(rawGuidStr, dn, out bool _);

                var rawClasses = GetAttributeValues(attributes, "objectClass");
                var classSet = new HashSet<string>(rawClasses, StringComparer.OrdinalIgnoreCase);

                if (classSet.Contains("pKICertificateTemplate"))
                {
                    string? cn = GetFirstAttributeValue(attributes, "cn");

                    if (!string.IsNullOrEmpty(cn) && !string.IsNullOrEmpty(guidString))
                    {
                        CertTemplateCnToGuidMap[cn] = guidString;
                    }
                }

                string? rawSid = GetFirstAttributeValue(attributes, "objectSid");
                string? sid = Helpers.ParseSid(rawSid);

                // Domain-scope well-known/built-in principal identities ({DOMAIN}-{SID}) so the node's
                // identifier matches every scoped ACE/membership reference to it; domain-relative and
                // unrecognized SIDs pass through unchanged.
                string objectDomainUpper = ExtractDomainFromDn(dn).ToUpperInvariant();
                string scopedSid = Helpers.ScopeSid(sid, objectDomainUpper, ForestRootOf(objectDomainUpper));
                string identifier = !string.IsNullOrEmpty(scopedSid) ? scopedSid : guidString;

                // Map every GPO's distinguished name to its objectGUID for gPLink (Links) resolution,
                // independent of the node-type branch below.
                if (classSet.Contains("groupPolicyContainer"))
                {
                    GpoDnToGuidMap[dn] = identifier;
                }

                if (classSet.Contains("trustedDomain"))
                {
                    var trust = Helpers.BuildDomainTrust(
                        GetFirstAttributeValue(attributes, "securityIdentifier"),
                        GetFirstAttributeValue(attributes, "trustPartner"),
                        GetFirstAttributeValue(attributes, "trustDirection"),
                        GetFirstAttributeValue(attributes, "trustAttributes"));
                    if (trust != null)
                    {
                        string owningDomain = ExtractDomainFromDn(dn).ToUpperInvariant();
                        if (!DomainTrustsByDomain.TryGetValue(owningDomain, out var domainTrusts))
                        {
                            domainTrusts = [];
                            DomainTrustsByDomain[owningDomain] = domainTrusts;
                        }
                        domainTrusts.Add(trust);
                    }
                }

                ObjectType exactType = ObjectType.Base;
                string defaultRid = string.Empty;

                // Only real domains (which carry a domain SID) are typed as Domain. Application-partition
                // roots (DomainDnsZones/ForestDnsZones) share objectClass domainDNS but have no SID, so
                // they fall through and are emitted as containers rather than SID-less domain nodes.
                //
                // objectClass lists the whole superclass chain, so subclasses must be matched before their
                // base classes: gMSA/sMSA before computer, computer before user, and groupPolicyContainer
                // before container. This order mirrors the node-writer dispatch below so the type maps
                // agree with the emitted node kinds.
                if ((classSet.Contains("domain") || classSet.Contains("domainDNS")) && !string.IsNullOrEmpty(sid))
                {
                    string domainName = ExtractDomainFromDn(dn);
                    exactType = ObjectType.Domain;

                    if (!string.IsNullOrWhiteSpace(domainName) &&
                        !DomainToSidMap.ContainsKey(domainName) &&
                        !string.IsNullOrEmpty(sid))
                    {
                        DomainToSidMap[domainName] = sid;
                    }
                }
                else if (classSet.Contains("builtinDomain"))
                {
                    exactType = ObjectType.Container;
                }
                else if (classSet.Contains("msDS-GroupManagedServiceAccount") || classSet.Contains("msDS-ManagedServiceAccount"))
                {
                    // Machine-account subclasses of computer, but emitted as users; match before computer.
                    exactType = ObjectType.User;
                    defaultRid = RID_DOMAIN_COMPUTERS;
                }
                else if (classSet.Contains("foreignSecurityPrincipal"))
                {
                    // CN=ForeignSecurityPrincipals stubs and the CN=WellKnown Security Principals objects
                    // both carry this class, identified by their objectSid. A domain-relative SID
                    // (S-1-5-21-...) is a genuine principal from another domain/forest, emitted as a
                    // resolvable Base node. Every other SID is a universal/well-known identity (Everyone,
                    // Authenticated Users, SYSTEM, Enterprise Domain Controllers, login types, ...): it is
                    // not registered as a typed object, so InjectWellKnownGroups can emit the useful ones
                    // as proper Group nodes. Its DN is still recorded (as the well-known SID) so an
                    // explicit `member` reference to it resolves to that injected group.
                    if (!string.IsNullOrEmpty(sid) && sid.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase))
                    {
                        exactType = ObjectType.Base;
                    }
                    else
                    {
                        if (!string.IsNullOrEmpty(sid))
                        {
                            // Record the universal principal's DN against its domain-scoped identity so an
                            // explicit `member` reference resolves to the injected well-known node, and mark
                            // it referenced so that node is emitted.
                            var wellKnownType = WellKnownSids.Table.TryGetValue(sid, out var wk) ? wk.Type : ObjectType.Group;
                            DnToIdentityMap[dn] = new ObjectIdentity { Id = identifier, Type = wellKnownType };
                            RecordWellKnownReference(objectDomainUpper, sid);
                        }
                        continue;
                    }
                }
                else if (classSet.Contains("computer"))
                {
                    exactType = ObjectType.Computer;

                    string? uacStr = GetFirstAttributeValue(attributes, "userAccountControl");
                    int uac = int.TryParse(uacStr, out int parsedUac) ? parsedUac : 0;

                    if ((uac & UAC_PARTIAL_SECRETS_ACCOUNT) != 0)
                    {
                        // Read-Only Domain Controller
                        defaultRid = RID_READONLY_DCS;
                    }
                    else if ((uac & UAC_SERVER_TRUST_ACCOUNT) != 0)
                    {
                        // Writable Domain Controller
                        defaultRid = RID_DOMAIN_CONTROLLERS;
                    }
                    else
                    {
                        // Member Server / Workstation
                        defaultRid = RID_DOMAIN_COMPUTERS;
                    }

                    string? dnsHostName = GetFirstAttributeValue(attributes, "dNSHostName");
                    if (!string.IsNullOrWhiteSpace(dnsHostName))
                    {
                        DnsNameToIdMap[dnsHostName] = identifier;
                    }
                }
                else if (classSet.Contains("user"))
                {
                    exactType = ObjectType.User;

                    if (sid?.EndsWith("-501", StringComparison.OrdinalIgnoreCase) == true)
                    {
                        defaultRid = RID_DOMAIN_GUESTS;
                    }
                    else
                    {
                        defaultRid = RID_DOMAIN_USERS;
                    }
                }
                else if (classSet.Contains("group"))
                {
                    exactType = ObjectType.Group;
                }
                else if (classSet.Contains("organizationalUnit"))
                {
                    exactType = ObjectType.OU;
                }
                else if (classSet.Contains("groupPolicyContainer"))
                {
                    exactType = ObjectType.GPO;
                }
                else if (classSet.Contains("container"))
                {
                    exactType = ObjectType.Container;
                }
                else if (classSet.Contains("pKIEnrollmentService"))
                {
                    exactType = ObjectType.EnterpriseCA;
                }
                else if (classSet.Contains("certificationAuthority"))
                {
                    if (dn.Contains("CN=Certification Authorities", StringComparison.OrdinalIgnoreCase))
                    {
                        exactType = ObjectType.RootCA;
                    }
                    else if (dn.Contains("CN=AIA", StringComparison.OrdinalIgnoreCase))
                    {
                        exactType = ObjectType.AIACA;
                    }
                    else if (dn.Contains("CN=NTAuthCertificates", StringComparison.OrdinalIgnoreCase))
                    {
                        exactType = ObjectType.NTAuthStore;
                    }
                }
                else if (classSet.Contains("pKICertificateTemplate"))
                {
                    exactType = ObjectType.CertTemplate;
                }
                else if (classSet.Contains("msPKI-Enterprise-Oid"))
                {
                    exactType = ObjectType.IssuancePolicy;
                }
                else
                {
                    exactType = ObjectType.Base;
                }

                // Extract primaryGroupID attribute from LDAP, falling back to schema default RID if absent
                string primaryGroupRid = GetFirstAttributeValue(attributes, "primaryGroupID") ?? defaultRid;

                // Calculate the full Primary Group SID (e.g., S-1-5-21-XXX-513), domain-scoping a built-in
                // target group so the membership edge points at the same node as everywhere else.
                string? primaryGroupSid = !string.IsNullOrEmpty(primaryGroupRid) && !string.IsNullOrWhiteSpace(sid)
                    ? Helpers.ScopeSid(Helpers.CalculateGroupSid(sid, primaryGroupRid), objectDomainUpper)
                    : null;

                var identity = new ObjectIdentity { Id = identifier, Type = exactType, PrimaryGroupSid = primaryGroupSid };
                DnToIdentityMap[dn] = identity;
                IdToTypeMap[identifier] = exactType;

                // Record whether the third pass will emit this object as a node, using the same classifier
                // it switches on, so the containment index built below only links emitted nodes.
                if (ClassifyRoute(rawClasses, dn, sid, GetFirstAttributeValue(attributes, "flags"),
                        GetFirstAttributeValue(attributes, "ntSecurityDescriptor") != null) != BhRoute.Skip)
                {
                    EmittedIds.Add(identifier);
                }
            }
            log.Info("Completed first pass");

            // Index each emitted object under its nearest emitted ancestor (not its immediate parent), so a
            // non-emitted intermediate container is transparent: its emitted children appear in the nearest
            // emitted container's ChildObjects and no Contains edge points at a node absent from the output.
            // Domains stay top-level (never listed as a child of their parent domain).
            foreach (var obj in results)
            {
                string dn = obj.DistinguishedName;
                if (string.IsNullOrEmpty(dn) || !DnToIdentityMap.TryGetValue(dn, out var identity)) continue;
                if (identity.Type == ObjectType.Domain || !EmittedIds.Contains(identity.Id)) continue;

                string? ancestorDn = FindEmittedAncestorDn(dn);
                if (ancestorDn == null) continue;
                if (!ChildObjectsByParentDn.TryGetValue(ancestorDn, out var children))
                {
                    ChildObjectsByParentDn[ancestorDn] = children = [];
                }
                children.Add(identity);
            }

            log.Info("Started second pass - Mapping group memberships");

            Dictionary<string, HashSet<ObjectIdentity>> groupMembersMap = new(StringComparer.OrdinalIgnoreCase);
            void AddGroupMember(string groupSid, ObjectIdentity memberIdentity)
            {
                if (string.IsNullOrEmpty(groupSid) || string.IsNullOrEmpty(memberIdentity.Id)) return;

                if (!groupMembersMap.TryGetValue(groupSid, out var members))
                {
                    members = new HashSet<ObjectIdentity>(new ObjectIdentitySidComparer());
                    groupMembersMap[groupSid] = members;
                }
                members.Add(memberIdentity);
            }

            foreach (var obj in results)
            {
                string dn = obj.DistinguishedName;
                if (string.IsNullOrEmpty(dn) || !DnToIdentityMap.TryGetValue(dn, out var currentIdentity))
                    continue;

                var attributes = obj.Attributes;

                // 1. Primary Group ID Resolution
                if (!string.IsNullOrEmpty(currentIdentity.PrimaryGroupSid))
                {
                    AddGroupMember(currentIdentity.PrimaryGroupSid, currentIdentity);
                }

                // 2. Group Forward Links (member attribute)
                if (currentIdentity.Type == ObjectType.Group)
                {
                    var memberDns = GetAttributeValues(attributes, "member");
                    foreach (var memberDn in memberDns)
                    {
                        if (DnToIdentityMap.TryGetValue(memberDn, out var memberIdentity))
                        {
                            AddGroupMember(currentIdentity.Id, memberIdentity);
                        }
                    }
                }

                // 3. User/Computer/Group Back-Links (memberOf attribute)
                var memberOfDns = GetAttributeValues(attributes, "memberOf");
                foreach (var groupDn in memberOfDns)
                {
                    if (DnToIdentityMap.TryGetValue(groupDn, out var targetGroupIdentity))
                    {
                        AddGroupMember(targetGroupIdentity.Id, currentIdentity);
                    }
                }
            }

            log.Info("Completed second pass");
            log.Info("Started third pass - Creating BloodHound records");

            using (var bhFactory = new BloodHoundDomainWriterFactory(outputDirectoryPath, baseFileTarget, Formatting.Indented))
            {
                var aIACAsNodeWriter = new AIACAsNodeWriter();
                var certTemplateNodeWriter = new CertTemplateNodeWriter();
                var computerNodeWriter = new ComputerNodeWriter();
                var containerNodeWriter = new ContainerNodeWriter();
                var domainNodeWriter = new DomainNodeWriter();
                var enterpriseCaNodeWriter = new EnterpriseCANodeWriter();
                var gPONodeWriter = new GPONodeWriter();
                var groupNodeWriter = new GroupNodeWriter();
                var issuancePolicyNodeWriter = new IssuancePolicyNodeWriter();
                var ntAuthStoreNodeWriter = new NtAuthStoreNodeWriter();
                var ouNodeWriter = new OUNodeWriter();
                var rootCANodeWriter = new RootCANodeWriter();
                var userNodeWriter = new UserNodeWriter();

                // 4. Stream-parse the inner objects mapped to this engine instance
                processedCount = 0;
                var notProcessedObjectClasses = new HashSet<string>();
                foreach (var obj in results)
                {
                    string? dn = obj.DistinguishedName;
                    if (dn == null) continue;

                    string samAccountName = GetFirstAttributeValue(obj.Attributes, "sAMAccountName") ??
                                            GetFirstAttributeValue(obj.Attributes, "name") ??
                                            GetFirstAttributeValue(obj.Attributes, "cn") ??
                                            GetFirstAttributeValue(obj.Attributes, "displayName") ??
                                            string.Empty;

                    string sid = GetFirstAttributeValue(obj.Attributes, "objectSid") is string rawSid ? Helpers.ParseSid(rawSid) ?? string.Empty : string.Empty;

                    string domainUpper = ExtractDomainFromDn(dn);
                    if (string.IsNullOrEmpty(domainUpper)) continue;

                    var objectClasses = GetAttributeValues(obj.Attributes, "objectClass");

                    try
                    {
                    if (log.IsDebugEnabled)
                    {
                        log.Debug($"Processing object: {samAccountName}@{domainUpper} (DN: {dn}, SID: {sid})");
                    }

                    var domainSid = DomainToSidMap.TryGetValue(domainUpper, out var dSid) ? dSid : string.Empty;

                    var nodeContext = new NodeProcessingContext(
                        obj,
                        domainSid,
                        IdToTypeMap,
                        DomainToSidMap,
                        DnToIdentityMap,
                        groupMembersMap,
                        DnsNameToIdMap,
                        CertTemplateCnToGuidMap
                        );

                    // Route via the shared classifier the first pass used to compute EmittedIds, so what is
                    // emitted and how it is emitted cannot drift apart.
                    var route = ClassifyRoute(
                        objectClasses, dn, sid,
                        nodeContext.GetFirstAttributeValue("flags"),
                        nodeContext.Attributes.Any(x => x.Key.Equals("ntSecurityDescriptor", StringComparison.OrdinalIgnoreCase)));

                    switch (route)
                    {
                        case BhRoute.Domain:
                            bhFactory.GetWriter(domainUpper, BloodHoundFileType.Domains).WriteNode(domainNodeWriter, nodeContext);
                            break;
                        case BhRoute.User:
                            bhFactory.GetWriter(domainUpper, BloodHoundFileType.Users).WriteNode(userNodeWriter, nodeContext);
                            break;
                        case BhRoute.Computer:
                            bhFactory.GetWriter(domainUpper, BloodHoundFileType.Computers).WriteNode(computerNodeWriter, nodeContext);
                            break;
                        case BhRoute.Group:
                            bhFactory.GetWriter(domainUpper, BloodHoundFileType.Groups).WriteNode(groupNodeWriter, nodeContext);
                            break;
                        case BhRoute.OU:
                            bhFactory.GetWriter(domainUpper, BloodHoundFileType.OUs).WriteNode(ouNodeWriter, nodeContext);
                            break;
                        case BhRoute.GPO:
                            bhFactory.GetWriter(domainUpper, BloodHoundFileType.GPOs).WriteNode(gPONodeWriter, nodeContext);
                            break;
                        case BhRoute.Container:
                            bhFactory.GetWriter(domainUpper, BloodHoundFileType.Containers).WriteNode(containerNodeWriter, nodeContext);
                            break;
                        case BhRoute.Others:
                            bhFactory.GetWriter(domainUpper, BloodHoundFileType.Others).WriteNode(containerNodeWriter, nodeContext);
                            break;
                        case BhRoute.EnterpriseCA:
                            bhFactory.GetWriter(domainUpper, BloodHoundFileType.EnterpriseCAs).WriteNode(enterpriseCaNodeWriter, nodeContext);
                            break;
                        case BhRoute.RootCA:
                            bhFactory.GetWriter(domainUpper, BloodHoundFileType.RootCAs).WriteNode(rootCANodeWriter, nodeContext);
                            break;
                        case BhRoute.AIACA:
                            bhFactory.GetWriter(domainUpper, BloodHoundFileType.AIACAs).WriteNode(aIACAsNodeWriter, nodeContext);
                            break;
                        case BhRoute.NTAuthStore:
                            bhFactory.GetWriter(domainUpper, BloodHoundFileType.NTAuthStores).WriteNode(ntAuthStoreNodeWriter, nodeContext);
                            break;
                        case BhRoute.CertTemplate:
                            bhFactory.GetWriter(domainUpper, BloodHoundFileType.CertTemplates).WriteNode(certTemplateNodeWriter, nodeContext);
                            break;
                        case BhRoute.IssuancePolicy:
                            bhFactory.GetWriter(domainUpper, BloodHoundFileType.IssuancePolicies).WriteNode(issuancePolicyNodeWriter, nodeContext);
                            break;
                        default:
                            log.Debug($"Skipping deterministic routing for object. SID: {sid}, DN: {dn}. ObjectClasses present: {string.Join(", ", objectClasses)}");
                            notProcessedObjectClasses.Add(string.Join(", ", objectClasses));
                            break;
                    }
                    }
                    catch (Exception ex)
                    {
                        log.Error($"Failed to process object (DN: {dn}); skipping it.", ex);
                    }
                    processedCount++;
                    if (processedCount % 25000 == 0)
                    {
                        log.Info($"Processed {processedCount:N0} records...");
                    }
                }
                log.Info($"Processed {processedCount:N0} records...");

                // Inject a domain-scoped node for every universal well-known principal referenced in a
                // domain that is not already emitted as a real object, so no scoped ACE/membership
                // reference dangles. Each is typed from WellKnownSids and written to the matching file.
                int injectedWellKnown = 0;
                var injectedWellKnownIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var (recordDomainUpper, rawSids) in BloodHoundConverter.ReferencedWellKnownByDomain)
                {
                    foreach (var rawSid in rawSids)
                    {
                        // A forest-wide principal (S-1-5-9) is owned by the forest root; every other
                        // well-known principal by the referencing domain. The node is emitted in that scope,
                        // and deduplicated because several domains in a forest resolve S-1-5-9 to one node.
                        string scopeDomain = WellKnownSids.ForestScoped.Contains(rawSid)
                            ? BloodHoundConverter.ForestRootOf(recordDomainUpper)
                            : recordDomainUpper;
                        string scopedId = Helpers.ScopeSid(rawSid, recordDomainUpper, BloodHoundConverter.ForestRootOf(recordDomainUpper));
                        if (IdToTypeMap.ContainsKey(scopedId) || !injectedWellKnownIds.Add(scopedId))
                        {
                            continue;
                        }
                        var (wkName, wkType) = WellKnownSids.Table[rawSid];
                        var fileType = wkType switch
                        {
                            ObjectType.Computer => BloodHoundFileType.Computers,
                            ObjectType.User => BloodHoundFileType.Users,
                            _ => BloodHoundFileType.Groups
                        };
                        string domainDn = string.Join(",", scopeDomain.Split('.').Select(p => $"DC={p}"));
                        var wkWriter = bhFactory.GetWriter(scopeDomain, fileType);
                        var jw = wkWriter.JsonWriter!;
                        jw.WriteStartObject();
                        IADNodeWriter.WriteProperty(jw, "ObjectIdentifier", scopedId);
                        jw.WritePropertyName("Properties");
                        jw.WriteStartObject();
                        IADNodeWriter.WriteProperty(jw, "domain", scopeDomain);
                        IADNodeWriter.WriteProperty(jw, "name", $"{wkName}@{scopeDomain}");
                        IADNodeWriter.WriteProperty(jw, "distinguishedname", $"CN={wkName},CN=WELLKNOWNSIDS,{domainDn}");
                        jw.WriteEndObject();
                        if (wkType == ObjectType.Group)
                        {
                            IADNodeWriter.WritePropertyArray(jw, "Members", []);
                        }
                        IADNodeWriter.WritePropertyArray(jw, "Aces", []);
                        jw.WriteEndObject();
                        wkWriter.AddToCount(1);
                        injectedWellKnown++;
                    }
                }
                log.Info($"Injected {injectedWellKnown} domain-scoped well-known principal node(s).");

                if (notProcessedObjectClasses.Count > 0)
                {
                    log.Debug($"Unknown objectClasses: {string.Join(';', notProcessedObjectClasses)}");
                }

                string resultSummary = JsonConvert.SerializeObject(
                bhFactory.GetAllWriters()
                    .GroupBy(x => x.Domain)
                    .OrderBy(g => g.Key)
                    .ToDictionary(
                        g => g.Key,
                        g => g.OrderBy(x => x.Writer.NodeType)
                              .ToDictionary(
                                  x => x.Writer.NodeType.ToString(),
                                  x => x.Writer.TotalCount
                              )
                    ),
                    Formatting.Indented
                );

                var resultSummaryFilePath = Path.Combine(infoDirectory, "results_summary.txt");
                File.WriteAllText(resultSummaryFilePath, resultSummary);
                log.Info($"Results summary:\n{resultSummary}");
            }

            if (Helpers.GeneratedGuidsFor.Count > 0)
            {
                var deterministicFilePath = Path.Combine(infoDirectory, "deterministic_guids.txt");
                File.WriteAllLines(deterministicFilePath, Helpers.GeneratedGuidsFor);
                int synthesized = Helpers.GeneratedGuidsFor.Count;
                double percentage = results.Count > 0 ? 100.0 * synthesized / results.Count : 0;
                log.Warn($"Synthesized deterministic GUIDs for {synthesized:N0} of {results.Count:N0} objects ({percentage:F1}%) that had no parseable objectGUID; saved to {deterministicFilePath}");
            }
            log.Info($"BloodHound output files have been generated in the directory: {outputDirectoryPath}");

            string zipFilePath = Path.Combine(outputDirectoryPath, "BloodHound.zip");

            log.Info("Archiving output JSON files");

            using (var zipArchive = ZipFile.Open(zipFilePath, ZipArchiveMode.Create))
            {
                // Find all JSON files generated in the directory
                foreach (var file in Directory.EnumerateFiles(outputDirectoryPath, "*.json", SearchOption.TopDirectoryOnly))
                {
                    string fileName = Path.GetFileName(file);
                    using var sourceStream = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    var entry = zipArchive.CreateEntry(fileName, CompressionLevel.Optimal);
                    using var entryStream = entry.Open();
                    sourceStream.CopyTo(entryStream);
                }
            }

            log.Info($"Successfully compressed BloodHound files into: {zipFilePath}");
        }
    }
}