using BloodHoundConverter.Writers;
using log4net;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.IO.Compression;

namespace BloodHoundConverter
{
    internal partial class BloodHoundConverter
    {
        internal static Dictionary<string, ObjectIdentity> DnToIdentityMap { get; set; } = [];
        internal static Dictionary<string, ObjectType> IdToTypeMap { get; set; } = [];
        internal static Dictionary<string, string> DnToGuidMap { get; set; } = [];
        internal static Dictionary<string, string> DomainToSidMap { get; set; } = [];
        internal static Dictionary<string, string> DnsNameToIdMap { get; set; } = [];
        internal static Dictionary<string, string> CertTemplateCnToGuidMap { get; set; } = [];
        internal static Dictionary<string, HashSet<ObjectIdentity>> GroupMembersMap { get; set; } = [];

        private static readonly ILog log = LogManager.GetLogger(typeof(BloodHoundConverter));

        private static string CalculateGroupSid(string objectSid, string primaryGroupRid)
        {
            try
            {
                if (string.IsNullOrEmpty(objectSid) || string.IsNullOrEmpty(primaryGroupRid))
                    return string.Empty;

                // 1. Check for universal well-known built-in local groups (S-1-5-32-RID)
                if (int.TryParse(primaryGroupRid, out int rid) && rid >= 540 && rid <= 580)
                {
                    return $"S-1-5-32-{primaryGroupRid}";
                }

                // 2. Standard Domain-Relative SID calculation (S-1-5-21-...-RID)
                int lastHyphenIndex = objectSid.LastIndexOf('-');
                if (lastHyphenIndex <= 0)
                    return string.Empty;

                return $"{objectSid.AsSpan(0, lastHyphenIndex)}-{primaryGroupRid}";
            }
            catch (Exception ex)
            {
                log.Error($"Error calculating primary group SID for object SID: {objectSid}, RID: {primaryGroupRid}", ex);
                return string.Empty;
            }
        }
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
                                reader.Path.StartsWith("Values"))
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

        public static IEnumerable<JObject> StreamJObjectsFromChunks(List<string> sourceChunkFilePaths)
        {
            // Ensure chronological execution of file parts
            foreach (var filePath in sourceChunkFilePaths.Order())
            {
                log.Debug($"Opening stream for chunk: {Path.GetFileName(filePath)}");

                using StreamReader sr = new(filePath);
                using JsonTextReader reader = new(sr);
                while (reader.Read())
                {
                    // Find the beginning of the actual data array
                    if (reader.TokenType == JsonToken.PropertyName &&
                        "Values".Equals(reader.Value?.ToString(), StringComparison.OrdinalIgnoreCase))
                    {
                        // Move into the array block
                        reader.Read();
                        if (reader.TokenType != JsonToken.StartArray) continue;

                        // Stream each individual object out of the array frame one-by-one
                        while (reader.Read() && reader.TokenType != JsonToken.EndArray)
                        {
                            if (reader.TokenType == JsonToken.StartObject)
                            {
                                // 🚀 Lazily load and yield exactly ONE object into memory
                                yield return JObject.Load(reader);
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

            //var results = StreamJObjectsFromChunks(sourceChunkFilePaths);
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

            ILookup<string?, ObjectIdentity> primaryGroupLookup;

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

                if (!string.IsNullOrEmpty(guidString))
                {
                    DnToGuidMap[dn] = guidString;
                }

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

                string identifier = !string.IsNullOrEmpty(sid) ? sid : guidString;

                ObjectType exactType = ObjectType.Base;
                string defaultRid = string.Empty;

                if (classSet.Contains("domain") || classSet.Contains("domainDNS"))
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
                else if (classSet.Contains("organizationalUnit"))
                {
                    exactType = ObjectType.OU;
                }
                else if (classSet.Contains("container"))
                {
                    exactType = ObjectType.Container;
                }
                else if (classSet.Contains("groupPolicyContainer"))
                {
                    exactType = ObjectType.GPO;
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
                else if (classSet.Contains("group"))
                {
                    exactType = ObjectType.Group;
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
                else if (classSet.Contains("foreignSecurityPrincipal"))
                {
                    string? fspSid = GetFirstAttributeValue(attributes, "cn") ?? sid;
                    exactType = ObjectType.User;

                    sid = fspSid;
                }
                else if (classSet.Contains("msDS-GroupManagedServiceAccount") || classSet.Contains("msDS-ManagedServiceAccount") || classSet.Contains("foreignSecurityPrincipal"))
                {
                    exactType = ObjectType.User;
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
                    if (dn.Contains("CN=Certification Authorities"))
                    {
                        exactType = ObjectType.RootCA;
                    }
                    else if (dn.Contains("CN=AIA"))
                    {
                        exactType = ObjectType.AIACA;
                    }
                    else if (dn.Contains("CN = NTAuthCertificates", StringComparison.OrdinalIgnoreCase))
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

                // Calculate the full Primary Group SID (e.g., S-1-5-21-XXX-513)
                string? primaryGroupSid = !string.IsNullOrEmpty(primaryGroupRid) && !string.IsNullOrWhiteSpace(sid)
                    ? CalculateGroupSid(sid, primaryGroupRid)
                    : null;

                var identity = new ObjectIdentity { Id = identifier, Type = exactType, PrimaryGroupSid = primaryGroupSid };
                DnToIdentityMap[dn] = identity;
                IdToTypeMap[identifier] = exactType;
            }
            log.Info("Completed first pass");
            primaryGroupLookup = DnToIdentityMap.Values.Where(identity => !string.IsNullOrEmpty(identity.PrimaryGroupSid))
                .ToLookup(identity => identity.PrimaryGroupSid, StringComparer.OrdinalIgnoreCase);

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

                //TODO Missing files: enterprisecas.json

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

                    var sdToken = GetFirstAttributeValue(obj.Attributes, "ntSecurityDescriptor");
                    byte[]? sdBytes = null;
                    if (!string.IsNullOrWhiteSpace(sdToken))
                    {
                        sdBytes = Convert.FromBase64String(sdToken);
                    }

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

                    // 1. Root structural boundaries
                    if (objectClasses.Contains("domain", StringComparer.OrdinalIgnoreCase) ||
                        objectClasses.Contains("domainDNS", StringComparer.OrdinalIgnoreCase))
                    {
                        bhFactory.GetWriter(domainUpper, BloodHoundFileType.Domains).WriteNode(domainNodeWriter, nodeContext);
                    }
                    // 2. Specific Service Account subclasses (Prevents the computer-inheritance trap)
                    else if (objectClasses.Contains("msDS-GroupManagedServiceAccount", StringComparer.OrdinalIgnoreCase) ||
                        objectClasses.Contains("msDS-ManagedServiceAccount", StringComparer.OrdinalIgnoreCase))
                    {
                        bhFactory.GetWriter(domainUpper, BloodHoundFileType.Users).WriteNode(userNodeWriter, nodeContext);
                    }
                    // 3. Foreign Security Principals (Cross-forest identity targets)
                    else if (objectClasses.Contains("foreignSecurityPrincipal", StringComparer.OrdinalIgnoreCase))
                    {
                        bhFactory.GetWriter(domainUpper, BloodHoundFileType.Users).WriteNode(userNodeWriter, nodeContext);
                    }
                    // 4. Standard Computers
                    else if (objectClasses.Contains("computer", StringComparer.OrdinalIgnoreCase))
                    {
                        bhFactory.GetWriter(domainUpper, BloodHoundFileType.Computers).WriteNode(computerNodeWriter, nodeContext);
                    }
                    // 5. Standard Users
                    else if (objectClasses.Contains("user", StringComparer.OrdinalIgnoreCase))
                    {
                        bhFactory.GetWriter(domainUpper, BloodHoundFileType.Users).WriteNode(userNodeWriter, nodeContext);
                    }
                    // 6. Security Groups
                    else if (objectClasses.Contains("group", StringComparer.OrdinalIgnoreCase))
                    {
                        bhFactory.GetWriter(domainUpper, BloodHoundFileType.Groups).WriteNode(groupNodeWriter, nodeContext);
                    }
                    // 7. Organizational Units
                    else if (objectClasses.Contains("organizationalUnit", StringComparer.OrdinalIgnoreCase))
                    {
                        bhFactory.GetWriter(domainUpper, BloodHoundFileType.OUs).WriteNode(ouNodeWriter, nodeContext);
                    }
                    // 8. Group Policy Objects
                    else if (objectClasses.Contains("groupPolicyContainer", StringComparer.OrdinalIgnoreCase))
                    {
                        bhFactory.GetWriter(domainUpper, BloodHoundFileType.GPOs).WriteNode(gPONodeWriter, nodeContext);
                    }
                    // 9. Generic Structural Containers (e.g., CN=Computers, CN=Users)
                    else if (objectClasses.Contains("container", StringComparer.OrdinalIgnoreCase))
                    {
                        bhFactory.GetWriter(domainUpper, BloodHoundFileType.Containers).WriteNode(containerNodeWriter, nodeContext);
                    }
                    else if (objectClasses.Contains("pKIEnrollmentService", StringComparer.OrdinalIgnoreCase))
                    {
                        bhFactory.GetWriter(domainUpper, BloodHoundFileType.EnterpriseCAs).WriteNode(enterpriseCaNodeWriter, nodeContext);
                    }
                    else if (objectClasses.Contains("certificationAuthority", StringComparer.OrdinalIgnoreCase))
                    {
                        if (dn.Contains("CN=Certification Authorities", StringComparison.OrdinalIgnoreCase))
                        {
                            bhFactory.GetWriter(domainUpper, BloodHoundFileType.RootCAs).WriteNode(rootCANodeWriter, nodeContext);
                        }
                        else if (dn.Contains("CN=AIA", StringComparison.OrdinalIgnoreCase))
                        {
                            bhFactory.GetWriter(domainUpper, BloodHoundFileType.AIACAs).WriteNode(aIACAsNodeWriter, nodeContext);
                        }
                        else if (dn.Contains("CN=NTAuthCertificates", StringComparison.OrdinalIgnoreCase))
                        {
                            bhFactory.GetWriter(domainUpper, BloodHoundFileType.NTAuthStores).WriteNode(ntAuthStoreNodeWriter, nodeContext);
                        }
                    }
                    else if (objectClasses.Contains("pKICertificateTemplate", StringComparer.OrdinalIgnoreCase))
                    {
                        bhFactory.GetWriter(domainUpper, BloodHoundFileType.CertTemplates).WriteNode(certTemplateNodeWriter, nodeContext);
                    }
                    else if (objectClasses.Contains("msPKI-Enterprise-Oid", StringComparer.OrdinalIgnoreCase))
                    {
                        var flags = nodeContext.GetFirstAttributeValue("flags");
                        if (flags != null && long.TryParse(flags, out long longFlags) && (longFlags & 2) == 2)
                        {
                            bhFactory.GetWriter(domainUpper, BloodHoundFileType.IssuancePolicies).WriteNode(issuancePolicyNodeWriter, nodeContext);
                        }
                    }
                    else if (!objectClasses.Any(oc =>
                            oc.Equals("classSchema", StringComparison.OrdinalIgnoreCase) ||
                            oc.Equals("attributeSchema", StringComparison.OrdinalIgnoreCase) ||
                            oc.Equals("displaySpecifier", StringComparison.OrdinalIgnoreCase) ||
                            oc.Equals("dSUISettings", StringComparison.OrdinalIgnoreCase) ||
                            oc.Equals("subSchema", StringComparison.OrdinalIgnoreCase)) &&
                        nodeContext.Attributes.Any(x => x.Key.Equals("ntSecurityDescriptor", StringComparison.OrdinalIgnoreCase)))
                    {
                        bhFactory.GetWriter(domainUpper, BloodHoundFileType.Others).WriteNode(containerNodeWriter, nodeContext);
                    }
                    else
                    {
                        log.Debug($"Skipping deterministic routing for object. SID: {sid}, DN: {dn}. ObjectClasses present: {string.Join(", ", objectClasses)}");
                        notProcessedObjectClasses.Add(string.Join(", ", objectClasses));
                    }
                    processedCount++;
                    if (processedCount % 25000 == 0)
                    {
                        log.Info($"Processed {processedCount:N0} records...");
                    }
                }
                log.Info($"Processed {processedCount:N0} records...");

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
                log.Warn($"Generated {Helpers.GeneratedGuidsFor.Count} deterministic GUIDs, saved to {deterministicFilePath}");
            }
            if (AceParser.UnknownRights.Count > 0)
            {
                var unknownRightsFilePath = Path.Combine(infoDirectory, "unknown_rights.txt");
                File.WriteAllLines(unknownRightsFilePath, AceParser.UnknownRights);
                log.Warn($"{AceParser.UnknownRights.Count} RightGUIDs could not be processed, saved to {unknownRightsFilePath}");
                log.Debug($"Unknown RightGUIDs: {string.Join("\n", AceParser.UnknownRights)}");
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