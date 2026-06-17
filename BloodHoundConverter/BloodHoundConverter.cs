using log4net;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace BloodHoundConverter
{
    internal class BloodHoundConverter
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(BloodHoundConverter));

        private static string CalculateGroupSid(string objectSid, string primaryGroupRid)
        {
            if (string.IsNullOrWhiteSpace(objectSid) || string.IsNullOrWhiteSpace(primaryGroupRid))
                return string.Empty;

            // 1. Check for universal well-known built-in local groups (S-1-5-32-RID)
            // Common examples: 544 (Administrators), 545 (Users), 556 (Network Configuration Operators)
            int rid = int.TryParse(primaryGroupRid, out var parsedRid) ? parsedRid : 0;
            if (rid >= 540 && rid <= 580)
            {
                return $"S-1-5-32-{primaryGroupRid}";
            }

            // 2. Fall back to standard Domain-Relative group calculations (S-1-5-21-...-RID)
            try
            {
                if (!objectSid.Contains('-')) return string.Empty;

                string[] parts = objectSid.Split('-');

                // Reconstruct the domain authority prefix base, dropping the final object RID part
                string domainSidBase = string.Join("-", parts.Take(parts.Length - 1));

                // Append the target group RID to form the absolute Group SID
                return $"{domainSidBase}-{primaryGroupRid}";
            }
            catch (Exception ex)
            {
                log.Error($"Error calculating primary group SID for object SID: {objectSid}, RID: {primaryGroupRid}", ex);
                return string.Empty;
            }
        }

        private static string[] ExtractAttributeValues(JObject attributes, string key)
        {
            var token = attributes.GetValue(key, StringComparison.OrdinalIgnoreCase);
            if (token == null) return [];

            // If it's a JArray, project all items safely to a string array
            if (token is JArray arr)
            {
                return [.. arr.Select(t => t.ToString())];
            }

            // Fallback if the engine flattened a single value into a primitive string token
            return [token.ToString()];
        }

        public static string ExtractDomainFromDn(string dn)
        {
            if (string.IsNullOrWhiteSpace(dn)) return string.Empty;
            try
            {
                var dcComponents = dn.Split(',')
                    .Select(part => part.Trim())
                    .Where(part => part.StartsWith("DC=", StringComparison.OrdinalIgnoreCase))
                    .Select(part => part[3..])
                    .ToArray();

                return dcComponents.Length == 0 ? string.Empty : string.Join(".", dcComponents).ToUpper();
            }
            catch { return string.Empty; }
        }

        private static void FinalizeJsonFile(JsonTextWriter writer)
        {
            writer.WriteEndArray();
            writer.WriteEndObject();
            writer.Flush();
        }

        private static string MapFunctionalLevel(int levelCode)
        {
            return levelCode switch
            {
                0 => "2000",
                1 => "2003 Interim",
                2 => "2003",
                3 => "2008",
                4 => "2008 R2",
                5 => "2012",
                6 => "2012 R2",
                7 => "2016", // Note: Server 2019, 2022, and 2025 maintain the 2016 functional level baseline
                _ => "Unknown"
            };
        }

        private static void InitializeJsonFile(JsonTextWriter writer, string arrayName)
        {
            writer.WriteStartObject();
            writer.WritePropertyName("meta");
            writer.WriteStartObject();
            writer.WritePropertyName("version"); writer.WriteValue(5);
            writer.WritePropertyName("type"); writer.WriteValue(arrayName);
            writer.WriteEndObject();
            writer.WritePropertyName("data");
            writer.WriteStartArray();
        }

        private static void InjectWellKnownGroups(JsonTextWriter writer)
        {
            foreach (var kvp in BloodHoundModels.WellKnownSystemGroups)
            {
                string sid = kvp.Key;
                var (shortName, description) = kvp.Value;

                string assignedDomain = "NT AUTHORITY";

                if (sid.StartsWith("S-1-5-32", StringComparison.OrdinalIgnoreCase))
                {
                    assignedDomain = "BUILTIN";
                }
                else if (sid.Equals("S-1-1-0", StringComparison.OrdinalIgnoreCase))
                {
                    assignedDomain = "EVERYONE";
                }

                writer.WriteStartObject();
                writer.WritePropertyName("ObjectIdentifier"); writer.WriteValue(sid);
                writer.WritePropertyName("Properties");
                writer.WriteStartObject();
                writer.WritePropertyName("domain"); writer.WriteValue(assignedDomain);
                writer.WritePropertyName("name"); writer.WriteValue($"{shortName}@{assignedDomain}".ToUpper());
                writer.WritePropertyName("distinguishedname"); writer.WriteValue($"CN={shortName},CN=WellKnownSids,DC=System");
                writer.WritePropertyName("description"); writer.WriteValue(description);
                writer.WriteEndObject();

                // System SIDs have empty structural links/ACE arrays by default in exports
                writer.WritePropertyName("Members"); writer.WriteStartArray(); writer.WriteEndArray();
                writer.WritePropertyName("Aces"); writer.WriteStartArray(); writer.WriteEndArray();
                writer.WriteEndObject();
            }
        }

        private static string ParseSid(JToken? token)
        {
            if (token == null) return string.Empty;

            var rawValue = token.ToObject<string[]>()?.FirstOrDefault();
            if (string.IsNullOrWhiteSpace(rawValue)) return string.Empty;

            if (rawValue.StartsWith("S-", StringComparison.OrdinalIgnoreCase))
            {
                return rawValue.ToUpper();
            }

            byte[]? bytes;
            try
            {
                bytes = Convert.FromBase64String(rawValue);
            }
            catch
            {
                log.Debug($"String token value '{rawValue}' is neither a standard SID nor valid Base64 string.");
                return string.Empty;
            }

            if (bytes == null || bytes.Length < 8) return string.Empty;

            try
            {
                byte revision = bytes[0];
                byte subAuthorityCount = bytes[1];

                long authority = 0;
                for (int i = 2; i <= 7; i++)
                {
                    authority = (authority << 8) | bytes[i];
                }

                System.Text.StringBuilder sidBuilder = new();
                sidBuilder.Append($"S-{revision}-{authority}");

                for (int i = 0; i < subAuthorityCount; i++)
                {
                    int offset = 8 + (i * 4);
                    if (offset + 4 > bytes.Length) break;

                    uint subAuthority = BitConverter.ToUInt32(bytes, offset);
                    sidBuilder.Append($"-{subAuthority}");
                }

                return sidBuilder.ToString();
            }
            catch (Exception ex)
            {
                log.Error($"Failed to mathematically parse binary byte array. Length: {bytes.Length}", ex);
                return string.Empty;
            }
        }

        public static void ProcessJsonDump(string sourceFilePath, string outputDirectoryPath)
        {
            Directory.CreateDirectory(outputDirectoryPath);

            // 1. Parse the root object framework first to pull TestName metadata properties cleanly
            JObject root;
            using (StreamReader sr = new(sourceFilePath))
            using (JsonTextReader jsonReader = new(sr))
            {
                root = JObject.Load(jsonReader);
            }

            string rawTestName = root.GetValue("TestName", StringComparison.OrdinalIgnoreCase)?.ToString() ?? "TestResults";
            // Clean filename characters out of the test name string to prevent OS filesystem errors
            string safeTestName = string.Concat(rawTestName.Split(Path.GetInvalidFileNameChars())).Replace(" ", "_");

            if (root.GetValue("Results", StringComparison.OrdinalIgnoreCase) is not JObject resultsToken)
            {
                log.Warn($"No 'Results' node found inside the source file: {sourceFilePath}");
                return;
            }

            // 2. Loop dynamically over every engine populated inside the Results object
            foreach (var engineProperty in resultsToken.Properties())
            {
                string engineName = engineProperty.Name; // E.g., "LDAP", "ADWS", "ADWS-GC"
                JObject? engineData = engineProperty.Value as JObject;

                if (engineData?.GetValue("Values", StringComparison.OrdinalIgnoreCase) is not JArray valuesArray || !valuesArray.Any())
                {
                    log.Debug($"Engine '{engineName}' does not contain any record Values to parse.");
                    continue;
                }

                Dictionary<string, ObjectIdentity> dnToIdentityMap = new(StringComparer.OrdinalIgnoreCase);
                Dictionary<string, string> sidToTypeMap = new(StringComparer.OrdinalIgnoreCase);

                foreach (JObject obj in valuesArray.Cast<JObject>())
                {
                    string dn = obj.GetValue("DistinguishedName", StringComparison.OrdinalIgnoreCase)?.ToString() ?? obj.GetValue("distinguishedName", StringComparison.OrdinalIgnoreCase)?.ToString() ?? "";
                    if (obj.GetValue("Attributes", StringComparison.OrdinalIgnoreCase) is not JObject attributes || string.IsNullOrEmpty(dn)) continue;

                    var sid = ParseSid(attributes.GetValue("objectSid", StringComparison.OrdinalIgnoreCase));
                    if (string.IsNullOrEmpty(sid)) continue;

                    var objectClasses = ExtractAttributeValues(attributes, "objectClass");
                    var exactType = "User";
                    if (objectClasses.Contains("computer", StringComparer.OrdinalIgnoreCase)) exactType = "Computer";
                    else if (objectClasses.Contains("group", StringComparer.OrdinalIgnoreCase)) exactType = "Group";

                    string defaultRid = "513";
                    if (objectClasses.Contains("computer", StringComparer.OrdinalIgnoreCase))
                    {
                        exactType = "Computer";
                        defaultRid = "515"; // Default to Domain Computers
                    }
                    else if (objectClasses.Contains("group", StringComparer.OrdinalIgnoreCase))
                    {
                        exactType = "Group";
                    }

                    string primaryGroupRid = ExtractAttributeValues(attributes, "primaryGroupID").FirstOrDefault() ?? defaultRid;
                    string primaryGroupSid = CalculateGroupSid(sid, primaryGroupRid);

                    dnToIdentityMap[dn] = new ObjectIdentity { Sid = sid, Type = exactType, PrimaryGroupSid = primaryGroupSid };
                    sidToTypeMap[sid] = exactType;
                }

                log.Info($"Processing BloodHound translation map for Engine: {engineName} ({valuesArray.Count} records)...");

                // 3. Establish specific file paths matching: <TestName>-<Engine>-<Type>.json
                string baseFileName = $"{safeTestName}-{engineName}";
                string usersPath = Path.Combine(outputDirectoryPath, $"{baseFileName}-users.json");
                string computersPath = Path.Combine(outputDirectoryPath, $"{baseFileName}-computers.json");
                string groupsPath = Path.Combine(outputDirectoryPath, $"{baseFileName}-groups.json");
                string ousPath = Path.Combine(outputDirectoryPath, $"{baseFileName}-ous.json");
                string gposPath = Path.Combine(outputDirectoryPath, $"{baseFileName}-gpos.json");
                string domainsPath = Path.Combine(outputDirectoryPath, $"{baseFileName}-domains.json");

                using StreamWriter swUsers = new(usersPath);
                using JsonTextWriter jwUsers = new(swUsers);

                using StreamWriter swComputers = new(computersPath);
                using JsonTextWriter jwComputers = new(swComputers);

                using StreamWriter swGroups = new(groupsPath);
                using JsonTextWriter jwGroups = new(swGroups);

                using StreamWriter swOUs = new(ousPath);
                using JsonTextWriter jwOUs = new(swOUs);

                using StreamWriter swGPOs = new(gposPath);
                using JsonTextWriter jwGPOs = new(swGPOs);

                using StreamWriter swDomains = new(domainsPath);
                using JsonTextWriter jwDomains = new(swDomains);

                jwUsers.Formatting = Formatting.Indented;
                jwComputers.Formatting = Formatting.Indented;
                jwGroups.Formatting = Formatting.Indented;
                jwOUs.Formatting = Formatting.Indented;
                jwGPOs.Formatting = Formatting.Indented;
                jwDomains.Formatting = Formatting.Indented;

                InitializeJsonFile(jwUsers, "users");
                InitializeJsonFile(jwComputers, "computers");
                InitializeJsonFile(jwGroups, "groups");
                InitializeJsonFile(jwOUs, "ous");
                InitializeJsonFile(jwGPOs, "gpos");
                InitializeJsonFile(jwDomains, "domains");

                InjectWellKnownGroups(jwGroups);

                // 4. Stream-parse the inner objects mapped to this engine instance
                foreach (JObject obj in valuesArray.Cast<JObject>())
                {
                    // WCF/LDAP field canonical normalization mapping
                    string dn = obj.GetValue("DistinguishedName", StringComparison.OrdinalIgnoreCase)?.ToString() ?? obj.GetValue("distinguishedName", StringComparison.OrdinalIgnoreCase)?.ToString() ?? "";

                    if (obj.GetValue("Attributes", StringComparison.OrdinalIgnoreCase) is not JObject attributes) continue;

                    string samAccountName = ExtractAttributeValues(attributes, "sAMAccountName").FirstOrDefault()
                                         ?? ExtractAttributeValues(attributes, "cn").FirstOrDefault()
                                         ?? ExtractAttributeValues(attributes, "name").FirstOrDefault() ?? "";

                    string sid = ParseSid(attributes.GetValue("objectSid", StringComparison.OrdinalIgnoreCase));

                    if (string.IsNullOrWhiteSpace(sid) || string.IsNullOrWhiteSpace(samAccountName))
                        continue;

                    string domainUpper = ExtractDomainFromDn(dn);
                    if (string.IsNullOrEmpty(domainUpper)) continue;

                    string principalName = $"{samAccountName}@{domainUpper}".ToUpper();
                    string[] objectClasses = ExtractAttributeValues(attributes, "objectClass");

                    var sdToken = attributes.GetValue("ntSecurityDescriptor", StringComparison.OrdinalIgnoreCase);
                    var sdBytes = sdToken?.ToObject<string[]>()?.SelectMany(s => Convert.FromBase64String(s)).ToArray();

                    log.Debug($"Processing object: {principalName} (DN: {dn}, SID: {sid})");
                    if (objectClasses.Contains("computer", StringComparer.OrdinalIgnoreCase))
                    {
                        WriteComputerNode(jwComputers, attributes, principalName, dn, sid, domainUpper, sdBytes, sidToTypeMap);
                    }
                    else if (objectClasses.Contains("user", StringComparer.OrdinalIgnoreCase))
                    {
                        WriteUserNode(jwUsers, attributes, principalName, dn, sid, domainUpper, sdBytes, sidToTypeMap);
                    }
                    else if (objectClasses.Contains("group", StringComparer.OrdinalIgnoreCase))
                    {
                        WriteGroupNode(jwGroups, attributes, principalName, dn, sid, domainUpper, sdBytes, dnToIdentityMap, sidToTypeMap);
                    }
                    else if (objectClasses.Contains("organizationalUnit", StringComparer.OrdinalIgnoreCase))
                    {
                        WriteOuNode(jwOUs, attributes, dn, sid, domainUpper, sdBytes, sidToTypeMap);
                    }
                    else if (objectClasses.Contains("groupPolicyContainer", StringComparer.OrdinalIgnoreCase))
                    {
                        WriteGpoNode(jwGPOs, attributes, dn, sid, domainUpper, sdBytes, sidToTypeMap);
                    }
                    else if (objectClasses.Contains("domainDNS", StringComparer.OrdinalIgnoreCase))
                    {
                        WriteDomainNode(jwDomains, attributes, dn, sid, domainUpper, sdBytes, sidToTypeMap);
                    }
                    else
                    {
                        // Log unmapped structural objects (like structural OUs, containers, or GPOs) 
                        // at a debug level so you can track what was skipped.
                        log.Debug($"Skipping deterministic routing for object. SID: {sid}, DN: {dn}. ObjectClasses present: {string.Join(", ", objectClasses)}");
                    }
                }

                FinalizeJsonFile(jwUsers);
                FinalizeJsonFile(jwComputers);
                FinalizeJsonFile(jwGroups);
                FinalizeJsonFile(jwOUs);
                FinalizeJsonFile(jwGPOs);
                FinalizeJsonFile(jwDomains);
            }
        }

        private static long Win32FileTimeToUnixEpoch(string? rawTime)
        {
            if (string.IsNullOrWhiteSpace(rawTime) || !long.TryParse(rawTime, out var fileTime))
                return 0;

            // 0, -1, or max values indicate "Never Expires", "Cleared", or "Not Set" in Active Directory
            if (fileTime <= 0 || fileTime == long.MaxValue)
                return 0;

            try
            {
                // Active Directory tracking uses 100-nanosecond intervals since Jan 1, 1601
                DateTime dt = DateTime.FromFileTimeUtc(fileTime);
                return ((DateTimeOffset)dt).ToUnixTimeSeconds();
            }
            catch
            {
                return 0;
            }
        }

        private static void WriteComputerNode(JsonTextWriter writer, JObject attrs, string name, string dn, string sid, string domain, byte[]? sd, Dictionary<string, string> sidToTypeMap)
        {
            writer.WriteStartObject();
            writer.WritePropertyName("ObjectIdentifier"); writer.WriteValue(sid);
            writer.WritePropertyName("Properties");
            writer.WriteStartObject();
            writer.WritePropertyName("domain"); writer.WriteValue(domain);
            writer.WritePropertyName("name"); writer.WriteValue(name);
            writer.WritePropertyName("distinguishedname"); writer.WriteValue(dn);

            writer.WritePropertyName("description");
            writer.WriteValue(ExtractAttributeValues(attrs, "description").FirstOrDefault() ?? string.Empty);

            writer.WritePropertyName("operatingsystem");
            writer.WriteValue(ExtractAttributeValues(attrs, "operatingSystem").FirstOrDefault() ?? string.Empty);

            string rawLastLogon = ExtractAttributeValues(attrs, "lastLogonTimestamp")?.FirstOrDefault()
                               ?? ExtractAttributeValues(attrs, "lastLogon")?.FirstOrDefault() ?? string.Empty;
            writer.WritePropertyName("lastlogon");
            writer.WriteValue(Win32FileTimeToUnixEpoch(rawLastLogon));

            writer.WritePropertyName("sidhistory");
            writer.WriteStartArray();
            string[] historicalSidsRaw = ExtractAttributeValues(attrs, "sIDHistory");
            foreach (string rawSidEntry in historicalSidsRaw)
            {
                string parsedHistorySid = ParseSid(rawSidEntry);
                if (!string.IsNullOrEmpty(parsedHistorySid))
                {
                    writer.WriteValue(parsedHistorySid);
                }
            }
            writer.WriteEndArray();

            int uac = attrs.GetValue("userAccountControl", StringComparison.OrdinalIgnoreCase)?.FirstOrDefault()?.ToObject<int>() ?? attrs.GetValue("userAccountControl", StringComparison.OrdinalIgnoreCase)?.ToObject<int>() ?? 0;
            writer.WritePropertyName("enabled"); writer.WriteValue((uac & 2) == 0);
            writer.WritePropertyName("unconstraineddelegation"); writer.WriteValue((uac & 524288) != 0);

            string primaryGroupRid = ExtractAttributeValues(attrs, "primaryGroupID").FirstOrDefault() ?? "515";
            string primaryGroupSid = CalculateGroupSid(sid, primaryGroupRid);
            writer.WritePropertyName("PrimaryGroupSID"); writer.WriteValue(primaryGroupSid);

            writer.WriteEndObject();

            AceParser.WriteAcesFromDescriptor(writer, sd, sid, sidToTypeMap);
            writer.WriteEndObject();
        }

        private static void WriteDomainNode(JsonTextWriter writer, JObject attrs, string dn, string sid, string domain, byte[]? sd, Dictionary<string, string> sidToTypeMap)
        {
            writer.WriteStartObject();
            writer.WritePropertyName("ObjectIdentifier"); writer.WriteValue(sid);
            writer.WritePropertyName("Properties");
            writer.WriteStartObject();
            writer.WritePropertyName("domain"); writer.WriteValue(domain);
            writer.WritePropertyName("name"); writer.WriteValue(domain); // The domain name matches the FQDN root
            writer.WritePropertyName("distinguishedname"); writer.WriteValue(dn);

            writer.WritePropertyName("description");
            writer.WriteValue(ExtractAttributeValues(attrs, "description").FirstOrDefault() ?? string.Empty);

            // Map the domain functional level out of msDS-Behavior-Version
            int functionalLevelCode = int.TryParse(ExtractAttributeValues(attrs, "msDS-Behavior-Version").FirstOrDefault(), out var lvl) ? lvl : 0;
            writer.WritePropertyName("functionallevel"); writer.WriteValue(MapFunctionalLevel(functionalLevelCode));

            // Domain-wide GPO links
            string gpLink = ExtractAttributeValues(attrs, "gPLink").FirstOrDefault() ?? "";
            writer.WritePropertyName("gplink"); writer.WriteValue(gpLink);

            writer.WriteEndObject(); // End Properties

            // Collections expected by modern BloodHound JSON domain schemas
            writer.WritePropertyName("ChildObjects"); writer.WriteStartArray(); writer.WriteEndArray();
            writer.WritePropertyName("Links"); writer.WriteStartArray(); writer.WriteEndArray();
            writer.WritePropertyName("Acls"); writer.WriteStartArray(); writer.WriteEndArray();

            AceParser.WriteAcesFromDescriptor(writer, sd, sid, sidToTypeMap);
            writer.WriteEndObject();
        }

        private static void WriteGroupNode(JsonTextWriter writer, JObject attrs, string name, string dn, string sid, string domain, byte[]? sd, Dictionary<string, ObjectIdentity> dnMap, Dictionary<string, string> sidToTypeMap)
        {
            writer.WriteStartObject();
            writer.WritePropertyName("ObjectIdentifier"); writer.WriteValue(sid);
            writer.WritePropertyName("Properties");
            writer.WriteStartObject();
            writer.WritePropertyName("domain"); writer.WriteValue(domain);
            writer.WritePropertyName("name"); writer.WriteValue(name);
            writer.WritePropertyName("distinguishedname"); writer.WriteValue(dn);

            writer.WritePropertyName("description");
            writer.WriteValue(ExtractAttributeValues(attrs, "description").FirstOrDefault() ?? string.Empty);

            writer.WriteEndObject();

            writer.WritePropertyName("Members");
            writer.WriteStartArray();
            string[] implicitMembersDn = ExtractAttributeValues(attrs, "member");
            foreach (string memberDn in implicitMembersDn)
            {
                if (string.IsNullOrWhiteSpace(memberDn)) continue;

                if (dnMap.TryGetValue(memberDn, out var memberIdentity))
                {
                    writer.WriteStartObject();
                    writer.WritePropertyName("ObjectIdentifier"); writer.WriteValue(memberIdentity.Sid);
                    writer.WritePropertyName("ObjectType"); writer.WriteValue(memberIdentity.Type); // "Group", "User", or "Computer"
                    writer.WriteEndObject();
                }
                else
                {
                    // Fallback for objects outside the current query scope: BloodHound can resolve type via Name format
                    string memberSam = memberDn.Split(',').FirstOrDefault(p => p.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))?[3..] ?? "";
                    string memberDomain = ExtractDomainFromDn(memberDn);

                    if (!string.IsNullOrEmpty(memberSam))
                    {
                        writer.WriteStartObject();
                        writer.WritePropertyName("ObjectIdentifier"); writer.WriteValue($"{memberSam}@{memberDomain}".ToUpper());
                        writer.WritePropertyName("ObjectType"); writer.WriteValue("Base"); // "Base" triggers safe auto-resolution in BH CE
                        writer.WriteEndObject();
                    }
                }
            }
            var primaryMembers = dnMap.Values.Where(identity => identity.PrimaryGroupSid.Equals(sid, StringComparison.OrdinalIgnoreCase)).ToList();

            foreach (var member in primaryMembers)
            {
                writer.WriteStartObject();
                writer.WritePropertyName("ObjectIdentifier"); writer.WriteValue(member.Sid);
                writer.WritePropertyName("ObjectType"); writer.WriteValue(member.Type);
                writer.WriteEndObject();
            }
            writer.WriteEndArray();

            AceParser.WriteAcesFromDescriptor(writer, sd, sid, sidToTypeMap);
            writer.WriteEndObject();
        }

        private static void WriteGpoNode(JsonTextWriter writer, JObject attrs, string dn, string sid, string domain, byte[]? sd, Dictionary<string, string> sidToTypeMap)
        {
            writer.WriteStartObject();
            writer.WritePropertyName("ObjectIdentifier"); writer.WriteValue(sid);
            writer.WritePropertyName("Properties");
            writer.WriteStartObject();
            writer.WritePropertyName("domain"); writer.WriteValue(domain);
            writer.WritePropertyName("distinguishedname"); writer.WriteValue(dn);

            writer.WritePropertyName("description");
            writer.WriteValue(ExtractAttributeValues(attrs, "description").FirstOrDefault() ?? string.Empty);

            // Use the human-readable displayName (e.g., "Default Domain Policy") instead of the GUID name
            string displayName = ExtractAttributeValues(attrs, "displayName").FirstOrDefault()
                              ?? dn.Split(',').FirstOrDefault(p => p.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))?[3..]
                              ?? "Unknown GPO";

            writer.WritePropertyName("name"); writer.WriteValue($"{displayName}@{domain}".ToUpper());

            string gpcFileSysPath = ExtractAttributeValues(attrs, "gPCFileSysPath").FirstOrDefault() ?? "";
            writer.WritePropertyName("gpcpath"); writer.WriteValue(gpcFileSysPath);
            writer.WriteEndObject(); // End Properties

            AceParser.WriteAcesFromDescriptor(writer, sd, sid, sidToTypeMap);
            writer.WriteEndObject();
        }

        private static void WriteOuNode(JsonTextWriter writer, JObject attrs, string dn, string sid, string domain, byte[]? sd, Dictionary<string, string> sidToTypeMap)
        {
            writer.WriteStartObject();
            writer.WritePropertyName("ObjectIdentifier"); writer.WriteValue(sid);
            writer.WritePropertyName("Properties");
            writer.WriteStartObject();
            writer.WritePropertyName("domain"); writer.WriteValue(domain);
            writer.WritePropertyName("distinguishedname"); writer.WriteValue(dn);

            writer.WritePropertyName("description");
            writer.WriteValue(ExtractAttributeValues(attrs, "description").FirstOrDefault() ?? string.Empty);

            string ouName = dn.Split(',').FirstOrDefault(p => p.StartsWith("OU=", StringComparison.OrdinalIgnoreCase))?[3..] ?? "Unknown OU";
            writer.WritePropertyName("name"); writer.WriteValue($"{ouName}@{domain}".ToUpper());

            string gpLink = ExtractAttributeValues(attrs, "gPLink").FirstOrDefault() ?? "";
            writer.WritePropertyName("gplink"); writer.WriteValue(gpLink);

            int gpOptions = int.TryParse(ExtractAttributeValues(attrs, "gPOptions").FirstOrDefault(), out var opt) ? opt : 0;
            writer.WritePropertyName("blocksinheritance"); writer.WriteValue(gpOptions == 1);

            writer.WriteEndObject(); // End Properties

            writer.WritePropertyName("ChildObjects"); writer.WriteStartArray(); writer.WriteEndArray();
            AceParser.WriteAcesFromDescriptor(writer, sd, sid, sidToTypeMap);
            writer.WriteEndObject();
        }

        private static void WriteUserNode(JsonTextWriter writer, JObject attrs, string name, string dn, string sid, string domain, byte[]? sd, Dictionary<string, string> sidToTypeMap)
        {
            writer.WriteStartObject();
            writer.WritePropertyName("ObjectIdentifier"); writer.WriteValue(sid);
            writer.WritePropertyName("Properties");
            writer.WriteStartObject();
            writer.WritePropertyName("domain"); writer.WriteValue(domain);
            writer.WritePropertyName("name"); writer.WriteValue(name);
            writer.WritePropertyName("distinguishedname"); writer.WriteValue(dn);

            writer.WritePropertyName("description");
            writer.WriteValue(ExtractAttributeValues(attrs, "description").FirstOrDefault() ?? string.Empty);

            writer.WritePropertyName("displayname");
            writer.WriteValue(ExtractAttributeValues(attrs, "displayName").FirstOrDefault() ?? string.Empty);

            writer.WritePropertyName("title");
            writer.WriteValue(ExtractAttributeValues(attrs, "title").FirstOrDefault() ?? string.Empty);

            writer.WritePropertyName("email");
            writer.WriteValue(ExtractAttributeValues(attrs, "mail").FirstOrDefault() ?? string.Empty);

            string rawPwdLastSet = ExtractAttributeValues(attrs, "pwdLastSet")?.FirstOrDefault() ?? string.Empty;
            writer.WritePropertyName("pwdlastset");
            writer.WriteValue(Win32FileTimeToUnixEpoch(rawPwdLastSet));

            string rawLastLogon = ExtractAttributeValues(attrs, "lastLogonTimestamp")?.FirstOrDefault()
                               ?? ExtractAttributeValues(attrs, "lastLogon")?.FirstOrDefault() ?? string.Empty;
            writer.WritePropertyName("lastlogon");
            writer.WriteValue(Win32FileTimeToUnixEpoch(rawLastLogon));

            writer.WritePropertyName("sidhistory");
            writer.WriteStartArray();
            string[] historicalSidsRaw = ExtractAttributeValues(attrs, "sIDHistory");
            foreach (string rawSidEntry in historicalSidsRaw)
            {
                string parsedHistorySid = ParseSid(rawSidEntry);
                if (!string.IsNullOrEmpty(parsedHistorySid))
                {
                    writer.WriteValue(parsedHistorySid);
                }
            }
            writer.WriteEndArray();

            int uac = attrs.GetValue("userAccountControl", StringComparison.OrdinalIgnoreCase)?.FirstOrDefault()?.ToObject<int>() ?? attrs.GetValue("userAccountControl", StringComparison.OrdinalIgnoreCase)?.ToObject<int>() ?? 0;
            writer.WritePropertyName("enabled"); writer.WriteValue((uac & 2) == 0);
            writer.WritePropertyName("dontreqpreauth"); writer.WriteValue((uac & 4194304) != 0);
            writer.WritePropertyName("unconstraineddelegation"); writer.WriteValue((uac & 524288) != 0);

            string primaryGroupRid = ExtractAttributeValues(attrs, "primaryGroupID").FirstOrDefault() ?? "513";
            string primaryGroupSid = CalculateGroupSid(sid, primaryGroupRid);
            writer.WritePropertyName("PrimaryGroupSID"); writer.WriteValue(primaryGroupSid);
            writer.WriteEndObject();

            AceParser.WriteAcesFromDescriptor(writer, sd, sid, sidToTypeMap);
            writer.WriteEndObject();
        }

    }
}