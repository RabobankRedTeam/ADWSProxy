using log4net;
using Newtonsoft.Json;
using System.Text.RegularExpressions;

namespace BloodHoundConverter.Writers
{
    internal abstract class IADNodeWriter
    {
        internal abstract ILog Log { get; }

        internal abstract void WriteProperties(JsonTextWriter writer, NodeProcessingContext context);

        internal static void WritePropertyArray(JsonTextWriter writer, string propertyName, IEnumerable<object?>? values, IEnumerable<object>? defaultValues = null)
        {
            if (values != null)
            {
                writer.WritePropertyName(propertyName);
                writer.WriteStartArray();
                foreach (var value in values.Where(x => x != null))
                {
                    writer.WriteValue(value);
                }
                writer.WriteEndArray();
            }
            else if (defaultValues != null)
            {
                writer.WritePropertyName(propertyName);
                writer.WriteStartArray();
                foreach (var value in defaultValues.Where(x => x != null))
                {
                    writer.WriteValue(value);
                }
                writer.WriteEndArray();
            }
        }

        internal static void WriteProperty(JsonTextWriter writer, string propertyName, ObjectType value, ObjectType? defaultValue = null)
        {
            string convertedValue = Helpers.ObjectTypeToString(value);
            string? convertedDefaultValue = null;
            if (defaultValue != null)
            {
                convertedDefaultValue = Helpers.ObjectTypeToString(defaultValue);
            }

            WriteProperty(writer, propertyName, convertedValue, convertedDefaultValue);
        }

        internal static void WriteProperty(JsonTextWriter writer, string propertyName, object? value, object? defaultValue = null)
        {
            if (value != null)
            {
                writer.WritePropertyName(propertyName);
                writer.WriteValue(value);
            }
            else if (AppInfo.writeDefaultValues && defaultValue != null)
            {
                writer.WritePropertyName(propertyName);
                writer.WriteValue(defaultValue);
            }
        }

        internal static void WritePropertyBool(JsonTextWriter writer, string propertyName, string? value, bool? defaultValue = null)
        {
            bool? boolValue = null;
            if (!string.IsNullOrWhiteSpace(value))
            {
                if (bool.TryParse(value, out bool i))
                {
                    boolValue = i;
                }
                else if (value.Equals("true", StringComparison.OrdinalIgnoreCase))
                {
                    boolValue = true;
                }
                else if (value.Equals("false", StringComparison.OrdinalIgnoreCase))
                {
                    boolValue = false;
                }
                else if (value.Equals("1", StringComparison.OrdinalIgnoreCase))
                {
                    boolValue = true;
                }
            }
            WriteProperty(writer, propertyName, boolValue, defaultValue);
        }

        internal static void WritePropertyInt(JsonTextWriter writer, string propertyName, string? value, int? defaultValue = null)
        {
            int? intValue = null;
            if (!string.IsNullOrWhiteSpace(value))
            {
                if (int.TryParse(value, out int i))
                {
                    intValue = i;
                }
            }

            WriteProperty(writer, propertyName, intValue, defaultValue);
        }

        internal static void WritePropertyLong(JsonTextWriter writer, string propertyName, string? value, long? defaultValue = null)
        {
            long? longValue = null;
            if (!string.IsNullOrWhiteSpace(value))
            {
                if (long.TryParse(value, out long l))
                {
                    longValue = l;
                }
            }

            WriteProperty(writer, propertyName, longValue, defaultValue);
        }

        protected void WriteCertificate(JsonTextWriter writer, NodeProcessingContext context, string attributeName)
        {
            var rawCertificates = context.GetAttributeValues(attributeName);
            if (rawCertificates?.Count > 0)
            {
                var parsedCerts = new List<ParsedCertificateData>();

                foreach (string rawCertBase64 in rawCertificates)
                {
                    if (string.IsNullOrWhiteSpace(rawCertBase64)) continue;

                    try
                    {
                        var certData = CaCertificateParser.ParseCaCertificate(rawCertBase64);
                        if (certData != null)
                        {
                            parsedCerts.Add(certData);
                        }
                    }
                    catch (Exception ex)
                    {
                        Log.Warn("Failed to parse an individual caCertificate entry.", ex);
                    }
                }

                if (parsedCerts?.Count > 0)
                {
                    var activeCert = parsedCerts.OrderByDescending(c => c.NotBefore).First();

                    WriteProperty(writer, "certthumbprint", activeCert.Thumbprint);
                    WriteProperty(writer, "certname", activeCert.SubjectName);
                    WriteProperty(writer, "hasbasicconstraints", activeCert.HasBasicConstraints);
                    WriteProperty(writer, "basicconstraintpathlength", activeCert.BasicConstraintPathLength);

                    // 3. Full Chain / Thumbprint Array (across ALL certs in caCertificate)
                    var fullChainThumbprints = parsedCerts
                        .Select(c => c.Thumbprint)
                        .Where(tp => !string.IsNullOrEmpty(tp))
                        .Distinct()
                        .ToList();

                    WritePropertyArray(writer, "certchain", fullChainThumbprints);
                }
            }
        }

        /// <summary>
        /// Write the fields that exist in all Bloodhound data nodes
        /// </summary>
        /// <param name="writer"><see cref="JsonTextWriter">JsonTextWriter to use</see></param>
        /// <param name="context"><see cref="NodeProcessingContext">Object context</see></param>
        /// <param name="objectIdentifier">Some objects use a GUID and some a SID</param>
        protected static void WriteBaseNodeValues(JsonTextWriter writer, NodeProcessingContext context, string objectIdentifier)
        {
            WriteProperty(writer, "IsACLProtected", context.SdResult?.IsAclProtected);
            WritePropertyBool(writer, "IsDeleted", context.GetFirstAttributeValue("isdeleted"), false);
            WriteProperty(writer, "ObjectIdentifier", objectIdentifier);
        }

        /// <summary>
        /// Write the fields that exist in all Bloodhound properties nodes
        /// </summary>
        /// <param name="writer"><see cref="JsonTextWriter">JsonTextWriter to use</see></param>
        /// <param name="context"><see cref="NodeProcessingContext">Object context</see></param>
        protected static void WriteBasePropertyValues(JsonTextWriter writer, NodeProcessingContext context)
        {
            WriteProperty(writer, "domain", context.DomainName);
            WriteProperty(writer, "displayname", context.GetFirstAttributeValue("displayName"));
            WriteProperty(writer, "samaccountname", context.GetFirstAttributeValue("samaccountname"));
            WriteProperty(writer, "name", context.Name);
            WriteProperty(writer, "distinguishedname", context.DistinguishedName);
            WriteProperty(writer, "domainsid", context.DomainSid);

            if (context.SdResult != null)
            {
                WriteProperty(writer, "doesanyacegrantownerrights", context.SdResult.DoesAnyAceGrantOwnerRights);
                WriteProperty(writer, "doesanyinheritedacegrantownerrights", context.SdResult.DoesAnyInheritedAceGrantOwnerRights);
                WriteProperty(writer, "isaclprotected", context.SdResult.IsAclProtected);
            }

            WriteProperty(writer, "whencreated", context.WhenCreated);
            WriteProperty(writer, "whenchanged", context.WhenChanged);
            WriteProperty(writer, "objectguid", context.ObjectGUID);
            WriteProperty(writer, "description", context.Description);
            WriteProperty(writer, "lastlogon", Helpers.FileTimeToUnixEpoch(context.GetFirstAttributeValue("lastlogon")));
            WriteProperty(writer, "lastlogontimestamp", Helpers.FileTimeToUnixEpoch(context.GetFirstAttributeValue("lastlogontimestamp")));
            WriteProperty(writer, "pwdlastset", Helpers.FileTimeToUnixEpoch(context.GetFirstAttributeValue("pwdlastset")));
            WriteProperty(writer, "admincount", context.GetFirstAttributeValue("adminCount")?.Equals("1"));

            WritePropertyArray(writer, "sidhistory", context.GetAttributeValues("sidhistory")?.Select(x => Helpers.ParseSid(x)), []);
        }

        // Matches each [LDAP://<gpo dn>;<options>] segment of a gPLink value.
        private static readonly Regex GpLinkRegex = new(@"\[LDAP://([^;\]]+);(\d+)\]", RegexOptions.IgnoreCase | RegexOptions.Compiled);

        /// <summary>
        /// Writes the "Links" array from the object's gPLink attribute. Each enabled link resolves the
        /// GPO distinguished name to its ObjectIdentifier; disabled links (option bit 0) are skipped and
        /// the enforced state comes from option bit 1. Emitted by domains and OUs.
        /// </summary>
        protected static void WriteLinks(JsonTextWriter writer, NodeProcessingContext context)
        {
            writer.WritePropertyName("Links");
            writer.WriteStartArray();

            var rawGpLink = context.GetFirstAttributeValue("gPLink");
            if (!string.IsNullOrWhiteSpace(rawGpLink))
            {
                foreach (Match match in GpLinkRegex.Matches(rawGpLink))
                {
                    if (!int.TryParse(match.Groups[2].Value, out int options)) continue;
                    if ((options & 1) != 0) continue; // link disabled

                    string gpoDn = match.Groups[1].Value.Trim();
                    if (BloodHoundConverter.GpoDnToGuidMap.TryGetValue(gpoDn, out var gpoGuid))
                    {
                        writer.WriteStartObject();
                        WriteProperty(writer, "IsEnforced", (options & 2) != 0);
                        WriteProperty(writer, "GUID", gpoGuid);
                        writer.WriteEndObject();
                    }
                }
            }

            writer.WriteEndArray();
        }

        /// <summary>
        /// Writes the domain "Trusts" array from the trustedDomain objects harvested for this domain.
        /// </summary>
        protected static void WriteTrusts(JsonTextWriter writer, NodeProcessingContext context)
        {
            writer.WritePropertyName("Trusts");
            writer.WriteStartArray();

            if (BloodHoundConverter.DomainTrustsByDomain.TryGetValue(context.DomainName, out var trusts))
            {
                foreach (var trust in trusts)
                {
                    writer.WriteStartObject();
                    WriteProperty(writer, "TargetDomainSid", trust.TargetDomainSid);
                    WriteProperty(writer, "TargetDomainName", trust.TargetDomainName);
                    WriteProperty(writer, "IsTransitive", trust.IsTransitive);
                    WriteProperty(writer, "SidFilteringEnabled", trust.SidFilteringEnabled);
                    WriteProperty(writer, "TGTDelegationEnabled", trust.TGTDelegationEnabled);
                    WriteProperty(writer, "TrustAttributes", trust.TrustAttributes);
                    WriteProperty(writer, "TrustDirection", trust.TrustDirection);
                    WriteProperty(writer, "TrustType", trust.TrustType);
                    writer.WriteEndObject();
                }
            }

            writer.WriteEndArray();
        }

        protected static void WriteGPOChanges(JsonTextWriter writer, NodeProcessingContext _)
        {
            writer.WritePropertyName("GPOChanges");
            writer.WriteStartObject();
            WritePropertyArray(writer, "LocalAdmins", []);
            WritePropertyArray(writer, "RemoteDesktopUsers", []);
            WritePropertyArray(writer, "DcomUsers", []);
            WritePropertyArray(writer, "PSRemoteUsers", []);
            WritePropertyArray(writer, "AffectedComputers", []);
            writer.WriteEndObject();
        }

        public abstract void WriteNode(JsonTextWriter writer, NodeProcessingContext context);

        /// <summary>
        /// Writes the "HasSIDHistory" array as typed principals ({ObjectIdentifier, ObjectType}) from
        /// the object's sIDHistory values. Each value is parsed to a SID and its type resolved via the
        /// IdToTypeMap, defaulting to Base when the SID is not known. Emitted by users and computers.
        /// </summary>
        protected static void WriteSidHistoryPrincipals(JsonTextWriter writer, NodeProcessingContext context)
        {
            writer.WritePropertyName("HasSIDHistory");
            writer.WriteStartArray();
            foreach (var raw in context.GetAttributeValues("sidhistory") ?? [])
            {
                string? sid = Helpers.ParseSid(raw);
                if (string.IsNullOrEmpty(sid))
                {
                    continue;
                }

                string objectType = BloodHoundConverter.IdToTypeMap.TryGetValue(sid, out var type)
                    ? Helpers.ObjectTypeToString(type)
                    : Helpers.ObjectTypeToString(ObjectType.Base);

                writer.WriteStartObject();
                WriteProperty(writer, "ObjectIdentifier", sid);
                WriteProperty(writer, "ObjectType", objectType);
                writer.WriteEndObject();
            }
            writer.WriteEndArray();
        }

        /// <summary>
        /// Writes the "ChildObjects" array ({ObjectIdentifier, ObjectType}) of this container's direct
        /// children, resolved from the parent-DN index (the inverse of WriteContainedBy). Emitted by
        /// domains, OUs and containers; produces the Contains edges.
        /// </summary>
        protected static void WriteChildObjects(JsonTextWriter writer, NodeProcessingContext context)
        {
            writer.WritePropertyName("ChildObjects");
            writer.WriteStartArray();
            if (BloodHoundConverter.ChildObjectsByParentDn.TryGetValue(context.DistinguishedName, out var children))
            {
                foreach (var child in children)
                {
                    if (string.IsNullOrEmpty(child.Id))
                    {
                        continue;
                    }
                    writer.WriteStartObject();
                    WriteProperty(writer, "ObjectIdentifier", child.Id);
                    WriteProperty(writer, "ObjectType", Helpers.ObjectTypeToString(child.Type));
                    writer.WriteEndObject();
                }
            }
            writer.WriteEndArray();
        }

        /// <summary>
        /// Writes the "AllowedToDelegate" array ({ObjectIdentifier, ObjectType}) from the object's
        /// msDS-AllowedToDelegateTo (constrained delegation). Each SPN's host is resolved to a computer
        /// via DnsNameToIdMap; unresolved hosts are skipped. Emitted by users and computers.
        /// </summary>
        protected static void WriteAllowedToDelegate(JsonTextWriter writer, NodeProcessingContext context)
        {
            writer.WritePropertyName("AllowedToDelegate");
            writer.WriteStartArray();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var spn in context.GetAttributeValues("msds-allowedtodelegateto") ?? [])
            {
                var computerId = ResolveSpnHostToComputerId(spn);
                if (computerId == null || !seen.Add(computerId))
                {
                    continue;
                }
                var type = BloodHoundConverter.IdToTypeMap.TryGetValue(computerId, out var t) ? t : ObjectType.Computer;
                writer.WriteStartObject();
                WriteProperty(writer, "ObjectIdentifier", computerId);
                WriteProperty(writer, "ObjectType", Helpers.ObjectTypeToString(type));
                writer.WriteEndObject();
            }
            writer.WriteEndArray();
        }

        /// <summary>
        /// Writes the "SPNTargets" array ({ComputerSID, Port, Service}) from the object's own
        /// servicePrincipalName. Mirrors SharpHound: only MSSQLSvc SPNs, resolved to a computer, emit a
        /// SQLAdmin target (default port 1433). Emitted by users.
        /// </summary>
        protected static void WriteSpnTargets(JsonTextWriter writer, NodeProcessingContext context)
        {
            writer.WritePropertyName("SPNTargets");
            writer.WriteStartArray();
            foreach (var spn in context.GetAttributeValues("serviceprincipalname") ?? [])
            {
                if (string.IsNullOrWhiteSpace(spn) || spn.Contains('@')
                    || spn.IndexOf("mssqlsvc", StringComparison.OrdinalIgnoreCase) < 0)
                {
                    continue;
                }
                var computerId = ResolveSpnHostToComputerId(spn);
                if (computerId == null)
                {
                    continue;
                }
                int port = 1433;
                var parts = spn.Split(':');
                if (parts.Length > 1 && int.TryParse(parts[1], out int parsedPort))
                {
                    port = parsedPort;
                }
                writer.WriteStartObject();
                WriteProperty(writer, "ComputerSID", computerId);
                WriteProperty(writer, "Port", port);
                WriteProperty(writer, "Service", "SQLAdmin");
                writer.WriteEndObject();
            }
            writer.WriteEndArray();
        }

        // Extracts the host from an SPN ("service/host[:port][/rest]") and resolves it to a computer
        // ObjectIdentifier via DnsNameToIdMap. Returns null when the SPN has no host or the host (an
        // FQDN dNSHostName) was not collected.
        private static string? ResolveSpnHostToComputerId(string? spn)
        {
            if (string.IsNullOrWhiteSpace(spn))
            {
                return null;
            }
            int slash = spn.IndexOf('/');
            if (slash < 0 || slash == spn.Length - 1)
            {
                return null;
            }
            string host = spn[(slash + 1)..];
            int colon = host.IndexOf(':');
            if (colon >= 0)
            {
                host = host[..colon];
            }
            int nextSlash = host.IndexOf('/');
            if (nextSlash >= 0)
            {
                host = host[..nextSlash];
            }
            if (string.IsNullOrWhiteSpace(host))
            {
                return null;
            }
            return BloodHoundConverter.DnsNameToIdMap.TryGetValue(host, out var id) ? id : null;
        }

        protected static void WriteContainedBy(JsonTextWriter writer, NodeProcessingContext context)
        {
            int firstComma = context.DistinguishedName.IndexOf(',');
            if (firstComma <= 0 || firstComma >= context.DistinguishedName.Length - 1)
            {
                return; // No parent in the DN (a naming-context root): omit ContainedBy entirely.
            }

            // Domains stay top-level, matching SharpHound; a child domain is linked to its parent by trust
            // edges, not containment, so it carries no ContainedBy.
            if (BloodHoundConverter.DnToIdentityMap.TryGetValue(context.DistinguishedName, out var self)
                && self.Type == ObjectType.Domain)
            {
                return;
            }

            writer.WritePropertyName("ContainedBy");

            // Resolve to the nearest emitted ancestor rather than the immediate parent, so the edge never
            // points at a collected-but-not-emitted container (the flags-less CN=OID, attribute-less DNS
            // stubs, schema objects).
            string? ancestorDn = BloodHoundConverter.FindEmittedAncestorDn(context.DistinguishedName);
            if (ancestorDn != null && BloodHoundConverter.DnToIdentityMap.TryGetValue(ancestorDn, out var parent))
            {
                writer.WriteStartObject();
                WriteProperty(writer, "ObjectIdentifier", parent.Id);
                WriteProperty(writer, "ObjectType", Helpers.ObjectTypeToString(parent.Type));
                writer.WriteEndObject();
            }
            else
            {
                const string? nullValue = null;
                writer.WriteValue(nullValue);
            }
        }
    }
}
