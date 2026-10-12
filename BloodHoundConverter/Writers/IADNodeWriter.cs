using log4net;
using Newtonsoft.Json;

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
            WriteProperty(writer, "lastlogon", Helpers.GeneralizedTimeToUnixEpoch(context.GetFirstAttributeValue("lastlogon")));
            WriteProperty(writer, "lastlogontimestamp", Helpers.GeneralizedTimeToUnixEpoch(context.GetFirstAttributeValue("lastlogontimestamp")));
            WriteProperty(writer, "pwdlastset", Helpers.GeneralizedTimeToUnixEpoch(context.GetFirstAttributeValue("pwdlastset")));
            WriteProperty(writer, "admincount", context.GetFirstAttributeValue("adminCount")?.Equals("1"));

            WritePropertyArray(writer, "sidhistory", context.GetAttributeValues("sidhistory")?.Select(x => Helpers.ParseSid(x)), []);
        }

        protected static void WriteGPOChanges(JsonTextWriter writer, NodeProcessingContext _)
        {
            WritePropertyArray(writer, "LocalAdmins", []);
            WritePropertyArray(writer, "RemoteDesktopUsers", []);
            WritePropertyArray(writer, "DcomUsers", []);
            WritePropertyArray(writer, "PSRemoteUsers", []);
            WritePropertyArray(writer, "AffectedComputers", []);
        }

        public abstract void WriteNode(JsonTextWriter writer, NodeProcessingContext context);

        protected string? CalculateGroupSid(string objectSid, string primaryGroupRid)
        {
            if (string.IsNullOrWhiteSpace(objectSid) || string.IsNullOrWhiteSpace(primaryGroupRid))
                return null;

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
                Log.Error($"Error calculating primary group SID for object SID: {objectSid}, RID: {primaryGroupRid}", ex);
                return string.Empty;
            }
        }

        protected static void WriteContaineredBy(JsonTextWriter writer, NodeProcessingContext context)
        {
            string parentDn = string.Empty;
            int firstComma = context.DistinguishedName.IndexOf(',');
            if (firstComma > 0 && firstComma < context.DistinguishedName.Length - 1)
            {
                parentDn = context.DistinguishedName[(firstComma + 1)..].Trim();
            }
            if (!string.IsNullOrEmpty(parentDn))
            {
                string? objectIdentifier = null;
                string? objectType = null;

                writer.WritePropertyName("ContainedBy");
                if (BloodHoundConverter.DnToIdentityMap.TryGetValue(parentDn.ToUpperInvariant(), out var typeAndSid))
                {
                    objectIdentifier = typeAndSid.Id;
                    objectType = Helpers.ObjectTypeToString(typeAndSid.Type);
                }
                else
                {
                    if (parentDn.StartsWith("DC=", StringComparison.OrdinalIgnoreCase))
                    {
                        objectIdentifier = context.DomainSid;
                        objectType = "Domain";
                    }
                }

                if (!string.IsNullOrWhiteSpace(objectIdentifier) && !string.IsNullOrWhiteSpace(objectType))
                {
                    writer.WriteStartObject();
                    WriteProperty(writer, "ObjectIdentifier", objectIdentifier);
                    WriteProperty(writer, "ObjectType", objectType);
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
}
