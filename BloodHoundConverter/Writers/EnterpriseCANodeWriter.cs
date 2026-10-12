using log4net;
using Newtonsoft.Json;
using System.Security.AccessControl;

namespace BloodHoundConverter.Writers
{
    internal class EnterpriseCANodeWriter : IADNodeWriter
    {
        internal override ILog Log => LogManager.GetLogger(typeof(DomainNodeWriter));

        public override void WriteNode(JsonTextWriter writer, NodeProcessingContext context)
        {
            writer.WriteStartObject();

            WriteProperties(writer, context);

            string? dnsHostName = context.GetFirstAttributeValue("dNSHostName");
            if (!string.IsNullOrWhiteSpace(dnsHostName) &&
                BloodHoundConverter.DnsNameToIdMap.TryGetValue(dnsHostName, out string? hostingComputerId))
            {
                if (hostingComputerId != null)
                {
                    WriteProperty(writer, "HostingComputer", hostingComputerId);
                }
            }

            WriteCARegistryData(writer, context);
            WriteEnabledCertTemplates(writer, context);
            AceParser.WriteAcesFromDescriptor(writer, context);
            WriteBaseNodeValues(writer, context, context.ObjectGUID);

            WriteContaineredBy(writer, context);

            writer.WriteEndObject();
        }

        private static readonly Dictionary<int, string> CAFlags = new()
        {
            {0x00000001, "NO_TEMPLATE_SUPPORT"},
            {0x00000002, "SUPPORTS_NT_AUTHENTICATION"},
            {0x00000004, "CA_SUPPORTS_MANUAL_AUTHENTICATION" },
            {0x00000008, "CA_SERVERTYPE_ADVANCED" }
        };

        private static List<string> ParseCaFlags(int rawFlags)
        {
            var flagsList = new List<string>();

            foreach (var kvp in CAFlags)
            {
                if ((rawFlags & kvp.Key) != 0)
                {
                    flagsList.Add(kvp.Value);
                }
            }

            return flagsList;
        }

        private static void WriteCARegistryData(JsonTextWriter writer, NodeProcessingContext context)
        {
            writer.WritePropertyName("CARegistryData");
            writer.WriteStartObject();

            writer.WritePropertyName("CASecurity");
            writer.WriteStartObject();

            writer.WritePropertyName("Data");
            writer.WriteStartArray();

            var sd = context.SecurityDescriptorBytes;
            var collectedCARegistryData = (sd != null && sd.Length != 0);
            if (collectedCARegistryData && !OperatingSystem.IsWindows())
            {
                Helpers.NotifyWindowsOnlyFunctionality();
                collectedCARegistryData = false;
            }
            else if (collectedCARegistryData)
            {
                RawSecurityDescriptor rsd = new(sd!, 0);

                if (rsd.Owner != null)
                {
                    string ownerSid = rsd.Owner.Value;
                    if (BloodHoundConverter.IdToTypeMap.TryGetValue(ownerSid, out var ownerType))
                    {
                        writer.WriteStartObject();
                        WriteProperty(writer, "PrincipalSID", ownerSid);
                        WriteProperty(writer, "PrincipalType", ownerType);
                        WriteProperty(writer, "RightName", "Owns");
                        WriteProperty(writer, "IsInherited", false);
                        writer.WriteEndObject();
                    }
                }

                if (rsd.DiscretionaryAcl != null)
                {
                    foreach (GenericAce ace in rsd.DiscretionaryAcl)
                    {

                        if (ace is KnownAce knownAce && AceParser.IsAccessAllowedAce(knownAce.AceType))
                        {
                            string principalSid = knownAce.SecurityIdentifier.Value;
                            if (!BloodHoundConverter.IdToTypeMap.TryGetValue(principalSid, out var principalType))
                            {
                                continue;
                            }

                            bool isInherited = (knownAce.AceFlags & AceFlags.Inherited) != 0;

                            if (Enum.IsDefined(typeof(CertificationAuthorityRights), knownAce.AccessMask))
                            {
                                var right = (CertificationAuthorityRights)knownAce.AccessMask;
                                string rightString;
                                switch (right)
                                {
                                    case CertificationAuthorityRights.ManageCA:
                                        rightString = "ManageCA";
                                        break;
                                    case CertificationAuthorityRights.ManageCertificates:
                                        rightString = "ManageCertificates";
                                        break;
                                    case CertificationAuthorityRights.Auditor:
                                        rightString = "Auditor";
                                        break;
                                    case CertificationAuthorityRights.Operator:
                                        rightString = "Operator";
                                        break;
                                    case CertificationAuthorityRights.Enroll:
                                        rightString = "Enroll";
                                        break;
                                    case CertificationAuthorityRights.Read:
                                        rightString = "Read";
                                        break;
                                    default:
                                        continue;
                                }

                                writer.WriteStartObject();
                                WriteProperty(writer, "PrincipalSID", principalSid);
                                WriteProperty(writer, "PrincipalType", principalType);
                                WriteProperty(writer, "RightName", rightString);
                                WriteProperty(writer, "IsInherited", isInherited);
                                writer.WriteEndObject();
                            }
                        }
                    }
                }
            }
            writer.WriteEndArray();
            writer.WriteEndObject();

            WriteProperty(writer, "Collected", collectedCARegistryData);
            WriteProperty(writer, "FailureReason", null);

            writer.WriteEndObject();
        }
        private static void WriteEnabledCertTemplates(JsonTextWriter writer, NodeProcessingContext context)
        {
            writer.WritePropertyName("EnabledCertTemplates");
            writer.WriteStartArray();
            foreach (var value in context.GetAttributeValues("CertificateTemplates") ?? [])
            {
                if (BloodHoundConverter.CertTemplateCnToGuidMap.TryGetValue(value, out string? guid))
                {
                    writer.WriteStartObject();
                    WriteProperty(writer, "ObjectIdentifier", guid);
                    WriteProperty(writer, "ObjectType", "CertTemplate");
                    writer.WriteEndObject();
                }
            }
            writer.WriteEndArray();
        }

        internal override void WriteProperties(JsonTextWriter writer, NodeProcessingContext context)
        {
            writer.WritePropertyName("Properties");
            writer.WriteStartObject();

            WriteBasePropertyValues(writer, context);

            WriteProperty(writer, "description", context.GetFirstAttributeValue("description"));
            WritePropertyArray(writer, "flags", int.TryParse(context.GetFirstAttributeValue("flags"), out int flags) ? ParseCaFlags(flags) : []);
            WriteProperty(writer, "caname", context.GetFirstAttributeValue("caname"));
            WriteProperty(writer, "dnshostname", context.GetFirstAttributeValue("dnshostname"));

            WriteCertificate(writer, context, "cacertificate");

            WriteProperty(writer, "casecuritycollected", context.GetFirstAttributeValue("casecuritycollected"));
            WriteProperty(writer, "enrollmentagentrestrictionscollected", context.GetFirstAttributeValue("enrollmentagentrestrictionscollected"));
            WriteProperty(writer, "isuserspecifiessanenabledcollected", context.GetFirstAttributeValue("isuserspecifiessanenabledcollected"));

            writer.WriteEndObject();
        }
    }
}
