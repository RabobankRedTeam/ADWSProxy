using log4net;
using Newtonsoft.Json;

namespace BloodHoundConverter.Writers
{
    internal class IssuancePolicyNodeWriter : IADNodeWriter
    {
        internal override ILog Log => LogManager.GetLogger(typeof(IssuancePolicyNodeWriter));

        public override void WriteNode(JsonTextWriter writer, NodeProcessingContext context)
        {
            writer.WriteStartObject();
            WriteProperties(writer, context);
            WriteBaseNodeValues(writer, context, context.ObjectGUID);
            WriteContainedBy(writer, context);

            // ESC13: msDS-OIDToGroupLink points this issuance policy at a group whose membership is
            // granted to anyone who enrolls a certificate carrying the policy. Resolve the group DN to
            // its principal; leave the link empty (no edge) when absent or unresolved.
            writer.WritePropertyName("GroupLink");
            writer.WriteStartObject();
            string? oidGroupDn = context.GetFirstAttributeValue("msds-oidtogrouplink");
            if (!string.IsNullOrWhiteSpace(oidGroupDn)
                && BloodHoundConverter.DnToIdentityMap.TryGetValue(oidGroupDn, out var linkedGroup))
            {
                WriteProperty(writer, "ObjectIdentifier", linkedGroup.Id);
                WriteProperty(writer, "ObjectType", Helpers.ObjectTypeToString(linkedGroup.Type));
            }
            else
            {
                WriteProperty(writer, "ObjectIdentifier", null);
                WriteProperty(writer, "ObjectType", "Base");
            }
            writer.WriteEndObject();

            AceParser.WriteAcesFromDescriptor(writer, context, ObjectType.IssuancePolicy);
            writer.WriteEndObject();
        }

        internal override void WriteProperties(JsonTextWriter writer, NodeProcessingContext context)
        {
            writer.WritePropertyName("Properties");
            writer.WriteStartObject();

            WriteBasePropertyValues(writer, context);
            WriteProperty(writer, "oid", context.GetFirstAttributeValue("msPKI-Cert-Template-OID"));
            WriteProperty(writer, "certtemplateoid", context.GetFirstAttributeValue("msPKI-Cert-Template-OID"));

            string? oidGroupDn = context.GetFirstAttributeValue("msds-oidtogrouplink");
            if (!string.IsNullOrWhiteSpace(oidGroupDn)
                && BloodHoundConverter.DnToIdentityMap.TryGetValue(oidGroupDn, out var linkedGroup))
            {
                WriteProperty(writer, "oidgrouplink", linkedGroup.Id);
            }
            writer.WriteEndObject();
        }
    }
}
