using log4net;
using Newtonsoft.Json;

namespace BloodHoundConverter.Writers
{
    internal class UserNodeWriter : IADNodeWriter
    {
        internal override ILog Log => LogManager.GetLogger(typeof(UserNodeWriter));

        public override void WriteNode(JsonTextWriter writer, NodeProcessingContext context)
        {
            writer.WriteStartObject();
            WriteProperties(writer, context);
            WriteBaseNodeValues(writer, context, context.ObjectSid);

            var primaryGroupRid = context.GetFirstAttributeValue("primaryGroupID") ?? "513";
            var primaryGroupSid = CalculateGroupSid(context.ObjectSid, primaryGroupRid);

            WriteProperty(writer, "PrimaryGroupSID", primaryGroupSid);
            WritePropertyArray(writer, "HasSIDHistory", context.GetAttributeValues("sIDHistory"), []);
            writer.WritePropertyName("AllowedToDelegate");
            writer.WriteStartArray();
            writer.WriteEndArray();

            AceParser.WriteAcesFromDescriptor(writer, context);
            WriteContaineredBy(writer, context);

            writer.WriteEndObject();
        }

        internal override void WriteProperties(JsonTextWriter writer, NodeProcessingContext context)
        {
            writer.WritePropertyName("Properties");
            writer.WriteStartObject();

            WriteBasePropertyValues(writer, context);

            UacParser.WriteUacProperties(writer, context.Attributes, UacParser.UacType.User);

            WritePropertyArray(writer, "serviceprincipalnames", context.GetAttributeValues("servicePrincipalName"), []);

            WriteProperty(writer, "email", context.GetFirstAttributeValue("email"));
            WriteProperty(writer, "title", context.GetFirstAttributeValue("title"));
            WriteProperty(writer, "homedirectory", context.GetFirstAttributeValue("homedirectory"));
            WriteProperty(writer, "userpassword", context.GetFirstAttributeValue("userpassword"));
            var adminCountRaw = context.GetFirstAttributeValue("adminCount");
            if (int.TryParse(adminCountRaw, out var adminCount))
            {
                WriteProperty(writer, "admincount", adminCount > 0);
            }
            WriteProperty(writer, "unixpassword", context.GetFirstAttributeValue("unixpassword"));
            WriteProperty(writer, "unicodepassword", context.GetFirstAttributeValue("unicodepassword"));
            WriteProperty(writer, "logonscript", context.GetFirstAttributeValue("logonscript"));
            WriteProperty(writer, "sfupassword", context.GetFirstAttributeValue("sfupassword"));

            writer.WriteEndObject();
        }
    }
}
