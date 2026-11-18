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
            var primaryGroupSid = Helpers.CalculateGroupSid(context.ObjectSid, primaryGroupRid);

            WriteProperty(writer, "PrimaryGroupSID", primaryGroupSid);
            WriteSidHistoryPrincipals(writer, context);
            WriteAllowedToDelegate(writer, context);
            WriteSpnTargets(writer, context);
            AceParser.WriteAcesFromDescriptor(writer, context, ObjectType.User);
            WriteContainedBy(writer, context);

            writer.WriteEndObject();
        }

        internal override void WriteProperties(JsonTextWriter writer, NodeProcessingContext context)
        {
            writer.WritePropertyName("Properties");
            writer.WriteStartObject();

            WriteBasePropertyValues(writer, context);

            UacParser.WriteUacProperties(writer, context.Attributes, UacParser.UacType.User);

            var servicePrincipalNames = context.GetAttributeValues("servicePrincipalName");
            WritePropertyArray(writer, "serviceprincipalnames", servicePrincipalNames, []);
            WriteProperty(writer, "hasspn", servicePrincipalNames?.Count > 0);

            WriteProperty(writer, "email", context.GetFirstAttributeValue("mail"));
            WriteProperty(writer, "title", context.GetFirstAttributeValue("title"));
            WriteProperty(writer, "homedirectory", context.GetFirstAttributeValue("homedirectory"));
            WriteProperty(writer, "userpassword", context.GetFirstAttributeValue("userpassword"));
            WriteProperty(writer, "unixpassword", context.GetFirstAttributeValue("unixpassword"));
            WriteProperty(writer, "unicodepassword", context.GetFirstAttributeValue("unicodepassword"));
            WriteProperty(writer, "logonscript", context.GetFirstAttributeValue("logonscript"));
            WriteProperty(writer, "sfupassword", context.GetFirstAttributeValue("sfupassword"));

            writer.WriteEndObject();
        }
    }
}
