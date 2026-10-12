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
            WriteContaineredBy(writer, context);

            writer.WritePropertyName("GroupLink");
            writer.WriteStartObject();
            WriteProperty(writer, "ObjectIdentifier", null);
            WriteProperty(writer, "ObjectType", "Base");
            writer.WriteEndObject();

            AceParser.WriteAcesFromDescriptor(writer, context);
            writer.WriteEndObject();
        }

        internal override void WriteProperties(JsonTextWriter writer, NodeProcessingContext context)
        {
            writer.WritePropertyName("Properties");
            writer.WriteStartObject();

            WriteBasePropertyValues(writer, context);
            string? certTemplateOid = null;
            WriteProperty(writer, "certtemplateoid", certTemplateOid);
            writer.WriteEndObject();
        }
    }
}
