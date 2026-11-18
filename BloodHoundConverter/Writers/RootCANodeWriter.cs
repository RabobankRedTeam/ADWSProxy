using log4net;
using Newtonsoft.Json;

namespace BloodHoundConverter.Writers
{
    internal class RootCANodeWriter : IADNodeWriter
    {
        internal override ILog Log => LogManager.GetLogger(typeof(RootCANodeWriter));

        public override void WriteNode(JsonTextWriter writer, NodeProcessingContext context)
        {
            writer.WriteStartObject();
            WriteProperties(writer, context);
            WriteProperty(writer, "DomainSID", context.DomainSid);

            AceParser.WriteAcesFromDescriptor(writer, context.SecurityDescriptorBytes, ObjectType.RootCA, context.DomainName);

            WriteBaseNodeValues(writer, context, context.ObjectGUID);

            WriteContainedBy(writer, context);
            writer.WriteEndObject();
        }

        internal override void WriteProperties(JsonTextWriter writer, NodeProcessingContext context)
        {
            writer.WritePropertyName("Properties");
            writer.WriteStartObject();

            WriteBasePropertyValues(writer, context);

            WriteCertificate(writer, context, "cacertificate");

            writer.WriteEndObject();
        }
    }
}
