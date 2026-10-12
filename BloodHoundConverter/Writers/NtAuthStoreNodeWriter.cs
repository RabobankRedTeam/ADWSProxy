using log4net;
using Newtonsoft.Json;

namespace BloodHoundConverter.Writers
{
    internal class NtAuthStoreNodeWriter : IADNodeWriter
    {
        internal override ILog Log => LogManager.GetLogger(typeof(NtAuthStoreNodeWriter));

        public override void WriteNode(JsonTextWriter writer, NodeProcessingContext context)
        {
            writer.WriteStartObject();
            WriteProperties(writer, context);

            AceParser.WriteAcesFromDescriptor(writer, context.SecurityDescriptorBytes);

            WriteBaseNodeValues(writer, context, context.ObjectGUID);

            WriteContaineredBy(writer, context);
            writer.WriteEndObject();
        }

        internal override void WriteProperties(JsonTextWriter writer, NodeProcessingContext context)
        {
            writer.WritePropertyName("Properties");
            writer.WriteStartObject();

            WriteBasePropertyValues(writer, context);

            var certificates = context.GetAttributeValues("cacertificate");
            writer.WritePropertyName("certthumbprints");
            writer.WriteStartArray();
            foreach(var certificate in certificates?.Select(c => CaCertificateParser.ParseCaCertificate(c)) ?? [])
            {
                writer.WriteValue(certificate.Thumbprint);
            }
            writer.WriteEndArray();

            writer.WriteEndObject();
        }
    }
}
