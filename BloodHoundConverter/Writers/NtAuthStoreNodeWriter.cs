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
            WriteProperty(writer, "DomainSID", context.DomainSid);

            AceParser.WriteAcesFromDescriptor(writer, context.SecurityDescriptorBytes, ObjectType.NTAuthStore, context.DomainName);

            WriteBaseNodeValues(writer, context, context.ObjectGUID);

            WriteContainedBy(writer, context);
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
                if (string.IsNullOrWhiteSpace(certificate?.Thumbprint))
                {
                    continue;
                }
                writer.WriteValue(certificate.Thumbprint);
            }
            writer.WriteEndArray();

            writer.WriteEndObject();
        }
    }
}
