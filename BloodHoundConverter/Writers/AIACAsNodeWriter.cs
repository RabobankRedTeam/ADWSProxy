using log4net;
using Newtonsoft.Json;

namespace BloodHoundConverter.Writers
{
    internal class AIACAsNodeWriter : IADNodeWriter
    {
        internal override ILog Log => LogManager.GetLogger(typeof(AIACAsNodeWriter));

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

            var rawCrossCertificatePair = context.GetAttributeValues("crossCertificatePair");
            if (rawCrossCertificatePair != null)
            {
                WritePropertyArray(writer, "crosscertificatepair", rawCrossCertificatePair);
                WriteProperty(writer, "hascrosscertificatepair", rawCrossCertificatePair.Count > 0);
            }

            WriteCertificate(writer, context, "cacertificate");

            writer.WriteEndObject();
        }
    }
}
