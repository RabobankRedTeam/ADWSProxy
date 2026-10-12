using log4net;
using Newtonsoft.Json;

namespace BloodHoundConverter.Writers
{
    internal class GPONodeWriter : IADNodeWriter
    {
        internal override ILog Log => LogManager.GetLogger(typeof(GPONodeWriter));

        public override void WriteNode(JsonTextWriter writer, NodeProcessingContext context)
        {
            writer.WriteStartObject();
            WriteProperties(writer, context);
            WriteBaseNodeValues(writer, context, context.ObjectGUID);
            WriteContaineredBy(writer, context);
            AceParser.WriteAcesFromDescriptor(writer, context);
            writer.WriteEndObject();
        }

        internal override void WriteProperties(JsonTextWriter writer, NodeProcessingContext context)
        {
            writer.WritePropertyName("Properties");
            writer.WriteStartObject();

            WriteBasePropertyValues(writer, context);

            WriteProperty(writer, "gpcpath", context.GetFirstAttributeValue("gPCFileSysPath"));
            WriteProperty(writer, "gpostatus", context.GetFirstAttributeValue("flags"));

            WriteContaineredBy(writer, context);

            writer.WriteEndObject();
        }
    }
}
