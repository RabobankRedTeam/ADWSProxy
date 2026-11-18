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
            WriteContainedBy(writer, context);
            AceParser.WriteAcesFromDescriptor(writer, context, ObjectType.GPO);
            writer.WriteEndObject();
        }

        internal override void WriteProperties(JsonTextWriter writer, NodeProcessingContext context)
        {
            writer.WritePropertyName("Properties");
            writer.WriteStartObject();

            WriteBasePropertyValues(writer, context);

            WriteProperty(writer, "gpcpath", context.GetFirstAttributeValue("gPCFileSysPath"));
            WriteProperty(writer, "gpostatus", context.GetFirstAttributeValue("flags"));

            writer.WriteEndObject();
        }
    }
}
