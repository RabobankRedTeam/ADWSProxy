using log4net;
using Newtonsoft.Json;

namespace BloodHoundConverter.Writers
{
    internal class ContainerNodeWriter : IADNodeWriter
    {
        internal override ILog Log => LogManager.GetLogger(typeof(ContainerNodeWriter));

        internal override void WriteProperties(JsonTextWriter writer, NodeProcessingContext context)
        {
            writer.WritePropertyName("Properties");
            writer.WriteStartObject();

            WriteBasePropertyValues(writer, context);

            var keywords = context.GetAttributeValues("keywords");
            if (keywords?.Count > 0)
            {
                WritePropertyArray(writer, "keywords", keywords);
            }

            writer.WriteEndObject();
        }

        public override void WriteNode(JsonTextWriter writer, NodeProcessingContext context)
        {
            writer.WriteStartObject();
            WriteProperties(writer, context);
            WriteBaseNodeValues(writer, context, context.ObjectGUID);

            WritePropertyArray(writer, "ChildObjects", []);
            WritePropertyArray(writer, "InheritanceHashes", []);

            AceParser.WriteAcesFromDescriptor(writer, context);

            WriteContaineredBy(writer, context);

            writer.WriteEndObject();
        }
    }
}
