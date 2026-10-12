using log4net;
using Newtonsoft.Json;

namespace BloodHoundConverter.Writers
{
    internal class OUNodeWriter : IADNodeWriter
    {
        internal override ILog Log => LogManager.GetLogger(typeof(OUNodeWriter));

        internal override void WriteProperties(JsonTextWriter writer, NodeProcessingContext context)
        {
            writer.WritePropertyName("Properties");
            writer.WriteStartObject();

            WriteBasePropertyValues(writer, context);

            writer.WriteEndObject();
        }

        public override void WriteNode(JsonTextWriter writer, NodeProcessingContext context)
        {
            writer.WriteStartObject();
            WriteProperties(writer, context);
            WriteBaseNodeValues(writer, context, context.ObjectGUID);
            WriteGPOChanges(writer, context);

            WritePropertyArray(writer, "ChildObjects", []);
            WritePropertyArray(writer, "Links", []);
            WritePropertyArray(writer, "InheritanceHashes", []);

            AceParser.WriteAcesFromDescriptor(writer, context);

            WriteContaineredBy(writer, context);

            writer.WriteEndObject();
        }
    }
}
