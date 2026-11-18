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
            // Always emit blocksinheritance (default false when gPOptions is absent), as BloodHound expects.
            int gpOptions = int.TryParse(context.GetFirstAttributeValue("gPOptions"), out int g) ? g : 0;
            WriteProperty(writer, "blocksinheritance", (gpOptions & 1) != 0);

            writer.WriteEndObject();
        }

        public override void WriteNode(JsonTextWriter writer, NodeProcessingContext context)
        {
            writer.WriteStartObject();
            WriteProperties(writer, context);
            WriteBaseNodeValues(writer, context, context.ObjectGUID);
            WriteGPOChanges(writer, context);

            WriteChildObjects(writer, context);
            WriteLinks(writer, context);
            WritePropertyArray(writer, "InheritanceHashes", AceParser.ComputeInheritanceHashes(context.SecurityDescriptorBytes));

            AceParser.WriteAcesFromDescriptor(writer, context, ObjectType.OU);

            WriteContainedBy(writer, context);

            writer.WriteEndObject();
        }
    }
}
