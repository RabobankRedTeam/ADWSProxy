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
            // Prefer the (domain-scoped) SID when the object has one so the emitted ObjectIdentifier
            // matches what the first pass registered and what ContainedBy/ChildObjects reference. Only
            // CN=Builtin and cross-domain foreign principals carry a SID here; every other container has
            // none and keeps its objectGUID.
            WriteBaseNodeValues(writer, context, string.IsNullOrEmpty(context.ObjectSid) ? context.ObjectGUID : context.ObjectSid);

            WriteChildObjects(writer, context);
            WritePropertyArray(writer, "InheritanceHashes", AceParser.ComputeInheritanceHashes(context.SecurityDescriptorBytes));

            AceParser.WriteAcesFromDescriptor(writer, context, ObjectType.Container);

            WriteContainedBy(writer, context);

            writer.WriteEndObject();
        }
    }
}
