using log4net;
using Newtonsoft.Json;

namespace BloodHoundConverter.Writers
{
    internal class GroupNodeWriter : IADNodeWriter
    {
        internal override ILog Log => LogManager.GetLogger(typeof(GroupNodeWriter));

        public override void WriteNode(JsonTextWriter writer, NodeProcessingContext context)
        {
            writer.WriteStartObject();
            WriteProperties(writer, context);
            WriteBaseNodeValues(writer, context, context.ObjectSid);
            AceParser.WriteAcesFromDescriptor(writer, context);
            WriteContaineredBy(writer, context);

            var members = context.GetAttributeValues("member")?.Select(x => BloodHoundConverter.DnToIdentityMap.TryGetValue(x, out var identity) ? identity : null).Where(x => x != null) ?? [];

            var linkedMembers = BloodHoundConverter.GroupMembersMap.TryGetValue(context.ObjectSid, out var linkedMembersList) ? linkedMembersList : Enumerable.Empty<ObjectIdentity>();

            var allMembers = members.Concat(linkedMembers).DistinctBy(x => x?.Id);

            if (allMembers?.Count() > 0)
            {
                writer.WritePropertyName("Members");
                writer.WriteStartArray();
                foreach (var member in allMembers)
                {
                    if (member == null) continue;
                    writer.WriteStartObject();
                    WriteProperty(writer, "ObjectIdentifier", member.Id);
                    WriteProperty(writer, "ObjectType", member.Type);
                    writer.WriteEndObject();
                }
                writer.WriteEndArray();
            }

            writer.WriteEndObject();
        }

        internal override void WriteProperties(JsonTextWriter writer, NodeProcessingContext context)
        {
            writer.WritePropertyName("Properties");
            writer.WriteStartObject();

            WriteBasePropertyValues(writer, context);

            WritePropertyBool(writer, "admincount", null);
            WriteProperty(writer, "groupscope", long.TryParse(context.GetFirstAttributeValue("grouptype"), out long groupType) ? GetGroupScope(groupType) : null);

            writer.WriteEndObject();
        }

        private static string GetGroupScope(long groupType)
        {
            const int ADS_GROUP_TYPE_GLOBAL_GROUP = 0x00000002;
            const int ADS_GROUP_TYPE_DOMAIN_LOCAL_GROUP = 0x00000004;
            const int ADS_GROUP_TYPE_UNIVERSAL_GROUP = 0x00000008;

            if ((groupType & ADS_GROUP_TYPE_UNIVERSAL_GROUP) == ADS_GROUP_TYPE_UNIVERSAL_GROUP)
            {
                return "Universal";
            }
            else if ((groupType & ADS_GROUP_TYPE_DOMAIN_LOCAL_GROUP) == ADS_GROUP_TYPE_DOMAIN_LOCAL_GROUP)
            {
                return "DomainLocal";
            }
            else if ((groupType & ADS_GROUP_TYPE_GLOBAL_GROUP) == ADS_GROUP_TYPE_GLOBAL_GROUP)
            {
                return "Global";
            }
            else
            {
                return "Unknown";
            }
        }
    }
}
