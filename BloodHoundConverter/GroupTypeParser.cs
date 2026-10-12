using Newtonsoft.Json;

namespace BloodHoundConverter
{
    internal static class GroupTypeParser
    {
        [Flags]
        public enum GroupTypeFlags : uint
        {
            GROUP_TYPE_BUILTIN_LOCAL_GROUP = 0x00000001,
            GROUP_TYPE_ACCOUNT_GROUP = 0x00000002, // Global
            GROUP_TYPE_RESOURCE_GROUP = 0x00000004, // Domain Local
            GROUP_TYPE_UNIVERSAL_GROUP = 0x00000008,
            GROUP_TYPE_SECURITY_ENABLED = 0x80000000
        }

        public static void WriteGroupProperties(JsonTextWriter writer, Dictionary<string, List<string>> attrs)
        {
            var token = attrs.TryGetValue("groupType", out var groupTypeValues) ? groupTypeValues.FirstOrDefault() : null;

            if (token == null)
            {
                return;

            }
            if (!long.TryParse(token, out long groupTypeRaw))
            {
                return;
            }

            uint groupType = (uint)groupTypeRaw;

            // 1. Determine if it's a Security Group or Distribution Group
            // (Note: Distribution groups are usually ignored, but we map the property accurately here)
            bool isSecurityGroup = (groupType & (uint)GroupTypeFlags.GROUP_TYPE_SECURITY_ENABLED) != 0;

            // 2. Determine Scope (Useful if you map custom property extensions)
            string groupScope = "Global";
            if ((groupType & (uint)GroupTypeFlags.GROUP_TYPE_UNIVERSAL_GROUP) != 0)
            {
                groupScope = "Universal";
            }
            else if ((groupType & (uint)GroupTypeFlags.GROUP_TYPE_RESOURCE_GROUP) != 0 ||
                     (groupType & (uint)GroupTypeFlags.GROUP_TYPE_BUILTIN_LOCAL_GROUP) != 0)
            {
                groupScope = "DomainLocal";
            }

            // 📝 3. Write required BloodHound properties

            // BloodHound CE accepts custom tracking properties inside the node info block,
            // which can be invaluable for filtering your 800k+ dataset later!
            writer.WritePropertyName("securityenabled");
            writer.WriteValue(isSecurityGroup);

            writer.WritePropertyName("groupscope");
            writer.WriteValue(groupScope);
        }
    }
}