using BloodHoundConverter.Writers;
using Newtonsoft.Json;

namespace BloodHoundConverter
{
    internal static class UacParser
    {
        // 🎯 Active Directory UserAccountControl Bitmask Constants
        [Flags]
        public enum UserAccountControlFlags : int
        {
            NONE = 0,
            ACCOUNTDISABLE = 0x0002,          // 2
            PASSWD_NOTREQD = 0x0020,          // 32
            TRUSTED_FOR_DELEGATION = 0x80000,  // 524,288
            DONT_REQ_PREAUTH = 0x400000,       // 4,194,304
            TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION = 0x1000000 // 16,777,216
        }

        public enum UacType
        {
            Computer,
            User
        }

        public static void WriteUacProperties(JsonTextWriter writer, Dictionary<string, List<string>> attrs, UacType type)
        {
            // Extract the UAC integer safely regardless of whether it's wrapped in an array or raw scalar value

            var uacToken = attrs.TryGetValue("userAccountControl", out var uacValues) ? uacValues.FirstOrDefault() : null;

            int uac = 0;
            if (uacToken != null)
            {
                var _ = int.TryParse(uacToken, out uac);
            }

            // Fallback defaults if UAC is missing/0: AD defaults newly created accounts to active (enabled = true)
            bool enabled = true;
            bool dontReqPreauth = false;
            bool passwordNotReqd = false;
            bool unconstrainedDelegation = false;
            bool trustedToAuth = false;

            if (uac > 0)
            {
                // Bitwise flag checks
                enabled = (uac & (int)UserAccountControlFlags.ACCOUNTDISABLE) == 0;
                dontReqPreauth = (uac & (int)UserAccountControlFlags.DONT_REQ_PREAUTH) != 0;
                passwordNotReqd = (uac & (int)UserAccountControlFlags.PASSWD_NOTREQD) != 0;
                unconstrainedDelegation = (uac & (int)UserAccountControlFlags.TRUSTED_FOR_DELEGATION) != 0;
                trustedToAuth = (uac & (int)UserAccountControlFlags.TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION) != 0;
            }

            IADNodeWriter.WriteProperty(writer, "enabled", enabled);
            IADNodeWriter.WriteProperty(writer, "unconstraineddelegation", unconstrainedDelegation);

            switch (type)
            {
                case UacType.Computer:
                    IADNodeWriter.WriteProperty(writer, "trustedtoauth", trustedToAuth);
                    break;
                case UacType.User:
                    IADNodeWriter.WriteProperty(writer, "dontreqpreauth", dontReqPreauth);
                    IADNodeWriter.WriteProperty(writer, "passwordnotreqd", passwordNotReqd);
                    IADNodeWriter.WriteProperty(writer, "trustedtoauth", trustedToAuth);
                    break;
            }
        }
    }
}