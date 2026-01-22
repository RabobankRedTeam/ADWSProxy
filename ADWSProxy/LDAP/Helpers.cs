using Flexinets.Ldap.Core;
using log4net;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

namespace ADWSProxy.LDAP
{
    internal static class Helpers
    {
        private static readonly ILog logger = LogManager.GetLogger(MethodBase.GetCurrentMethod()?.DeclaringType!);

        public static string ConvertByteSidToStringSid(byte[] bytes)
        {
            if (bytes == null || bytes.Length < 8)
                return string.Empty;

            // 1. Generate the SID string using the cross-platform manual parser
            string manualSid = ParseSidManually(bytes);

            // 2. Perform Windows-specific validation if requested
            if (logger.IsDebugEnabled && RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                try
                {
                    var nativeSid = new SecurityIdentifier(bytes, 0).ToString();

                    if (!string.Equals(manualSid, nativeSid, StringComparison.OrdinalIgnoreCase))
                    {
                        // Generate Base64 for easier external debugging
                        string base64 = Convert.ToBase64String(bytes);

                        logger.Warn($"SID Mismatch! Manual: {manualSid} | Native: {nativeSid} | Raw Base64: {base64}");

                        return nativeSid;
                    }
                }
                catch (Exception ex)
                {
                    string base64 = Convert.ToBase64String(bytes);
                    logger.Debug($"Native SID validation failed. Manual: {manualSid} | Base64: {base64}", ex);
                }
            }

            return manualSid;
        }
        private static string ParseSidManually(byte[] bytes)
        {
            byte revision = bytes[0];
            int count = bytes[1];

            long authority = 0;
            for (int i = 2; i <= 7; i++)
            {
                authority = (authority << 8) | bytes[i];
            }

            StringBuilder sb = new();
            sb.Append($"S-{revision}-{authority}");

            for (int i = 0; i < count; i++)
            {
                int offset = 8 + (i * 4);
                if (offset + 4 > bytes.Length) break;

                uint subAuthority = BitConverter.ToUInt32(bytes, offset);
                sb.Append($"-{subAuthority}");
            }

            return sb.ToString();
        }

        public static LdapAttribute AddItemsToResponse(this LdapAttribute response, List<DataHolder> items)
        {
            var list = new LdapAttribute(UniversalDataType.Sequence);

            foreach (var item in items.GroupBy(i => i.Name))
            {
                var attribute = new LdapAttribute(UniversalDataType.Sequence);
                attribute.ChildAttributes.Add(new LdapAttribute(UniversalDataType.OctetString, item.Key));
                var attributeValues = new LdapAttribute(UniversalDataType.Set);
                foreach (var itemValue in item)
                {
                    attributeValues.ChildAttributes.Add(new LdapAttribute(itemValue.DataType, itemValue.Data));
                }

                attribute.ChildAttributes.Add(attributeValues);

                list.ChildAttributes.Add(attribute);
            }

            response.ChildAttributes.Add(list);

            return response;
        }

        public static byte[]? GetRawValue(this LdapAttribute ldapAttribute)
        {
            return typeof(LdapAttribute).GetField("Value", BindingFlags.Instance | BindingFlags.NonPublic)?.GetValue(ldapAttribute) as byte[];
        }

        /// <summary>
        /// This NTLMSSP_CHALLENGE is hardcoded into the software and uses empty bytes for the domain and computer name.
        /// </summary>
        public static IEnumerable<byte> NTLMMatchedDN()
        {
            return
                [
                        0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00, // NTLMSSP\0
                        0x02,0x00,0x00,0x00, // NTLMSSP_CHALLENGE
                        // Target Name:
                        0x1e,0x00, // Length: 30
                        0x1e,0x00, // Max length: 30
                        0x38,0x00,0x00,0x00, // Offset: 56
                        // End Target Name
                        0x05,0x82,0x89,0xa2, // Negotiate Flags
                        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                        //0xee,0x0e,0xbf,0x96,0xab,0xf0,0xd6,0xc8, // NTLM Server Challenge
                        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, // Reserved
                        // Target Info:
                        0xc0,0x00, // Length: 192
                        0xc0,0x00, // Max Length: 192
                        0x56,0x00,0x00,0x00, // Offset: 86
                        // End Target Info
                        // Version:
                        0x0a, // Major: 10
                        0x00, // Minor: 0
                        0x7c,0x4f, // Build Number: 20348
                        0x00,0x00,0x00,0x0f, // NTLM Current Revision: 15
                        // End Version
                        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, // <DOMAIN>
                        // Attribute
                        0x02,0x00, // ItemType: NetBIOS domain name
                        0x1e,0x00, // Item Length: 30
                        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, // <DOMAIN>
                        // End attribute
                        // Attribute
                        0x01,0x00, // ItemType: NetBIOS domain name
                        //0x00,0x00,
                        0x08,0x00, // Item Length: 8
                        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                        //0x44,0x00,0x43,0x00,0x30,0x00,0x31,0x00, // DC01
                        // End attribute
                        // Attribute
                        0x04,0x00, // ItemType: DNS domain name
                        0x24,0x00, // Item Length: 36
                        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, // <DOMAIN>.<TLD>
                        // End attribute
                        // Attribute
                        0x03,0x00, // ItemType: DNS computer name
                        0x2e,0x00, // Item Length: 46
                        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, // <HOSTNAME>.<Domain>.<TLD>
                        // End attribute
                        // Attribute
                        0x05,0x00, // ItemType: DNS tree name
                        0x24,0x00, // Item Length: 36
                        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, // <DOMAIN>.<TLD>
                        // End attribute
                        // Attribute
                        0x07,0x00, // ItemType: Timestamp
                        0x08,0x00, // Item Length: 8
                        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, // Timestamp: No time specified
                        // End attribute
                        // Attribute
                        0x00,0x00, // ItemType: End of list
                        0x00,0x00, // Item Length: 0
                        // End attribute
                        0x04,0x00 // End of bind response
                    ];
        }
    }
}