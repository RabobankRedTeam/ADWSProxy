using Flexinets.Ldap.Core;
using System.Collections.Generic;
using System.Linq;

namespace ADWSProxy.LDAP
{
    internal class LdapResultRawMatchedDNAttribute : LdapAttribute
    {
        /// <summary>
        /// This is a copy of LdapResultAttribute. However, for that class it was only possible to set the MatchedDN as a string. This resulted in changes to the data compared to sending a byte array directly.
        /// </summary>
        internal LdapResultRawMatchedDNAttribute(LdapOperation operation, LdapResult result, IEnumerable<byte> matchedDN = null, string diagnosticMessage = "") : base(operation)
        {
            ChildAttributes.Add(new LdapAttribute(UniversalDataType.Enumerated, (byte)result));
            if (matchedDN != null)
            {
                ChildAttributes.Add(new LdapAttribute(UniversalDataType.OctetString, matchedDN.ToArray()));
            }
            else
            {
                ChildAttributes.Add(new LdapAttribute(UniversalDataType.OctetString, string.Empty));
            }
            ChildAttributes.Add(new LdapAttribute(UniversalDataType.OctetString, diagnosticMessage));
        }
    }
}