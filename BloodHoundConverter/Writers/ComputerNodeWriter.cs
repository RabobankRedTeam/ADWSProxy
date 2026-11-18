using log4net;
using Newtonsoft.Json;

namespace BloodHoundConverter.Writers
{
    internal class ComputerNodeWriter : IADNodeWriter
    {
        internal override ILog Log => LogManager.GetLogger(typeof(ComputerNodeWriter));

        // msDS-SupportedEncryptionTypes bit -> Kerberos etype name, matching SharpHound's output.
        private static readonly (int Bit, string Name)[] EncryptionTypeNames =
        [
            (0x1, "DES-CBC-CRC"),
            (0x2, "DES-CBC-MD5"),
            (0x4, "RC4-HMAC-MD5"),
            (0x8, "AES128-CTS-HMAC-SHA1-96"),
            (0x10, "AES256-CTS-HMAC-SHA1-96"),
        ];

        // Decodes the msDS-SupportedEncryptionTypes integer bitmask into the named etype array
        // BloodHound expects. Returns null when the attribute is absent/unparsable (property omitted),
        // and ["Not defined"] for a value of 0, mirroring SharpHound.
        private static List<string>? DecodeSupportedEncryptionTypes(string? raw)
        {
            if (!int.TryParse(raw, out int flags))
            {
                return null;
            }
            if (flags == 0)
            {
                return ["Not defined"];
            }
            var result = new List<string>();
            foreach (var (bit, name) in EncryptionTypeNames)
            {
                if ((flags & bit) != 0)
                {
                    result.Add(name);
                }
            }
            return result;
        }

        internal override void WriteProperties(JsonTextWriter writer, NodeProcessingContext context)
        {
            writer.WritePropertyName("Properties");
            writer.WriteStartObject();

            WriteBasePropertyValues(writer, context);

            UacParser.WriteUacProperties(writer, context.Attributes, UacParser.UacType.Computer);
            var primaryGroupId = context.GetFirstAttributeValue("primarygroupid");

            var isDc = context.UacProps?.IsDc == true || primaryGroupId == "516" || primaryGroupId == "521";

            WriteProperty(writer, "highvalue", isDc);

            WriteProperty(writer, "isreadonlydc", primaryGroupId == "521");

            if (context.UacProps != null)
            {
                WriteProperty(writer, "encryptedtextpwdallowed", context.UacProps.EncryptedTextPwdAllowed);
                WriteProperty(writer, "usedeskeyonly", context.UacProps.UseDesKeyOnly);
                WriteProperty(writer, "logonscriptenabled", context.UacProps.LogonScriptEnabled);
                WriteProperty(writer, "lockedout", context.UacProps.Lockout);
                WriteProperty(writer, "passwordexpired", context.UacProps.PasswordExpired);
            }

            WritePropertyArray(writer, "supportedencryptiontypes", DecodeSupportedEncryptionTypes(context.GetFirstAttributeValue("msDS-SupportedEncryptionTypes")));

            WritePropertyArray(writer, "serviceprincipalnames", context.GetAttributeValues("servicePrincipalName"));

            WriteProperty(writer, "email", context.GetFirstAttributeValue("mail"));
            WriteProperty(writer, "useraccountcontrol", context.UacProps?.RawValue);
            WriteProperty(writer, "operatingsystem", context.GetFirstAttributeValue("operatingsystem"));
            WriteProperty(writer, "operatingsystemname",
                context.GetFirstAttributeValue("operatingsystemname") ??
                context.GetFirstAttributeValue("operatingsystem")
                );
            WriteProperty(writer, "operatingsystemservicepack", context.GetFirstAttributeValue("operatingsystemservicepack"));
            WriteProperty(writer, "operatingsystemversion", context.GetFirstAttributeValue("operatingsystemversion"));

            string? hasLaps = context.GetFirstAttributeValue("ms-MNS-HostPassword") ??
                  context.GetFirstAttributeValue("ms-LAPS-PasswordExpirationTime") ??
                  context.GetFirstAttributeValue("msLAPS-Password") ??
                  context.GetFirstAttributeValue("msLAPS-EncryptedPassword") ??
                  context.GetFirstAttributeValue("msLAPS-PasswordExpirationTime");
            if (!string.IsNullOrEmpty(hasLaps))
            {
                WriteProperty(writer, "haslaps", true);
            }

            writer.WriteEndObject();
        }

        public override void WriteNode(JsonTextWriter writer, NodeProcessingContext context)
        {
            writer.WriteStartObject();
            WriteProperties(writer, context);

            WriteBaseNodeValues(writer, context, context.ObjectSid);

            string primaryGroupRid = context.GetFirstAttributeValue("primaryGroupID") ?? "515";
            string primaryGroupSid = Helpers.CalculateGroupSid(context.ObjectSid, primaryGroupRid);

            WriteProperty(writer, "PrimaryGroupSID", primaryGroupSid);
            WriteAllowedToDelegate(writer, context);
            var rawAllowedToAct = context.GetAttributeValues("msds-allowedtoactonbehalfofotheridentity");
            List<string> allowedToAct = [];
            if (rawAllowedToAct?.Count > 0)
            {
                if (!OperatingSystem.IsWindows())
                {
                    Helpers.NotifyWindowsOnlyFunctionality();
                }
                else
                {
                    foreach (var a in rawAllowedToAct)
                    {

                        try
                        {
                            byte[] actbytes = Convert.FromBase64String(a);
                            var rsd = new System.Security.AccessControl.RawSecurityDescriptor(actbytes, 0);
                            if (rsd.DiscretionaryAcl != null)
                            {
                                foreach (System.Security.AccessControl.GenericAce ace in rsd.DiscretionaryAcl)
                                {
                                    if (ace is System.Security.AccessControl.KnownAce knownAce)
                                    {
                                        allowedToAct.Add(knownAce.SecurityIdentifier.Value);
                                    }
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            Log.Error(ex);
                        }
                    }
                }
            }
            WritePropertyArray(writer, "AllowedToAct", allowedToAct);

            WriteSidHistoryPrincipals(writer, context);

            writer.WritePropertyName("Sessions");
            writer.WriteStartObject();
            WritePropertyArray(writer, "Results", []);
            WriteProperty(writer, "Collected", false);
            WriteProperty(writer, "FailureReason", null);
            writer.WriteEndObject();

            writer.WritePropertyName("PrivilegedSessions");
            writer.WriteStartObject();
            WritePropertyArray(writer, "Results", []);
            WriteProperty(writer, "Collected", false);
            WriteProperty(writer, "FailureReason", null);
            writer.WriteEndObject();

            writer.WritePropertyName("RegistrySessions");
            writer.WriteStartObject();
            WritePropertyArray(writer, "Results", []);
            WriteProperty(writer, "Collected", false);
            WriteProperty(writer, "FailureReason", null);
            writer.WriteEndObject();

            writer.WritePropertyName("DCRegistryData");
            writer.WriteStartObject();
            WriteProperty(writer, "CertificateMappingMethods", null);
            WriteProperty(writer, "StrongCertificateBindingEnforcement", null);
            WriteProperty(writer, "VulnerableNetlogonSecurityDescriptor", null);
            writer.WriteEndObject();

            WriteProperty(writer, "Status", null);
            WriteProperty(writer, "IsDC", context.UacProps?.IsDc, false);
            WriteProperty(writer, "UnconstrainedDelegation", context.UacProps?.TrustedForDelegation, false);
            WriteProperty(writer, "DomainSID", context.DomainSid);

            AceParser.WriteAcesFromDescriptor(writer, context.SecurityDescriptorBytes, ObjectType.Computer, context.DomainName);
            WriteContainedBy(writer, context);
            writer.WriteEndObject();
        }
    }
}
