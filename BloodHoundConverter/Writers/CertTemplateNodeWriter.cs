using log4net;
using Newtonsoft.Json;

namespace BloodHoundConverter.Writers
{
    /// <summary>
    /// - CertTemplates
    /// </summary>
    internal class CertTemplateNodeWriter : IADNodeWriter
    {
        internal override ILog Log => LogManager.GetLogger(typeof(CertTemplateNodeWriter));

        private static readonly HashSet<string> AuthOids = new(StringComparer.OrdinalIgnoreCase)
        {
            "1.3.6.1.5.5.7.3.2",     // Client Authentication
            "1.3.6.1.4.1.311.20.2.2", // Smart Card Logon
            "1.3.6.1.5.2.3.4",       // PKINIT Client Authentication
            "2.5.29.37.0"            // Any Purpose
        };

        private static readonly HashSet<string> SchannelAuthOids = new(StringComparer.OrdinalIgnoreCase)
        {
            "1.3.6.1.5.5.7.3.2",     // Client Authentication
            "2.5.29.37.0"            // Any Purpose
        };

        public override void WriteNode(JsonTextWriter writer, NodeProcessingContext context)
        {
            writer.WriteStartObject();
            WriteProperties(writer, context);
            AceParser.WriteAcesFromDescriptor(writer, context.SecurityDescriptorBytes, ObjectType.CertTemplate, context.DomainName);
            WriteBaseNodeValues(writer, context, context.ObjectGUID);
            WriteContainedBy(writer, context);
            writer.WriteEndObject();
        }

        internal override void WriteProperties(JsonTextWriter writer, NodeProcessingContext context)
        {
            writer.WritePropertyName("Properties");
            writer.WriteStartObject();

            WriteBasePropertyValues(writer, context);

            int? schemaVersion = int.TryParse(context.GetFirstAttributeValue("mspki-template-schema-version"), out int intSchemaVersion) ? intSchemaVersion : null;
            if (schemaVersion.HasValue)
            {
                WriteProperty(writer, "schemaversion", schemaVersion);
            }

            // applicationpolicies comes from msPKI-RA-Application-Policies (the RA signature policies),
            // not from the certificate application policy. On schema v3 / v4-CNG templates that attribute
            // is a composite string that ParseApplicationPolicies unpacks.
            bool hasUseLegacyProvider = int.TryParse(context.GetFirstAttributeValue("mspki-private-key-flag"), out int pkFlags)
                && (pkFlags & 0x00000100) != 0; // CT_FLAG_USE_LEGACY_PROVIDER
            var appPolicies = ParseApplicationPolicies(context.GetAttributeValues("mspki-ra-application-policies"), schemaVersion ?? 0, hasUseLegacyProvider);
            WritePropertyArray(writer, "applicationpolicies", appPolicies);

            var ekus = context.GetAttributeValues("pkiextendedkeyusage");
            WritePropertyArray(writer, "ekus", ekus);

            var certificateapplicationpolicy = context.GetAttributeValues("mspki-certificate-application-policy");
            WritePropertyArray(writer, "certificateapplicationpolicy", certificateapplicationpolicy);

            WritePropertyArray(writer, "certificatepolicy", context.GetAttributeValues("mspki-certificate-policy"));

            // Only schema v1 templates use pkiExtendedKeyUsage as the effective EKUs; v2+ (and any
            // template without a known schema version) use the certificate application policy.
            var effectiveekus = schemaVersion == 1 && ekus?.Count > 0 ? ekus : certificateapplicationpolicy;
            WritePropertyArray(writer, "effectiveekus", effectiveekus);

            string? oid = context.GetFirstAttributeValue("msPKI-Cert-Template-OID");
            if (!string.IsNullOrWhiteSpace(oid))
            {
                WriteProperty(writer, "oid", oid);
            }

            WritePropertyInt(writer, "authorizedsignatures", context.GetFirstAttributeValue("msPKI-RA-Signature"));
            WritePropertyArray(writer, "issuancepolicies", context.GetAttributeValues("mspki-ra-policies"), []);

            string? rawValidity = context.GetFirstAttributeValue("pKIExpirationPeriod");
            string? rawRenewal = context.GetFirstAttributeValue("pKIOverlapPeriod");

            if (!string.IsNullOrWhiteSpace(rawValidity))
            {
                Span<byte> valBytes = new(new byte[rawValidity.Length]);
                if (Convert.TryFromBase64String(rawValidity, valBytes, out int bytesWritten))
                {
                    var validity = Helpers.ParseAdTimePeriod(valBytes.ToArray());
                    WriteProperty(writer, "validityperiod", validity);
                }
            }
            if (!string.IsNullOrWhiteSpace(rawRenewal))
            {
                Span<byte> renewBytes = new(new byte[rawRenewal.Length]);
                if (Convert.TryFromBase64String(rawRenewal, renewBytes, out int bytesWritten))
                {
                    var renewal = Helpers.ParseAdTimePeriod(renewBytes.ToArray());
                    WriteProperty(writer, "renewalperiod", renewal);
                }
            }

            int? enrollmentFlag = int.TryParse(context.GetFirstAttributeValue("msPKI-Enrollment-Flag"), out int ef) ? ef : null;
            int? nameFlag = int.TryParse(context.GetFirstAttributeValue("msPKI-Certificate-Name-Flag"), out int nf) ? nf : null;
            if (enrollmentFlag.HasValue)
            {
                WriteProperty(writer, "enrollmentflag", enrollmentFlag);
                bool requiresManagerApproval = (enrollmentFlag & 0x00000002) != 0; // CT_FLAG_PEND_ALL_REQUESTS
                bool noSecurityExtension = (enrollmentFlag & 0x00080000) != 0;     // CT_FLAG_NO_SECURITY_EXTENSION
                WriteProperty(writer, "requiresmanagerapproval", requiresManagerApproval);
                WriteProperty(writer, "nosecurityextension", noSecurityExtension);
            }

            if (nameFlag.HasValue)
            {
                WriteProperty(writer, "certificatenameflag", nameFlag);

                // msPKI-Certificate-Name-Flag (CT_FLAG_*) bits
                WriteProperty(writer, "enrolleesuppliessubject", (nameFlag & 0x00000001) != 0);   // ENROLLEE_SUPPLIES_SUBJECT
                WriteProperty(writer, "subjectaltrequireupn", (nameFlag & 0x02000000) != 0);       // SUBJECT_ALT_REQUIRE_UPN
                WriteProperty(writer, "subjectaltrequiredns", (nameFlag & 0x08000000) != 0);       // SUBJECT_ALT_REQUIRE_DNS
                WriteProperty(writer, "subjectaltrequiredomaindns", (nameFlag & 0x00400000) != 0); // SUBJECT_ALT_REQUIRE_DOMAIN_DNS
                WriteProperty(writer, "subjectaltrequireemail", (nameFlag & 0x04000000) != 0);     // SUBJECT_ALT_REQUIRE_EMAIL
                WriteProperty(writer, "subjectaltrequirespn", (nameFlag & 0x00800000) != 0);       // SUBJECT_ALT_REQUIRE_SPN
                WriteProperty(writer, "subjectrequireemail", (nameFlag & 0x20000000) != 0);        // SUBJECT_REQUIRE_EMAIL
            }

            // msPKI-Template-Schema-Version (like the certificate-application-policy and the other mspki-*
            // template attributes) is part of the full LDAP object but not the GC partial attribute set,
            // so its presence marks a full dump. For a full dump, follow SharpHound: an empty effectiveEKUs
            // set means "no EKU restriction → usable for any purpose", so authentication is enabled. For a
            // GC-sourced dump the effective EKUs cannot be computed reliably (schema version and
            // certificate-application-policy are absent), so omit the flags (fail safe) rather than flag
            // every template as authentication-capable.
            if (schemaVersion.HasValue)
            {
                var effective = effectiveekus ?? [];
                bool noEkuRestriction = effective.Count == 0;
                WriteProperty(writer, "authenticationenabled", noEkuRestriction || effective.Any(eku => AuthOids.Contains(eku)));
                WriteProperty(writer, "schannelauthenticationenabled", noEkuRestriction || effective.Any(eku => SchannelAuthOids.Contains(eku)));
            }

            writer.WriteEndObject();
        }

        /// <summary>
        /// Resolves the template's application policies from the raw msPKI-RA-Application-Policies
        /// values. For schema v1/v2 (and v4 with the legacy provider) the values are returned as-is.
        /// For schema v3 / v4-CNG the single value is a composite "Name`Type`Value`..." string
        /// (MS-CRTD 2.27); this returns the Value of each msPKI-RA-Application-Policies entry.
        /// </summary>
        private static List<string>? ParseApplicationPolicies(List<string>? applicationPolicies, int schemaVersion, bool hasUseLegacyProvider)
        {
            if (applicationPolicies == null
                || applicationPolicies.Count == 0
                || schemaVersion == 1
                || schemaVersion == 2
                || (schemaVersion == 4 && hasUseLegacyProvider))
            {
                return applicationPolicies;
            }

            var entries = applicationPolicies[0].Split('`');
            var result = new List<string>();
            for (int i = 0; i + 2 < entries.Length; i += 3)
            {
                if (entries[i].Equals("mspki-ra-application-policies", StringComparison.OrdinalIgnoreCase))
                {
                    result.Add(entries[i + 2]);
                }
            }
            return result;
        }
    }

}