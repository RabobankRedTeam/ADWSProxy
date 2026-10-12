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

        public override void WriteNode(JsonTextWriter writer, NodeProcessingContext context)
        {
            writer.WriteStartObject();
            WriteProperties(writer, context);
            AceParser.WriteAcesFromDescriptor(writer, context.SecurityDescriptorBytes);
            WriteBaseNodeValues(writer, context, context.ObjectGUID);
            WriteContaineredBy(writer, context);
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

            var appPolicies = context.GetAttributeValues("msPKI-Certificate-Application-Policy");
            if (context.DistinguishedName.Contains("CN=CROSSCA", StringComparison.OrdinalIgnoreCase) && appPolicies?.Count == 0)
            {
                appPolicies.Add("1.3.6.1.4.1.311.10.3.10");
            }
            WritePropertyArray(writer, "applicationpolicies", appPolicies);

            var ekus = context.GetAttributeValues("pkiextendedkeyusage");
            WritePropertyArray(writer, "ekus", ekus);

            var certificateapplicationpolicy = context.GetAttributeValues("mspki-certificate-application-policy");
            WritePropertyArray(writer, "certificateapplicationpolicy", certificateapplicationpolicy);

            var effectiveekus = (schemaVersion == null || schemaVersion == 1) && ekus?.Count > 0 ? ekus : certificateapplicationpolicy;
            WritePropertyArray(writer, "effectiveekus", effectiveekus);

            string? oid = context.GetFirstAttributeValue("msPKI-Cert-Template-OID");
            if (!string.IsNullOrWhiteSpace(oid))
            {
                WriteProperty(writer, "oid", oid);
            }

            string? rawValidty = context.GetFirstAttributeValue("pKIExpirationPeriod");
            string? rawRenuwal = context.GetFirstAttributeValue("pKIOverlapPeriod");

            if (!string.IsNullOrWhiteSpace(rawValidty))
            {
                Span<byte> valBytes = new(new byte[rawValidty.Length]);
                if (Convert.TryFromBase64String(rawValidty, valBytes, out int bytesWritten))
                {
                    var validity = Helpers.ParseAdTimePeriod(valBytes.ToArray());
                    WriteProperty(writer, "validityperiod", validity);
                }
            }
            if (!string.IsNullOrWhiteSpace(rawRenuwal))
            {
                Span<byte> renuwBytes = new(new byte[rawRenuwal.Length]);
                if (Convert.TryFromBase64String(rawRenuwal, renuwBytes, out int bytesWritten))
                {
                    var renuwal = Helpers.ParseAdTimePeriod(renuwBytes.ToArray());
                    WriteProperty(writer, "renewalperiod", renuwal);
                }
            }

            int? enrollmentFlag = int.TryParse(context.GetFirstAttributeValue("msPKI-Enrollment-Flag"), out int ef) ? ef : null;
            int? nameFlag = int.TryParse(context.GetFirstAttributeValue("msPKI-Certificate-Name-Flag"), out int nf) ? nf : null;
            if (enrollmentFlag.HasValue)
            {
                WriteProperty(writer, "enrollmentflag", enrollmentFlag);
                bool requiresManagerApproval = (enrollmentFlag & 0x00000002) != 0; // CT_FLAG_PENDING_INSULTS
                bool noSecurityExtension = (enrollmentFlag & 0x00080000) != 0;     // CT_FLAG_NO_SECURITY_EXTENSION
                WriteProperty(writer, "requiresmanagerapproval", requiresManagerApproval);
                WriteProperty(writer, "nosecurityextension", noSecurityExtension);
            }

            if (nameFlag.HasValue)
            {
                WriteProperty(writer, "certificatenameflag", nameFlag);

                bool enrolleeSuppliesSubject = (nameFlag & 0x00000001) != 0;       // CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT
                bool subjectAltRequireUpn = (nameFlag & 0x00000200) != 0;          // CT_FLAG_SUBJECT_ALT_REQUIRE_UPN
                WriteProperty(writer, "enrolleesuppliessubject", enrolleeSuppliesSubject);
                WriteProperty(writer, "subjectaltrequireupn", subjectAltRequireUpn);
            }

            bool? authEnabled = ekus?.Any(eku => AuthOids.Contains(eku));
            if (authEnabled.HasValue)
            {
                WriteProperty(writer, "authenticationenabled", authEnabled);
            }

            writer.WriteEndObject();
        }
    }

}