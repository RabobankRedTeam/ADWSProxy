namespace BloodHoundConverter
{
    internal static class EnrollmentConfigurationParser
    {
        public class EnrollmentConfiguration
        {
            public bool EnrolleeSuppliesSubject { get; set; }
            public bool NoSecurityExtension { get; set; }
            public bool RequiresManagerApproval { get; set; }
            public bool SubjectAltRequireDNS { get; set; }
            public bool SubjectAltRequireDomainDNS { get; set; }
            public bool SubjectAltRequireEmail { get; set; }
            public bool SubjectAltRequireSPN { get; set; }
            public bool SubjectAltRequireUPN { get; set; }
            public bool SubjectRequireEmail { get; set; }
            public string EnrollmentFlagsText { get; set; } = "None";
            public string NameFlagText { get; set; } = string.Empty;
        }

        public static EnrollmentConfiguration Parse(Dictionary<string, List<string>> attrs)
        {
            var config = new EnrollmentConfiguration();
            int flagValue = 0;

            if (attrs.TryGetValue("flags", out var fList) && fList.Count > 0)
            {
                _ = int.TryParse(fList[0], out flagValue);
            }

            config.EnrolleeSuppliesSubject = (flagValue & 0x00000001) != 0;
            config.NoSecurityExtension = (flagValue & 0x00000040) != 0;
            config.RequiresManagerApproval = (flagValue & 0x00000002) != 0;
            config.SubjectAltRequireDNS = (flagValue & 0x00800000) != 0;
            config.SubjectAltRequireDomainDNS = (flagValue & 0x01000000) != 0;
            config.SubjectAltRequireEmail = (flagValue & 0x02000000) != 0;
            config.SubjectAltRequireSPN = (flagValue & 0x08000000) != 0;
            config.SubjectAltRequireUPN = (flagValue & 0x00400000) != 0;
            config.SubjectRequireEmail = (flagValue & 0x04000000) != 0;

            List<string> activeFlags = [];
            if ((flagValue & 0x00000001) != 0) activeFlags.Add("INCLUDE_SYMMETRIC_ALGORITHMS");
            if ((flagValue & 0x00000002) != 0) activeFlags.Add("PEND_ALL_REQUESTS");
            if ((flagValue & 0x00000004) != 0) activeFlags.Add("PUBLISH_TO_KRA_CONTAINER");
            if ((flagValue & 0x00000008) != 0) activeFlags.Add("PUBLISH_TO_DS");
            if ((flagValue & 0x00000010) != 0) activeFlags.Add("AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE");
            if ((flagValue & 0x00000020) != 0) activeFlags.Add("AUTO_ENROLLMENT");
            if ((flagValue & 0x00000040) != 0) activeFlags.Add("NO_SECURITY_EXTENSION");
            if ((flagValue & 0x00000080) != 0) activeFlags.Add("RENEWAL_REQUIRE_SMIME_CERTIFICATE");
            if ((flagValue & 0x00000100) != 0) activeFlags.Add("USER_INTERACTION_REQUIRED");
            if ((flagValue & 0x00000400) != 0) activeFlags.Add("REMOVE_INVALID_CERT_FROM_PERSONAL_STORE");

            if (activeFlags.Count > 0)
            {
                config.EnrollmentFlagsText = string.Join(", ", activeFlags);
            }

            List<string> nameFlags = [];
            if ((flagValue & 0x00000001) != 0) nameFlags.Add("ENROLLEE_SUPPLIES_SUBJECT");
            if ((flagValue & 0x00400000) != 0) nameFlags.Add("SUBJECT_ALT_REQUIRE_UPN");
            if ((flagValue & 0x00800000) != 0) nameFlags.Add("SUBJECT_ALT_REQUIRE_DNS");
            if ((flagValue & 0x01000000) != 0) nameFlags.Add("SUBJECT_REQUIRE_DIRECTORY_PATH");
            if ((flagValue & 0x02000000) != 0) nameFlags.Add("SUBJECT_ALT_REQUIRE_EMAIL");
            if ((flagValue & 0x04000000) != 0) nameFlags.Add("SUBJECT_REQUIRE_EMAIL");
            if ((flagValue & 0x08000000) != 0) nameFlags.Add("SUBJECT_ALT_REQUIRE_SPN");

            config.NameFlagText = string.Join(", ", nameFlags);

            return config;
        }
    }
}
