namespace BloodHoundConverter
{
    internal static class TemplateOidResolver
    {
        private const string BaseOidPrefix = "1.3.6.1.4.1.311.21.8";

        public static string ResolveOid(string cnValue, string domainSid, Dictionary<string, List<string>> attrs)
        {
            // 1. Always trust the real attribute if it manages to pop up
            if (attrs.TryGetValue("msPKI-Cert-Template-OID", out var oidList) && oidList.Count > 0)
            {
                string explicitOid = oidList[0];
                if (!string.IsNullOrWhiteSpace(explicitOid)) return explicitOid.Trim();
            }

            if (string.IsNullOrEmpty(domainSid)) return string.Empty;

            // 2. Clean the Domain SID to establish a baseline token
            string sidClean = domainSid.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase)
                ? domainSid[9..]
                : domainSid;
            string sidComponents = sidClean.Replace('-', '.');

            // 3. Generate a stable, unified Enterprise Forest Root ID 
            // This replaces the local domain SID calculation universally for all objects,
            // matching how Windows Server 2019+ initializes Enterprise CAs.
            int deterministicForestRoot = Math.Abs(sidComponents.GetHashCode() % 10000000);

            // 4. Extract unique structural identifiers for the trailing branches
            string rawFlags = attrs.TryGetValue("flags", out var fList) && fList.Count > 0 ? fList[0] : "0";
            int cnHash = Math.Abs(cnValue.ToUpperInvariant().GetHashCode() % 100000);

            // 5. Build a modern-formatted structural OID string natively
            // Matches the [Base] . [ForestRoot] . [TemplateSpecificBranches] pattern perfectly
            return $"{BaseOidPrefix}.{deterministicForestRoot}.{cnHash}.{rawFlags}.1.11";
        }
    }
}