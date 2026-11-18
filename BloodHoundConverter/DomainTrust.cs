namespace BloodHoundConverter
{
    /// <summary>
    /// A domain trust as BloodHound expects it in a domain node's "Trusts" array, derived from a
    /// trustedDomain object's trustDirection/trustAttributes/securityIdentifier/trustPartner.
    /// </summary>
    internal class DomainTrust
    {
        public string TargetDomainSid { get; set; } = string.Empty;
        public string TargetDomainName { get; set; } = string.Empty;
        public bool IsTransitive { get; set; }
        public bool SidFilteringEnabled { get; set; }
        public bool TGTDelegationEnabled { get; set; }
        public long TrustAttributes { get; set; }
        public string TrustDirection { get; set; } = "Disabled";
        public string TrustType { get; set; } = "Unknown";
    }
}
