namespace BloodHoundConverter.Writers
{
    internal class NodeProcessingContext
    {
        internal string Name { get; set; } = string.Empty;
        internal string DistinguishedName { get; set; } = string.Empty;
        internal string ObjectSid { get; set; } = string.Empty;
        internal string DomainName { get; set; } = string.Empty;
        internal string DomainSid { get; set; } = string.Empty;
        internal string? Description { get; set; } = null;
        internal byte[]? SecurityDescriptorBytes { get; set; }
        internal Dictionary<string, List<string>> Attributes { get; set; } = [];
        internal SecurityDescriptorResult? SdResult { get; set; } = null;
        internal UacProperties? UacProps { get; set; } = null;
        internal string ObjectGUID { get; set; } = string.Empty;
        internal long? WhenCreated { get; set; } = null;
        internal long? WhenChanged { get; set; } = null;
        internal string SamAccountName { get; set; } = string.Empty;

        private static string ExtractDomainFromDn(string dn)
        {
            if (string.IsNullOrWhiteSpace(dn)) return string.Empty;
            try
            {
                var dcComponents = dn.Split(',')
                    .Select(part => part.Trim())
                    .Where(part => part.StartsWith("DC=", StringComparison.OrdinalIgnoreCase))
                    .Select(part => part[3..])
                    .ToArray();

                return dcComponents.Length == 0 ? string.Empty : string.Join(".", dcComponents).ToUpperInvariant();
            }
            catch { return string.Empty; }
        }

        // Objects in the DNS application partitions (DomainDnsZones/ForestDnsZones) carry DC= components
        // for the DNS node hierarchy, so the raw DC= join is not a real domain. Map an object to the real
        // AD domain it belongs to: the longest SID-bearing domain its DC= DNS ends with. Falls back to the
        // raw value when nothing matches, so a well-known principal is scoped to a real domain rather than
        // a per-DNS-node pseudo-domain.
        private static string ResolveOwningDomain(string rawDomainDns, Dictionary<string, string> domainToSidMap)
        {
            if (string.IsNullOrEmpty(rawDomainDns)) return rawDomainDns;
            string best = rawDomainDns;
            int bestLen = -1;
            foreach (var known in domainToSidMap.Keys)
            {
                if ((rawDomainDns.Equals(known, StringComparison.OrdinalIgnoreCase) ||
                     rawDomainDns.EndsWith("." + known, StringComparison.OrdinalIgnoreCase)) &&
                    known.Length > bestLen)
                {
                    best = known;
                    bestLen = known.Length;
                }
            }
            return best.ToUpperInvariant();
        }

        internal NodeProcessingContext(
            DataHolder dataHolder,
            string domainSid,
            Dictionary<string, ObjectType> sidToTypeMap,
            Dictionary<string, string> domainToSidMap,
            Dictionary<string, ObjectIdentity> dnToIdentityMap,
            Dictionary<string, HashSet<ObjectIdentity>> groupMembersMap,
            Dictionary<string, string> dnsNameToSidMap,
            Dictionary<string, string> certTemplateCnToGuidMap)
        {
            DistinguishedName = dataHolder.DistinguishedName;
            Description = GetFirstAttributeValue("description");

            if (dataHolder.Attributes.Count == 0)
            {
                return;
            }
            Attributes = dataHolder.Attributes;
            SamAccountName = GetFirstAttributeValue("sAMAccountName") ??
                                        GetFirstAttributeValue("displayName") ??
                                        GetFirstAttributeValue("name") ??
                                        GetFirstAttributeValue("cn") ??
                                        string.Empty;
            DomainName = ResolveOwningDomain(ExtractDomainFromDn(dataHolder.DistinguishedName), domainToSidMap);
            string[] typesWithDotInName = ["computer"];
            var objectClasses = GetAttributeValues("objectclass");
            // gMSA/sMSA carry the "computer" objectClass but are emitted as user nodes, so they take
            // the user-style SAM@DOMAIN name rather than the computer-style dotted name.
            bool isManagedServiceAccount = objectClasses?.Any(x =>
                x.Equals("msDS-GroupManagedServiceAccount", StringComparison.OrdinalIgnoreCase) ||
                x.Equals("msDS-ManagedServiceAccount", StringComparison.OrdinalIgnoreCase)) == true;
            // The domain object's name is its DNS FQDN, not a SAM-derived dotted name.
            bool isDomainObject = objectClasses?.Any(x =>
                x.Equals("domainDNS", StringComparison.OrdinalIgnoreCase)) == true;
            bool useDottedName = !isManagedServiceAccount &&
                objectClasses?.Any(x => typesWithDotInName.Contains(x)) == true;
            Name = isDomainObject
                ? DomainName
                : useDottedName
                    ? $"{SamAccountName.Trim('$')}.{DomainName}".ToUpperInvariant()
                    : $"{SamAccountName.Trim('$')}@{DomainName}".ToUpperInvariant();
            // Domain-scope the node's own identifier so a well-known/built-in principal (e.g. a
            // BUILTIN group) gets the same {DOMAIN}-{SID} identity used by every ACE/membership
            // reference to it; domain-relative SIDs are returned unchanged.
            ObjectSid = GetFirstAttributeValue("objectSid") is string rawSid ? Helpers.ScopeSid(Helpers.ParseSid(rawSid), DomainName) : string.Empty;

            DomainSid = domainSid;

            var sdToken = GetFirstAttributeValue("ntSecurityDescriptor");
            byte[]? sdBytes = null;
            if (!string.IsNullOrWhiteSpace(sdToken))
            {
                sdBytes = Convert.FromBase64String(sdToken);
                SecurityDescriptorBytes = sdBytes;
                SdResult = SecurityDescriptorParser.Parse(SecurityDescriptorBytes);
            }

            BloodHoundConverter.CertTemplateCnToGuidMap = certTemplateCnToGuidMap;
            BloodHoundConverter.DnsNameToIdMap = dnsNameToSidMap;
            BloodHoundConverter.DnToIdentityMap = dnToIdentityMap;
            BloodHoundConverter.DomainToSidMap = domainToSidMap;
            BloodHoundConverter.GroupMembersMap = groupMembersMap;
            BloodHoundConverter.IdToTypeMap = sidToTypeMap;

            UacProps = new UacProperties(int.TryParse(GetFirstAttributeValue("userAccountControl"), out var uac) ? uac : 0);

            ObjectGUID = Helpers.ResolveGuid(GetFirstAttributeValue("objectGuid"), DistinguishedName, out bool hasDeterministicGuid);
            if (hasDeterministicGuid)
            {
                const string deterministicGuidMessage = "This GUID has been generated by the Bloodhound converter";
                if (string.IsNullOrWhiteSpace(Description))
                {
                    Description = deterministicGuidMessage;
                }
                else
                {
                    Description = $"{Description}\n\n{deterministicGuidMessage}";
                }
            }

            var rawWhenCreated = GetFirstAttributeValue("whencreated");
            if (!string.IsNullOrWhiteSpace(rawWhenCreated))
            {
                WhenCreated = Helpers.GeneralizedTimeToUnixEpoch(rawWhenCreated);
            }

            var rawWhenChanged = GetFirstAttributeValue("whenchanged");
            if (!string.IsNullOrWhiteSpace(rawWhenChanged))
            {
                WhenChanged = Helpers.GeneralizedTimeToUnixEpoch(rawWhenChanged);
            }
        }

        internal List<string>? GetAttributeValues(string key)
        {
            return Attributes.TryGetValue(key, out var values) ? values : null;
        }

        internal string? GetFirstAttributeValue(string key)
        {
            var values = GetAttributeValues(key);
            if (values?.Count > 0)
            {
                return values[0];
            }
            return null;
        }

    }
}
