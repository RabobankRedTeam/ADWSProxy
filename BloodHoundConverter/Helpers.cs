using log4net;
using System.Globalization;
using System.Text;

namespace BloodHoundConverter
{
    internal class Helpers
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(Helpers));
        private static bool HasNotifiedWindowsOnly = false;
        private const string WindowsOnlyMessage = "Part of the functionality is Windows only, more data will be processed when it's processed on a Windows machine";
        // DNs of objects we synthesized a deterministic GUID for. A HashSet because ResolveGuid can
        // run more than once per object (mapping pass + node-context creation); dedup keeps the count
        // and the saved file at one entry per object.
        public static readonly HashSet<string> GeneratedGuidsFor = new(StringComparer.OrdinalIgnoreCase);

        public static string ObjectTypeToString(ObjectType? objectType) => objectType switch
        {
            ObjectType.User => "user",
            ObjectType.Computer => "computer",
            ObjectType.Group => "group",
            ObjectType.GPO => "gpo",
            ObjectType.Domain => "domain",
            ObjectType.OU => "ou",
            ObjectType.Container => "container",
            ObjectType.Configuration => "configuration",
            ObjectType.CertTemplate => "certTemplate",
            ObjectType.RootCA => "rootca",
            ObjectType.AIACA => "aiaca",
            ObjectType.EnterpriseCA => "enterpriseca",
            ObjectType.NTAuthStore => "ntauthstore",
            ObjectType.IssuancePolicy => "issuancepolicy",
            ObjectType.Base => "base",
            _ => "base"
        };

        public static string ParseAdTimePeriod(long ticks)
        {
            if (ticks >= 0) return "0 hours";

            // Avoid Math.Abs overflow exception on long.MinValue
            long positiveTicks = (ticks == long.MinValue) ? long.MaxValue : -ticks;
            TimeSpan span = TimeSpan.FromTicks(positiveTicks);

            double totalDays = span.TotalDays;
            if (totalDays >= 365)
            {
                // Accounts for leap year shifts (~365.25 days per year)
                int years = (int)Math.Round(totalDays / 365.25);
                return $"{years} year{(years > 1 ? "s" : "")}";
            }

            if (totalDays >= 7 && (int)totalDays % 7 == 0)
            {
                int weeks = (int)(totalDays / 7);
                return $"{weeks} week{(weeks > 1 ? "s" : "")}";
            }

            if (totalDays >= 1)
            {
                int days = (int)totalDays;
                return $"{days} day{(days > 1 ? "s" : "")}";
            }

            int hours = (int)span.TotalHours;
            return $"{hours} hour{(hours > 1 ? "s" : "")}";
        }

        public static string ParseAdTimePeriod(byte[]? bytes)
        {
            if (bytes == null || bytes.Length < 8)
            {
                return "0 days";
            }

            // Read the file time ticks from the raw byte layout
            long ticks = BitConverter.ToInt64(bytes, 0);
            return ParseAdTimePeriod(ticks);
        }

        public static string ResolveGuid(string? value, string dn, out bool isDeterministic)
        {
            isDeterministic = false;
            if (TryParseRawGuid(value, out string validGuid))
            {
                return validGuid;
            }

            if (!string.IsNullOrWhiteSpace(dn))
            {
                const int guidLen = 36;
                for (int i = 0; i <= dn.Length - guidLen; i++)
                {
                    if (dn[i] == '{' || (i == 0 || dn[i - 1] == '='))
                    {
                        var candidate = dn.AsSpan(i, guidLen);
                        if (Guid.TryParse(candidate, out var parsedDnGuid))
                        {
                            return parsedDnGuid.ToString().ToUpperInvariant();
                        }
                    }
                }
            }

            isDeterministic = true;
            return GenerateDeterministicGuid(dn);
        }

        private static bool TryParseRawGuid(string? input, out string formattedGuid)
        {
            formattedGuid = string.Empty;
            if (string.IsNullOrWhiteSpace(input)) return false;

            ReadOnlySpan<char> span = input.AsSpan().Trim();

            // Try standard GUID parse
            if (Guid.TryParse(span, out var parsedGuid))
            {
                formattedGuid = parsedGuid.ToString().ToUpperInvariant();
                return true;
            }

            // Try Base64 string parse
            if (span.Length == 24)
            {
                Span<byte> bytes = stackalloc byte[16];
                if (Convert.TryFromBase64String(input, bytes, out int bytesWritten) && bytesWritten == 16)
                {
                    formattedGuid = new Guid(bytes).ToString().ToUpperInvariant();
                    return true;
                }
            }

            return false;
        }

        private static string GenerateDeterministicGuid(string text)
        {
            if (string.IsNullOrEmpty(text))
            {
                return Guid.Empty.ToString().ToUpperInvariant();
            }

            GeneratedGuidsFor.Add(text);

            byte[] hash = System.Security.Cryptography.MD5.HashData(Encoding.UTF8.GetBytes(text.ToUpperInvariant()));

            var generatedGuid = new Guid(hash).ToString().ToUpperInvariant();
            log.Debug($"Generated deterministic GUID for {text}: {generatedGuid}");
            return generatedGuid;
        }

        public static long? GeneralizedTimeToUnixEpoch(string? rawTime)
        {
            if (string.IsNullOrWhiteSpace(rawTime)) return null;

            const string format = "yyyyMMddHHmmss.0'Z'";
            if (DateTime.TryParseExact(rawTime, format, CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out DateTime dt))
            {
                return ((DateTimeOffset)dt).ToUnixTimeSeconds();
            }
            return null;
        }

        /// <summary>
        /// Converts an Active Directory Integer8 timestamp (FILETIME: 100ns ticks since 1601-01-01 UTC,
        /// used by pwdLastSet, lastLogon, lastLogonTimestamp, etc.) to Unix epoch seconds.
        /// Returns null for the "not set" (0) and "never" (long.MaxValue) sentinels.
        /// </summary>
        public static long? FileTimeToUnixEpoch(string? rawFileTime)
        {
            if (string.IsNullOrWhiteSpace(rawFileTime)) return null;
            if (!long.TryParse(rawFileTime, out long ticks)) return null;
            if (ticks <= 0 || ticks == long.MaxValue) return null;

            try
            {
                return ((DateTimeOffset)DateTime.FromFileTimeUtc(ticks)).ToUnixTimeSeconds();
            }
            catch (ArgumentOutOfRangeException)
            {
                return null;
            }
        }

        public static string? ParseSid(string? value)
        {
            if (string.IsNullOrWhiteSpace(value)) return null;

            ReadOnlySpan<char> span = value.AsSpan().Trim();

            if (span.StartsWith("S-", StringComparison.OrdinalIgnoreCase))
            {
                return value.ToUpperInvariant();
            }

            Span<byte> bytes = stackalloc byte[128];
            if (!Convert.TryFromBase64String(value, bytes, out int bytesWritten) || bytesWritten < 8)
            {
                return string.Empty;
            }

            ReadOnlySpan<byte> sidBytes = bytes[..bytesWritten];
            byte revision = sidBytes[0];
            byte subAuthorityCount = sidBytes[1];

            if (8 + (subAuthorityCount * 4) > bytesWritten)
            {
                return string.Empty;
            }

            long authority = 0;
            for (int i = 2; i <= 7; i++)
            {
                authority = (authority << 8) | sidBytes[i];
            }

            var sb = new StringBuilder(64);
            sb.Append("S-").Append(revision).Append('-').Append(authority);

            for (int i = 0; i < subAuthorityCount; i++)
            {
                int offset = 8 + (i * 4);
                uint subAuthority = System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(sidBytes.Slice(offset, 4));
                sb.Append('-').Append(subAuthority);
            }

            return sb.ToString();
        }

        /// <summary>
        /// Builds a primary-group SID from an object SID and its primaryGroupID RID. Built-in local
        /// groups (RID 540-580) resolve to S-1-5-32-RID; otherwise the object SID's domain prefix is
        /// combined with the RID. Single source of truth for all node writers.
        /// </summary>
        public static string CalculateGroupSid(string? objectSid, string? primaryGroupRid)
        {
            if (string.IsNullOrWhiteSpace(objectSid) || string.IsNullOrWhiteSpace(primaryGroupRid))
                return string.Empty;

            if (int.TryParse(primaryGroupRid, out int rid) && rid >= 540 && rid <= 580)
                return $"S-1-5-32-{primaryGroupRid}";

            int lastHyphenIndex = objectSid.LastIndexOf('-');
            if (lastHyphenIndex <= 0)
                return string.Empty;

            return $"{objectSid.AsSpan(0, lastHyphenIndex)}-{primaryGroupRid}";
        }

        /// <summary>
        /// Domain-scopes a principal SID the way SharpHound does. Universal / built-in identities carry
        /// the same raw SID in every domain (Everyone, Authenticated Users, BUILTIN\Administrators, ...),
        /// so each domain's copy is made distinct by prefixing the owning domain: {DOMAIN}-{SID}. A
        /// domain-relative SID (S-1-5-21-...) is already globally unique and an unrecognized SID is left
        /// untouched, so the same reference always resolves to the same node across nodes, ACEs and
        /// memberships. Scoping must be applied with the domain of the object that owns the reference.
        /// </summary>
        public static string ScopeSid(string? sid, string? domain, string? forestRoot = null)
        {
            if (string.IsNullOrEmpty(sid)) return sid ?? string.Empty;
            if (!WellKnownSids.IsScopable(sid)) return sid;
            // Forest-wide identities (Enterprise Domain Controllers) are scoped to the forest root; every
            // other well-known/built-in principal is scoped to the object's own domain.
            string? scope = WellKnownSids.ForestScoped.Contains(sid) ? (forestRoot ?? domain) : domain;
            return string.IsNullOrEmpty(scope) ? sid : $"{scope}-{sid}".ToUpperInvariant();
        }

        /// <summary>
        /// Builds a <see cref="DomainTrust"/> from a trustedDomain object's attributes, mirroring
        /// SharpHound's DomainTrustProcessor. Returns null when the target SID or the trust
        /// direction/attributes cannot be parsed. trustPartner supplies the target domain name
        /// (SharpHound uses canonicalName, which is not available offline).
        /// </summary>
        public static DomainTrust? BuildDomainTrust(string? securityIdentifier, string? trustPartner, string? trustDirectionRaw, string? trustAttributesRaw)
        {
            string? sid = ParseSid(securityIdentifier);
            if (string.IsNullOrEmpty(sid)) return null;
            if (!long.TryParse(trustDirectionRaw, out long td)) return null;
            if (!long.TryParse(trustAttributesRaw, out long ta)) return null;

            const long NonTransitive = 0x1, QuarantinedDomain = 0x4, ForestTransitive = 0x8,
                       WithinForest = 0x20, TreatAsExternal = 0x40, CrossOrgEnableTgtDelegation = 0x800;

            return new DomainTrust
            {
                TargetDomainSid = sid,
                TargetDomainName = trustPartner?.ToUpperInvariant() ?? string.Empty,
                TrustAttributes = ta,
                IsTransitive = (ta & NonTransitive) == 0,
                SidFilteringEnabled = (ta & QuarantinedDomain) != 0 ||
                    ((ta & ForestTransitive) != 0 && (ta & TreatAsExternal) == 0),
                TGTDelegationEnabled = (ta & QuarantinedDomain) == 0 &&
                    ((ta & WithinForest) != 0 || (ta & CrossOrgEnableTgtDelegation) != 0),
                TrustDirection = td switch
                {
                    0 => "Disabled",
                    1 => "Inbound",
                    2 => "Outbound",
                    3 => "Bidirectional",
                    _ => "Disabled"
                },
                TrustType = (ta & WithinForest) != 0 ? "ParentChild"
                    : (ta & ForestTransitive) != 0 ? "Forest"
                    : "External"
            };
        }

        internal static void NotifyWindowsOnlyFunctionality()
        {
            if (!OperatingSystem.IsWindows())
            {
                if (!HasNotifiedWindowsOnly)
                {
                    log.Warn(WindowsOnlyMessage);
                    HasNotifiedWindowsOnly = true;
                }
            }
        }

        internal static string? ParseBehaviorVersion(string? version)
        {
            return version switch
            {
                null => null,
                "0" => "2000 Mixed/Native",
                "1" => "2003 Interim",
                "2" => "2003",
                "3" => "2008",
                "4" => "2008 R2",
                "5" => "2012",
                "6" => "2012 R2",
                "7" => "2016",
                "8" => "2025",
                _ => "Unknown",
            };
        }
    }
}
