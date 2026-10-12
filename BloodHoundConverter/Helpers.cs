using log4net;
using System.Globalization;
using System.Text;

namespace BloodHoundConverter
{
    internal class Helpers
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(Helpers));
        private static bool HasNotifiedWindowsOnly = false;
        private const string WindowsOnlyMessage = "Part of the funcationlity is Windows only, more data will be processed when it's processed on a Windows machine";
        public static readonly List<string> GeneratedGuidsFor = [];

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

        public static string ConvertCertificateNameFlags(int flags)
        {
            List<string> options = [];
            if ((flags & 0x00000001) != 0) options.Add("ENROLLEE_SUPPLIES_SUBJECT");
            if ((flags & 0x00400000) != 0) options.Add("SUBJECT_ALT_REQUIRE_UPN");
            if ((flags & 0x00800000) != 0) options.Add("SUBJECT_ALT_REQUIRE_DNS");
            if ((flags & 0x01000000) != 0) options.Add("SUBJECT_REQUIRE_DIRECTORY_PATH");

            return options.Count > 0 ? string.Join(", ", options) : "None";
        }

        public static string NameFromDn(string dn)
        {
            if (string.IsNullOrWhiteSpace(dn)) return string.Empty;
            try
            {
                var cnComponent = dn.Split(',')
                    .Select(part => part.Trim())
                    .FirstOrDefault(part => part.StartsWith("CN=", StringComparison.OrdinalIgnoreCase));
                if (cnComponent != null)
                {
                    return cnComponent[3..].Trim();
                }
            }
            catch
            {
                log.Debug($"Failed to extract CN from DN: {dn}");
            }
            return string.Empty;
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
