using System;
using System.Security.AccessControl;
using log4net;
using Newtonsoft.Json;

namespace BloodHoundConverter
{
    internal class AceParser
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(AceParser));

        // Tracking flag to prevent spamming the console/logs
        private static bool _hasLoggedPlatformWarningSecurityDescriptor = false;
        private static bool _hasLoggedPlatformWarningAce = false;

        private static readonly HashSet<string> NoiseSids = new(StringComparer.OrdinalIgnoreCase)
        {
            "S-1-1-0",   // Everyone
            "S-1-5-9",   // Enterprise Domain Controllers
            "S-1-5-10",  // Principal Self
            "S-1-5-11",  // Authenticated Users
            "S-1-5-18"   // LocalSystem / SYSTEM
        };

        public static void WriteAcesFromDescriptor(JsonTextWriter writer, byte[]? sdBytes, string targetObjectSid, Dictionary<string, string> sidToTypeMap)
        {
            writer.WritePropertyName("Aces");
            writer.WriteStartArray();

            if (sdBytes == null || sdBytes.Length == 0)
            {
                writer.WriteEndArray();
                return;
            }

            if (!OperatingSystem.IsWindows())
            {
                if (!_hasLoggedPlatformWarningSecurityDescriptor)
                {
                    log.Warn("ntSecurityDescriptor parsing is only supported on Windows. Skipping ACE generation for all records to prevent runtime platform exceptions.");
                    _hasLoggedPlatformWarningSecurityDescriptor = true;
                }

                writer.WriteEndArray();
                return;
            }

            try
            {
                // This block calls native Win32 APIs under the hood and will crash on Linux/macOS
                RawSecurityDescriptor rsd = new(sdBytes, 0);
                if (rsd.DiscretionaryAcl == null)
                {
                    writer.WriteEndArray();
                    return;
                }

                foreach (GenericAce ace in rsd.DiscretionaryAcl)
                {
                    if (ace is KnownAce knownAce &&
                       (knownAce.AceType == AceType.AccessAllowed || knownAce.AceType == AceType.AccessAllowedObject))
                    {
                        string principalSid = knownAce.SecurityIdentifier.ToString();
                        if (principalSid == targetObjectSid || NoiseSids.Contains(principalSid)) continue;

                        string rightName = MapAccessMask(knownAce.AccessMask, ace);

                        if (!string.IsNullOrEmpty(rightName))
                        {
                            writer.WriteStartObject();
                            writer.WritePropertyName("PrincipalSID"); writer.WriteValue(principalSid);
                            writer.WritePropertyName("PrincipalType"); writer.WriteValue(GetPrincipalType(principalSid, sidToTypeMap));
                            writer.WritePropertyName("RightName"); writer.WriteValue(rightName);
                            writer.WritePropertyName("IsInherited"); writer.WriteValue(knownAce.IsInherited);
                            writer.WriteEndObject();
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                // Catch any unhandled internal marshalling or serialization quirks
                log.Debug("Failed to parse individual structural DACL entry.", ex);
            }

            writer.WriteEndArray();
        }

        private static string MapAccessMask(int mask, GenericAce ace)
        {
            if ((mask & 0xf01ff) == 0xf01ff) return "GenericAll";
            if ((mask & 0x40000) == 0x40000) return "WriteDacl";
            if ((mask & 0x80000) == 0x80000) return "WriteOwner";
            if ((mask & 0x20000) == 0x20000) return "GenericWrite";

            if (!OperatingSystem.IsWindows())
            {
                if (!_hasLoggedPlatformWarningAce)
                {
                    log.Warn("Ace parsing is only supported on Windows. Skipping ACE generation for all records to prevent runtime platform exceptions.");
                    _hasLoggedPlatformWarningAce = true;
                }
                return string.Empty;
            }

            if (ace is ObjectAce objectAce && BloodHoundModels.ExtendedRights.TryGetValue(objectAce.ObjectAceType, out var right))
            {
                return right;
            }

            return string.Empty;
        }

        private static string GetPrincipalType(string sid, Dictionary<string, string> sidToTypeMap)
        {
            // 1. Direct High-Fidelity Lookup from Pass 1 Index
            if (sidToTypeMap.TryGetValue(sid, out var exactType))
            {
                return exactType; // Returns exactly "User", "Computer", or "Group"
            }

            // 2. Built-in Local Security Groups (S-1-5-32-X)
            if (sid.StartsWith("S-1-5-32-", StringComparison.OrdinalIgnoreCase))
            {
                return "Group";
            }

            // 3. Fallback evaluation via well-known relative identifier (RID) checks if outside capture scope
            if (sid.EndsWith("-512") || sid.EndsWith("-513") || sid.EndsWith("-515") || sid.EndsWith("-516") || sid.EndsWith("-520"))
            {
                return "Group";
            }

            // Default safety fallback for unknown references
            return "User";
        }
    }
}