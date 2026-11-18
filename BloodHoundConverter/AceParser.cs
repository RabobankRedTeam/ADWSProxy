using BloodHoundConverter.Writers;
using log4net;
using Newtonsoft.Json;
using System.DirectoryServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;

namespace BloodHoundConverter
{
    internal class AceParser
    {

        private static readonly ILog log = LogManager.GetLogger(typeof(AceParser));

        internal static bool IsAccessAllowedAce(AceType aceType)
        {
            if (!OperatingSystem.IsWindows())
            {
                Helpers.NotifyWindowsOnlyFunctionality();
                return false;
            }
            return aceType switch
            {
                AceType.AccessAllowed => true,
                AceType.AccessAllowedObject => true,
                AceType.AccessAllowedCallback => true,
                AceType.AccessAllowedCallbackObject => true,
                AceType.AccessAllowedCompound => true,
                _ => false
            };
        }


        private const string OwnerRightsSid = "S-1-3-4";

        public static void WriteAcesFromDescriptor(JsonTextWriter writer, NodeProcessingContext context, ObjectType targetType)
        {
            WriteAcesFromDescriptor(writer, context.SecurityDescriptorBytes, targetType, context.DomainName);
        }

        private static void WriteAceObject(JsonTextWriter writer, string? sid, ObjectType type, string? rightName, bool isInherited, string? inheritanceHash, bool isPermissionForOwnerRightsSid, bool isInheritedPermissionForOwnerRightsSid)
        {
            writer.WriteStartObject();
            writer.WritePropertyName("PrincipalSID"); writer.WriteValue(sid);
            writer.WritePropertyName("PrincipalType"); writer.WriteValue(Helpers.ObjectTypeToString(type));
            writer.WritePropertyName("RightName"); writer.WriteValue(rightName);
            writer.WritePropertyName("IsInherited"); writer.WriteValue(isInherited);
            writer.WritePropertyName("InheritanceHash"); writer.WriteValue(inheritanceHash);
            writer.WritePropertyName("IsPermissionForOwnerRightsSid"); writer.WriteValue(isPermissionForOwnerRightsSid);
            writer.WritePropertyName("IsInheritedPermissionForOwnerRightsSid"); writer.WriteValue(isInheritedPermissionForOwnerRightsSid);
            writer.WriteEndObject();
        }

        internal static string CalculateInheritanceHash(string identityReference, ActiveDirectoryRights rights, string aceType, string inheritedObjectType)
        {
            var hash = identityReference + rights + aceType + inheritedObjectType;
            try
            {
                var bytes = SHA1.HashData(Encoding.UTF8.GetBytes(hash));
                return BitConverter.ToString(bytes).Replace("-", string.Empty).ToUpperInvariant();
            }
            catch
            {
                return "";
            }
        }

        /// <summary>
        /// Computes the InheritanceHashes for a container (domain/OU/container): the hash of every
        /// explicit, inheritable, non-deny ACE on the object's own security descriptor. BloodHound
        /// matches these against the InheritanceHash stamped on each inherited child ACE to trace
        /// where an inherited right originated. Windows-only (same constraint as ACL parsing).
        /// </summary>
        internal static IEnumerable<string> ComputeInheritanceHashes(byte[]? securityDescriptorBytes)
        {
            if (!OperatingSystem.IsWindows())
            {
                Helpers.NotifyWindowsOnlyFunctionality();
                yield break;
            }

            if (securityDescriptorBytes == null || securityDescriptorBytes.Length == 0)
            {
                yield break;
            }

            var activeDirectorySecurity = new ActiveDirectorySecurity();
            activeDirectorySecurity.SetSecurityDescriptorBinaryForm(securityDescriptorBytes);

            foreach (ActiveDirectoryAccessRule ace in activeDirectorySecurity.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            {
                // Only explicit (not already-inherited), non-deny ACEs that actually propagate to
                // children (InheritanceFlags set) seed a child's inherited ACE.
                if (ace == null
                    || ace.AccessControlType.HasFlag(AccessControlType.Deny)
                    || ace.IsInherited
                    || ace.InheritanceFlags == InheritanceFlags.None)
                {
                    continue;
                }

                var principalSid = ace.IdentityReference?.Value;
                if (string.IsNullOrWhiteSpace(principalSid))
                {
                    continue;
                }

                var hash = CalculateInheritanceHash(principalSid, ace.ActiveDirectoryRights,
                    ace.ObjectType.ToString().ToLowerInvariant(), ace.InheritedObjectType.ToString());
                if (!string.IsNullOrEmpty(hash))
                {
                    yield return hash;
                }
            }
        }

        internal class Ace
        {
            public string PrincipalSID { get; set; } = string.Empty;
            public ObjectType PrincipalType { get; set; } = ObjectType.Base;
            public string RightName { get; set; } = string.Empty;
            public bool IsInherited { get; set; }
            public string InheritanceHash { get; set; } = string.Empty;
            public bool IsPermissionForOwnerRightsSid { get; set; }
            public bool IsInheritedPermissionForOwnerRightsSid { get; set; }
        }

        internal static IEnumerable<Ace> ProcessACL(byte[]? securityDescriptorBytes, ObjectType targetType, string? domainScope = null, bool checkForOwnerRights = true)
        {
            if (!OperatingSystem.IsWindows())
            {
                Helpers.NotifyWindowsOnlyFunctionality();
                yield break;
            }

            if (securityDescriptorBytes == null || securityDescriptorBytes.Length == 0)
            {
                yield break;
            }

            var activeDirectorySecurity = new ActiveDirectorySecurity();
            activeDirectorySecurity.SetSecurityDescriptorBinaryForm(securityDescriptorBytes);
            string? forestScope = BloodHoundConverter.ForestRootOf(domainScope);
            var rawOwnerSid = activeDirectorySecurity.GetOwner(typeof(SecurityIdentifier))?.Value;

            if (rawOwnerSid != null)
            {
                string ownerSid = Helpers.ScopeSid(rawOwnerSid, domainScope, forestScope);
                if (WellKnownSids.Table.ContainsKey(rawOwnerSid))
                {
                    BloodHoundConverter.RecordWellKnownReference(domainScope, rawOwnerSid);
                }
                yield return new Ace
                {
                    PrincipalSID = ownerSid,
                    PrincipalType = WellKnownSids.Table.TryGetValue(rawOwnerSid, out var ownerWk) ? ownerWk.Type
                        : (BloodHoundConverter.IdToTypeMap.TryGetValue(ownerSid, out var type) ? type : ObjectType.Base),
                    RightName = EdgeNames.Owns,
                    IsInherited = false,
                    InheritanceHash = string.Empty,
                    IsPermissionForOwnerRightsSid = rawOwnerSid.Equals(OwnerRightsSid, StringComparison.OrdinalIgnoreCase),
                    IsInheritedPermissionForOwnerRightsSid = false
                };
            }

            foreach (ActiveDirectoryAccessRule ace in activeDirectorySecurity.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            {
                if (ace == null)
                {
                    continue;
                }

                if (ace.AccessControlType.HasFlag(AccessControlType.Deny))
                {
                    continue;
                }

                var rawPrincipalSid = ace.IdentityReference?.Value;
                if (string.IsNullOrWhiteSpace(rawPrincipalSid))
                {
                    continue;
                }

                // Domain-scope a well-known/built-in principal so the ACE edge targets the same
                // {DOMAIN}-{SID} node used elsewhere, and record universal principals so their node is
                // injected. The raw SID is kept for owner-rights and inheritance-hash matching.
                string principalSid = Helpers.ScopeSid(rawPrincipalSid, domainScope, forestScope);
                ObjectType principalType = WellKnownSids.Table.TryGetValue(rawPrincipalSid, out var wkPrincipal)
                    ? wkPrincipal.Type
                    : (BloodHoundConverter.IdToTypeMap.TryGetValue(principalSid, out var type) ? type : ObjectType.Base);
                if (WellKnownSids.Table.ContainsKey(rawPrincipalSid))
                {
                    BloodHoundConverter.RecordWellKnownReference(domainScope, rawPrincipalSid);
                }

                bool isPermissionForOwnerRightsSid = false;
                bool isInheritedPermissionForOwnerRightsSid = false;

                if (checkForOwnerRights && rawPrincipalSid.EndsWith("S-1-3-4", StringComparison.OrdinalIgnoreCase))
                {
                    isPermissionForOwnerRightsSid = true;
                }

                var aceRights = ace.ActiveDirectoryRights;
                var aceType = ace.ObjectType.ToString().ToLowerInvariant();
                var inherited = ace.IsInherited;

                var aceInheritanceHash = "";
                if (inherited)
                {
                    aceInheritanceHash = CalculateInheritanceHash(rawPrincipalSid, aceRights, aceType, ace.InheritedObjectType.ToString());

                    if (checkForOwnerRights && rawPrincipalSid.EndsWith("S-1-3-4", StringComparison.OrdinalIgnoreCase))
                    {
                        isInheritedPermissionForOwnerRightsSid = true;
                    }
                }

                if (aceType is AceGuids.AllGuid or "")
                {
                    if (aceRights.HasFlag(ActiveDirectoryRights.GenericAll))
                    {
                        yield return new Ace
                        {
                            PrincipalSID = principalSid,
                            PrincipalType = principalType,
                            RightName = EdgeNames.GenericAll,
                            IsInherited = inherited,
                            InheritanceHash = aceInheritanceHash,
                            IsPermissionForOwnerRightsSid = isPermissionForOwnerRightsSid,
                            IsInheritedPermissionForOwnerRightsSid = isInheritedPermissionForOwnerRightsSid
                        };
                        continue;
                    }

                    if (aceRights.HasFlag(ActiveDirectoryRights.WriteDacl))
                    {
                        yield return new Ace
                        {
                            PrincipalSID = principalSid,
                            PrincipalType = principalType,
                            RightName = EdgeNames.WriteDacl,
                            IsInherited = inherited,
                            InheritanceHash = aceInheritanceHash,
                            IsPermissionForOwnerRightsSid = isPermissionForOwnerRightsSid,
                            IsInheritedPermissionForOwnerRightsSid = isInheritedPermissionForOwnerRightsSid
                        };
                    }

                    if (aceRights.HasFlag(ActiveDirectoryRights.WriteOwner))
                    {
                        yield return new Ace
                        {
                            PrincipalSID = principalSid,
                            PrincipalType = principalType,
                            RightName = EdgeNames.WriteOwner,
                            IsInherited = inherited,
                            InheritanceHash = aceInheritanceHash,
                            IsPermissionForOwnerRightsSid = isPermissionForOwnerRightsSid,
                            IsInheritedPermissionForOwnerRightsSid = isInheritedPermissionForOwnerRightsSid
                        };
                    }
                }

                if (aceRights.HasFlag(ActiveDirectoryRights.Self) &&
                    !aceRights.HasFlag(ActiveDirectoryRights.WriteProperty) &&
                    !aceRights.HasFlag(ActiveDirectoryRights.GenericWrite) && targetType == ObjectType.Group &&
                    (aceType == AceGuids.WriteMember || aceType == AceGuids.MembershipPropertySet || aceType == AceGuids.AllGuid))
                {
                    yield return new Ace
                    {
                        PrincipalSID = principalSid,
                        PrincipalType = principalType,
                        RightName = EdgeNames.AddSelf,
                        IsInherited = inherited,
                        InheritanceHash = aceInheritanceHash,
                        IsPermissionForOwnerRightsSid = isPermissionForOwnerRightsSid,
                        IsInheritedPermissionForOwnerRightsSid = isInheritedPermissionForOwnerRightsSid
                    };
                }

                if (aceRights.HasFlag(ActiveDirectoryRights.ExtendedRight) ||
                    aceRights.HasFlag(ActiveDirectoryRights.GenericAll))
                {
                    if (targetType == ObjectType.Domain)
                    {
                        if (aceType == AceGuids.DSReplicationGetChanges)
                        {
                            yield return new Ace
                            {
                                PrincipalSID = principalSid,
                                PrincipalType = principalType,
                                RightName = EdgeNames.GetChanges,
                                IsInherited = inherited,
                                InheritanceHash = aceInheritanceHash,
                                IsPermissionForOwnerRightsSid = isPermissionForOwnerRightsSid,
                                IsInheritedPermissionForOwnerRightsSid = isInheritedPermissionForOwnerRightsSid
                            };
                        }
                        else if (aceType == AceGuids.DSReplicationGetChangesAll)
                        {
                            yield return new Ace
                            {
                                PrincipalSID = principalSid,
                                PrincipalType = principalType,
                                RightName = EdgeNames.GetChangesAll,
                                IsInherited = inherited,
                                InheritanceHash = aceInheritanceHash,
                                IsPermissionForOwnerRightsSid = isPermissionForOwnerRightsSid,
                                IsInheritedPermissionForOwnerRightsSid = isInheritedPermissionForOwnerRightsSid
                            };
                        }
                        else if (aceType == AceGuids.DSReplicationGetChangesInFilteredSet)
                        {
                            yield return new Ace
                            {
                                PrincipalSID = principalSid,
                                PrincipalType = principalType,
                                RightName = EdgeNames.GetChangesInFilteredSet,
                                IsInherited = inherited,
                                InheritanceHash = aceInheritanceHash,
                                IsPermissionForOwnerRightsSid = isPermissionForOwnerRightsSid,
                                IsInheritedPermissionForOwnerRightsSid = isInheritedPermissionForOwnerRightsSid
                            };
                        }
                        else if (aceType is AceGuids.AllGuid or "")
                        {
                            yield return new Ace
                            {
                                PrincipalSID = principalSid,
                                PrincipalType = principalType,
                                RightName = EdgeNames.AllExtendedRights,
                                IsInherited = inherited,
                                InheritanceHash = aceInheritanceHash,
                                IsPermissionForOwnerRightsSid = isPermissionForOwnerRightsSid,
                                IsInheritedPermissionForOwnerRightsSid = isInheritedPermissionForOwnerRightsSid
                            };

                        }
                    }
                    else if (targetType == ObjectType.User)
                    {
                        if (aceType == AceGuids.UserForceChangePassword)
                        {
                            yield return new Ace
                            {
                                PrincipalSID = principalSid,
                                PrincipalType = principalType,
                                RightName = EdgeNames.ForceChangePassword,
                                IsInherited = inherited,
                                InheritanceHash = aceInheritanceHash,
                                IsPermissionForOwnerRightsSid = isPermissionForOwnerRightsSid,
                                IsInheritedPermissionForOwnerRightsSid = isInheritedPermissionForOwnerRightsSid
                            };
                        }
                        else if (aceType is AceGuids.AllGuid or "")
                        {
                            yield return new Ace
                            {
                                PrincipalSID = principalSid,
                                PrincipalType = principalType,
                                RightName = EdgeNames.AllExtendedRights,
                                IsInherited = inherited,
                                InheritanceHash = aceInheritanceHash,
                                IsPermissionForOwnerRightsSid = isPermissionForOwnerRightsSid,
                                IsInheritedPermissionForOwnerRightsSid = isInheritedPermissionForOwnerRightsSid
                            };
                        }
                    }
                    else if (targetType == ObjectType.Computer)
                    {
                        if (aceType is AceGuids.AllGuid or "")
                        {
                            yield return new Ace
                            {
                                PrincipalSID = principalSid,
                                PrincipalType = principalType,
                                RightName = EdgeNames.AllExtendedRights,
                                IsInherited = inherited,
                                InheritanceHash = aceInheritanceHash,
                                IsPermissionForOwnerRightsSid = isPermissionForOwnerRightsSid,
                                IsInheritedPermissionForOwnerRightsSid = isInheritedPermissionForOwnerRightsSid
                            };
                        }
                    }
                    else if (targetType == ObjectType.CertTemplate)
                    {
                        if (aceType is AceGuids.AllGuid or "")
                        {
                            yield return new Ace
                            {
                                PrincipalSID = principalSid,
                                PrincipalType = principalType,
                                RightName = EdgeNames.AllExtendedRights,
                                IsInherited = inherited,
                                InheritanceHash = aceInheritanceHash,
                                IsPermissionForOwnerRightsSid = isPermissionForOwnerRightsSid,
                                IsInheritedPermissionForOwnerRightsSid = isInheritedPermissionForOwnerRightsSid
                            };
                        }
                        else if (aceType == AceGuids.Enroll)
                        {
                            yield return new Ace
                            {
                                PrincipalSID = principalSid,
                                PrincipalType = principalType,
                                RightName = EdgeNames.Enroll,
                                IsInherited = inherited,
                                InheritanceHash = aceInheritanceHash,
                                IsPermissionForOwnerRightsSid = isPermissionForOwnerRightsSid,
                                IsInheritedPermissionForOwnerRightsSid = isInheritedPermissionForOwnerRightsSid
                            };
                        }
                    }
                }

                if (aceRights.HasFlag(ActiveDirectoryRights.GenericWrite) ||
                    aceRights.HasFlag(ActiveDirectoryRights.WriteProperty) ||
                    aceRights.HasFlag(ActiveDirectoryRights.GenericAll))
                {
                    if (targetType is ObjectType.User
                        or ObjectType.Group
                        or ObjectType.Computer
                        or ObjectType.GPO
                        or ObjectType.OU
                        or ObjectType.Domain
                        or ObjectType.CertTemplate
                        or ObjectType.RootCA
                        or ObjectType.EnterpriseCA
                        or ObjectType.AIACA
                        or ObjectType.NTAuthStore
                        or ObjectType.IssuancePolicy
                        && aceType is AceGuids.AllGuid or "")
                    {
                        yield return new Ace
                        {
                            PrincipalSID = principalSid,
                            PrincipalType = principalType,
                            RightName = EdgeNames.GenericWrite,
                            IsInherited = inherited,
                            InheritanceHash = aceInheritanceHash,
                            IsPermissionForOwnerRightsSid = isPermissionForOwnerRightsSid,
                            IsInheritedPermissionForOwnerRightsSid = isInheritedPermissionForOwnerRightsSid
                        };
                    }

                    if (targetType == ObjectType.User && aceType == AceGuids.WriteSPN)
                    {
                        yield return new Ace
                        {
                            PrincipalSID = principalSid,
                            PrincipalType = principalType,
                            IsInherited = inherited,
                            RightName = EdgeNames.WriteSPN,
                            InheritanceHash = aceInheritanceHash,
                            IsPermissionForOwnerRightsSid = isPermissionForOwnerRightsSid,
                            IsInheritedPermissionForOwnerRightsSid = isInheritedPermissionForOwnerRightsSid,
                        };
                    }
                    else if (targetType == ObjectType.Computer && aceType == AceGuids.WriteAllowedToAct)
                    {
                        yield return new Ace
                        {
                            PrincipalSID = principalSid,
                            PrincipalType = principalType,
                            IsInherited = inherited,
                            RightName = EdgeNames.AddAllowedToAct,
                            InheritanceHash = aceInheritanceHash,
                            IsPermissionForOwnerRightsSid = isPermissionForOwnerRightsSid,
                            IsInheritedPermissionForOwnerRightsSid = isInheritedPermissionForOwnerRightsSid,
                        };
                    }
                    else if (targetType == ObjectType.Computer && aceType == AceGuids.UserAccountRestrictions)
                    {
                        yield return new Ace
                        {
                            PrincipalSID = principalSid,
                            PrincipalType = principalType,
                            IsInherited = inherited,
                            RightName = EdgeNames.WriteAccountRestrictions,
                            InheritanceHash = aceInheritanceHash,
                            IsPermissionForOwnerRightsSid = isPermissionForOwnerRightsSid,
                            IsInheritedPermissionForOwnerRightsSid = isInheritedPermissionForOwnerRightsSid,
                        };
                    }
                    else if (targetType is ObjectType.OU or ObjectType.Domain && aceType == AceGuids.WriteGPLink)
                    {
                        yield return new Ace
                        {
                            PrincipalSID = principalSid,
                            PrincipalType = principalType,
                            IsInherited = inherited,
                            RightName = EdgeNames.WriteGPLink,
                            InheritanceHash = aceInheritanceHash,
                            IsPermissionForOwnerRightsSid = isPermissionForOwnerRightsSid,
                            IsInheritedPermissionForOwnerRightsSid = isInheritedPermissionForOwnerRightsSid,
                        };
                    }
                    else if (targetType == ObjectType.Group && (aceType is AceGuids.WriteMember or AceGuids.MembershipPropertySet))
                    {
                        yield return new Ace
                        {
                            PrincipalSID = principalSid,
                            PrincipalType = principalType,
                            IsInherited = inherited,
                            RightName = EdgeNames.AddMember,
                            InheritanceHash = aceInheritanceHash,
                            IsPermissionForOwnerRightsSid = isPermissionForOwnerRightsSid,
                            IsInheritedPermissionForOwnerRightsSid = isInheritedPermissionForOwnerRightsSid,
                        };
                    }
                    else if (targetType is ObjectType.User or ObjectType.Computer && aceType == AceGuids.AddKeyPrincipal)
                    {
                        yield return new Ace
                        {
                            PrincipalSID = principalSid,
                            PrincipalType = principalType,
                            IsInherited = inherited,
                            RightName = EdgeNames.AddKeyCredentialLink,
                            InheritanceHash = aceInheritanceHash,
                            IsPermissionForOwnerRightsSid = isPermissionForOwnerRightsSid,
                            IsInheritedPermissionForOwnerRightsSid = isInheritedPermissionForOwnerRightsSid,
                        };
                    }
                    else if (targetType is ObjectType.User or ObjectType.Computer && aceType == AceGuids.WriteAltSecurityIdentities)
                    {
                        yield return new Ace
                        {
                            PrincipalSID = principalSid,
                            PrincipalType = principalType,
                            IsInherited = inherited,
                            RightName = EdgeNames.WriteAltSecurityIdentities,
                            InheritanceHash = aceInheritanceHash,
                            IsPermissionForOwnerRightsSid = isPermissionForOwnerRightsSid,
                            IsInheritedPermissionForOwnerRightsSid = isInheritedPermissionForOwnerRightsSid,
                        };
                    }
                    else if (targetType is ObjectType.User or ObjectType.Computer && aceType == AceGuids.WritePublicInformation)
                    {
                        yield return new Ace
                        {
                            PrincipalSID = principalSid,
                            PrincipalType = principalType,
                            IsInherited = inherited,
                            RightName = EdgeNames.WritePublicInformation,
                            InheritanceHash = aceInheritanceHash,
                            IsPermissionForOwnerRightsSid = isPermissionForOwnerRightsSid,
                            IsInheritedPermissionForOwnerRightsSid = isInheritedPermissionForOwnerRightsSid,
                        };
                    }
                    else if (targetType is ObjectType.CertTemplate)
                    {
                        if (aceType == AceGuids.PKIEnrollmentFlag)
                        {
                            yield return new Ace
                            {
                                PrincipalSID = principalSid,
                                PrincipalType = principalType,
                                IsInherited = inherited,
                                RightName = EdgeNames.WritePKIEnrollmentFlag,
                                InheritanceHash = aceInheritanceHash,
                                IsPermissionForOwnerRightsSid = isPermissionForOwnerRightsSid,
                                IsInheritedPermissionForOwnerRightsSid = isInheritedPermissionForOwnerRightsSid,
                            };
                        }
                        else if (aceType == AceGuids.PKINameFlag)
                        {
                            yield return new Ace
                            {
                                PrincipalSID = principalSid,
                                PrincipalType = principalType,
                                IsInherited = inherited,
                                RightName = EdgeNames.WritePKINameFlag,
                                InheritanceHash = aceInheritanceHash,
                                IsPermissionForOwnerRightsSid = isPermissionForOwnerRightsSid,
                                IsInheritedPermissionForOwnerRightsSid = isInheritedPermissionForOwnerRightsSid,
                            };
                        }
                    }
                }

                if (targetType == ObjectType.EnterpriseCA)
                {
                    if (aceType is AceGuids.Enroll)
                    {
                        yield return new Ace
                        {
                            PrincipalSID = principalSid,
                            PrincipalType = principalType,
                            IsInherited = inherited,
                            RightName = EdgeNames.Enroll,
                            InheritanceHash = aceInheritanceHash,
                            IsPermissionForOwnerRightsSid = isPermissionForOwnerRightsSid,
                            IsInheritedPermissionForOwnerRightsSid = isInheritedPermissionForOwnerRightsSid,
                        };
                    }

                    var cARights = (CertificationAuthorityRights)aceRights;

                    if ((cARights & CertificationAuthorityRights.ManageCA) != 0)
                    {
                        yield return new Ace
                        {
                            PrincipalSID = principalSid,
                            PrincipalType = principalType,
                            IsInherited = inherited,
                            RightName = EdgeNames.ManageCA,
                            InheritanceHash = aceInheritanceHash,
                            IsPermissionForOwnerRightsSid = isPermissionForOwnerRightsSid,
                            IsInheritedPermissionForOwnerRightsSid = isInheritedPermissionForOwnerRightsSid,
                        };
                    }
                    if ((cARights & CertificationAuthorityRights.ManageCertificates) != 0)
                    {
                        yield return new Ace
                        {
                            PrincipalSID = principalSid,
                            PrincipalType = principalType,
                            IsInherited = inherited,
                            RightName = EdgeNames.ManageCertificates,
                            InheritanceHash = aceInheritanceHash,
                            IsPermissionForOwnerRightsSid = isPermissionForOwnerRightsSid,
                            IsInheritedPermissionForOwnerRightsSid = isInheritedPermissionForOwnerRightsSid,
                        };

                    }

                    if ((cARights & CertificationAuthorityRights.Enroll) != 0)
                    {
                        yield return new Ace
                        {
                            PrincipalSID = principalSid,
                            PrincipalType = principalType,
                            IsInherited = inherited,
                            RightName = EdgeNames.Enroll,
                            InheritanceHash = aceInheritanceHash,
                            IsPermissionForOwnerRightsSid = isPermissionForOwnerRightsSid,
                            IsInheritedPermissionForOwnerRightsSid = isInheritedPermissionForOwnerRightsSid,
                        };
                    }
                }
            }

        }

        internal static void WriteAcesFromDescriptor(JsonTextWriter writer, byte[]? securityDescriptorBytes, ObjectType targetType, string? domainScope = null)
        {
            writer.WritePropertyName("Aces");
            writer.WriteStartArray();

            if (!OperatingSystem.IsWindows())
            {
                Helpers.NotifyWindowsOnlyFunctionality();
                writer.WriteEndArray();
                return;
            }

            if (securityDescriptorBytes == null || securityDescriptorBytes.Length == 0)
            {
                writer.WriteEndArray();
                return;
            }

            try
            {
                foreach (var acl in ProcessACL(securityDescriptorBytes, targetType, domainScope))
                {
                    WriteAceObject(writer, acl.PrincipalSID, acl.PrincipalType, acl.RightName, acl.IsInherited, acl.InheritanceHash, acl.IsPermissionForOwnerRightsSid, acl.IsInheritedPermissionForOwnerRightsSid);
                }
            }
            catch (Exception ex)
            {
                log.Error("Failed to parse individual structural DACL entry.", ex);
            }
            finally
            {
                writer.WriteEndArray();
            }

        }
    }
}