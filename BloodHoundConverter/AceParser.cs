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

        public static readonly HashSet<string> UnknownRights = new(StringComparer.OrdinalIgnoreCase);
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

        public static void WriteAcesFromDescriptor(JsonTextWriter writer, NodeProcessingContext context)
        {
            WriteAcesFromDescriptor(writer, context.SecurityDescriptorBytes);
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
                return BitConverter.ToString(bytes).Replace("-", string.Empty).ToUpper();
            }
            catch
            {
                return "";
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

        internal static IEnumerable<Ace> ProcessACL(byte[]? securityDescriptorBytes, bool checkForOwnerRights = true)
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
            var ownerSid = activeDirectorySecurity.GetOwner(typeof(SecurityIdentifier))?.Value;

            if (ownerSid != null)
            {
                yield return new Ace
                {
                    PrincipalSID = ownerSid,
                    PrincipalType = BloodHoundConverter.IdToTypeMap.TryGetValue(ownerSid, out var type) ? type : ObjectType.Base,
                    RightName = EdgeNames.Owns,
                    IsInherited = false,
                    InheritanceHash = string.Empty,
                    IsPermissionForOwnerRightsSid = ownerSid.Equals(OwnerRightsSid, StringComparison.OrdinalIgnoreCase),
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

                var principalSid = ace.IdentityReference?.Value;
                if (string.IsNullOrWhiteSpace(principalSid))
                {
                    continue;
                }

                ObjectType principalType = BloodHoundConverter.IdToTypeMap.TryGetValue(principalSid, out var type) ? type : ObjectType.Base;

                bool isPermissionForOwnerRightsSid = false;
                bool isInheritedPermissionForOwnerRightsSid = false;

                if (checkForOwnerRights && principalSid.EndsWith("S-1-3-4"))
                {
                    isPermissionForOwnerRightsSid = true;
                }

                var aceRights = ace.ActiveDirectoryRights;
                var aceType = ace.ObjectType.ToString().ToLower();
                var inherited = ace.IsInherited;

                var aceInheritanceHash = "";
                if (inherited)
                {
                    aceInheritanceHash = CalculateInheritanceHash(principalSid, aceRights, aceType, ace.InheritedObjectType.ToString());

                    if (checkForOwnerRights && principalSid.EndsWith("S-1-3-4"))
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
                    !aceRights.HasFlag(ActiveDirectoryRights.GenericWrite) && aceType == "group" &&
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
                    if (type == ObjectType.Domain)
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
                    else if (type == ObjectType.User)
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
                    else if (type == ObjectType.Computer)
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
                    else if (type == ObjectType.CertTemplate)
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
                    if (type is ObjectType.User
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

                    if (type == ObjectType.User && aceType == AceGuids.WriteSPN)
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
                    else if (type == ObjectType.Computer && aceType == AceGuids.WriteAllowedToAct)
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
                    else if (type == ObjectType.Computer && aceType == AceGuids.UserAccountRestrictions)
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
                    else if (type is ObjectType.OU or ObjectType.Domain && aceType == AceGuids.WriteGPLink)
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
                    else if (type == ObjectType.Group && (aceType is AceGuids.WriteMember or AceGuids.MembershipPropertySet))
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
                    else if (type is ObjectType.User or ObjectType.Computer && aceType == AceGuids.AddKeyPrincipal)
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
                    else if (type is ObjectType.User or ObjectType.Computer && aceType == AceGuids.WriteAltSecurityIdentities)
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
                    else if (type is ObjectType.User or ObjectType.Computer && aceType == AceGuids.WritePublicInformation)
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
                    else if (type is ObjectType.CertTemplate)
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

                if (type == ObjectType.EnterpriseCA)
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

        internal static void WriteAcesFromDescriptor(JsonTextWriter writer, byte[]? securityDescriptorBytes)
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
                foreach (var acl in ProcessACL(securityDescriptorBytes))
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