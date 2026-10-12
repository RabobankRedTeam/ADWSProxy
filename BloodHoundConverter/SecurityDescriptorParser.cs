using log4net;
using System.Security.AccessControl;

namespace BloodHoundConverter
{
    public static class SecurityDescriptorParser
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(SecurityDescriptorParser));

        public static SecurityDescriptorResult? Parse(byte[]? sdBytes)
        {
            if (!OperatingSystem.IsWindows())
            {
                Helpers.NotifyWindowsOnlyFunctionality();
                return null;
            }

            if (sdBytes == null || sdBytes.Length == 0)
            {
                return null;
            }

            var result = new SecurityDescriptorResult();

            try
            {
                var rsd = new RawSecurityDescriptor(sdBytes, 0);

                // 1. Evaluate Protection/Inheritance Flag
                result.IsAclProtected = (rsd.ControlFlags & ControlFlags.DiscretionaryAclProtected) != 0;

                // 2. Audit DACL for Owner Rights Well-Known SID (S-1-3-4)
                var dacl = rsd.DiscretionaryAcl;
                if (dacl != null)
                {
                    foreach (GenericAce ace in dacl)
                    {
                        // Object ACEs and Common ACEs inherit from GenericAce
                        if (ace is KnownAce knownAce)
                        {
                            if (knownAce.SecurityIdentifier.Value.Equals("S-1-3-4", StringComparison.OrdinalIgnoreCase))
                            {
                                // Check inheritance tracking bits on the descriptor
                                if ((knownAce.AceFlags & AceFlags.Inherited) != 0)
                                {
                                    result.DoesAnyInheritedAceGrantOwnerRights = true;
                                }
                                else
                                {
                                    result.DoesAnyAceGrantOwnerRights = true;
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                log.Debug("Failed to parse binary security descriptor bytes natively.", ex);
            }

            return result;
        }
    }
}