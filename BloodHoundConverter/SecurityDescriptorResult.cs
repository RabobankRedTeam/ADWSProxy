namespace BloodHoundConverter
{
    public class SecurityDescriptorResult
    {
        public bool IsAclProtected { get; set; }
        public bool DoesAnyAceGrantOwnerRights { get; set; }
        public bool DoesAnyInheritedAceGrantOwnerRights { get; set; }
    }
}