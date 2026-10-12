namespace BloodHoundConverter
{
    public class UacProperties(int mask)
    {
        public bool LogonScriptEnabled { get; set; } = (mask & 0x00000001) != 0;
        public bool AccountDisabled { get; set; } = (mask & 0x00000002) != 0;
        public bool HomeDirectoryRequired { get; set; } = (mask & 0x00000008) != 0;
        public bool Lockout { get; set; } = (mask & 0x00000010) != 0; // Shared bit offset
        public bool EncryptedTextPwdAllowed { get; set; } = (mask & 0x00000010) != 0;
        public bool IsDc { get; set; } = (mask & 0x00002000) != 0; // SERVER_TRUST_ACCOUNT
        public bool PasswordDoesNotExpire { get; set; } = (mask & 0x00010000) != 0;
        public bool SmartcardRequired { get; set; } = (mask & 0x00040000) != 0;
        public bool TrustedForDelegation { get; set; } = (mask & 0x00080000) != 0;
        public bool PasswordNotRequired { get; set; } = (mask & 0x00200000) != 0;
        public bool UseDesKeyOnly { get; set; } = (mask & 0x00400000) != 0;
        public bool PreauthNotRequired { get; set; } = (mask & 0x00400000) != 0; // Shared bit offset
        public bool PasswordExpired { get; set; } = (mask & 0x00800000) != 0;
        public bool TrustedToAuthForDelegation { get; set; } = (mask & 0x01000000) != 0;
        public int RawValue { get; set; } = mask;
    }

}