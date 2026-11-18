namespace BloodHoundConverter
{
    public class UacProperties(int mask)
    {
        public bool LogonScriptEnabled { get; set; } = (mask & (int)UserAccountControlFlags.SCRIPT) != 0;
        public bool AccountDisabled { get; set; } = (mask & (int)UserAccountControlFlags.ACCOUNTDISABLE) != 0;
        public bool HomeDirectoryRequired { get; set; } = (mask & (int)UserAccountControlFlags.HOMEDIR_REQUIRED) != 0;
        public bool Lockout { get; set; } = (mask & (int)UserAccountControlFlags.LOCKOUT) != 0;
        public bool EncryptedTextPwdAllowed { get; set; } = (mask & (int)UserAccountControlFlags.ENCRYPTED_TEXT_PWD_ALLOWED) != 0;
        public bool IsDc { get; set; } = (mask & (int)UserAccountControlFlags.SERVER_TRUST_ACCOUNT) != 0;
        public bool PasswordDoesNotExpire { get; set; } = (mask & (int)UserAccountControlFlags.DONT_EXPIRE_PASSWORD) != 0;
        public bool SmartcardRequired { get; set; } = (mask & (int)UserAccountControlFlags.SMARTCARD_REQUIRED) != 0;
        public bool TrustedForDelegation { get; set; } = (mask & (int)UserAccountControlFlags.TRUSTED_FOR_DELEGATION) != 0;
        public bool PasswordNotRequired { get; set; } = (mask & (int)UserAccountControlFlags.PASSWD_NOTREQD) != 0;
        public bool UseDesKeyOnly { get; set; } = (mask & (int)UserAccountControlFlags.USE_DES_KEY_ONLY) != 0;
        public bool PreauthNotRequired { get; set; } = (mask & (int)UserAccountControlFlags.DONT_REQ_PREAUTH) != 0;
        public bool PasswordExpired { get; set; } = (mask & (int)UserAccountControlFlags.PASSWORD_EXPIRED) != 0;
        public bool TrustedToAuthForDelegation { get; set; } = (mask & (int)UserAccountControlFlags.TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION) != 0;
        public int RawValue { get; set; } = mask;
    }
}
