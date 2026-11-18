namespace BloodHoundConverter
{
    // Canonical userAccountControl bit definitions. This is the single source of truth for UAC
    // flags; UacProperties and UacParser both reference it so the values cannot drift apart.
    [Flags]
    internal enum UserAccountControlFlags : int
    {
        None = 0,
        SCRIPT = 0x00000001,
        ACCOUNTDISABLE = 0x00000002,
        HOMEDIR_REQUIRED = 0x00000008,
        LOCKOUT = 0x00000010,
        PASSWD_NOTREQD = 0x00000020,
        PASSWD_CANT_CHANGE = 0x00000040,
        ENCRYPTED_TEXT_PWD_ALLOWED = 0x00000080,
        SERVER_TRUST_ACCOUNT = 0x00002000,
        DONT_EXPIRE_PASSWORD = 0x00010000,
        SMARTCARD_REQUIRED = 0x00040000,
        TRUSTED_FOR_DELEGATION = 0x00080000,
        NOT_DELEGATED = 0x00100000,
        USE_DES_KEY_ONLY = 0x00200000,
        DONT_REQ_PREAUTH = 0x00400000,
        PASSWORD_EXPIRED = 0x00800000,
        TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION = 0x01000000,
        PARTIAL_SECRETS_ACCOUNT = 0x04000000
    }
}
