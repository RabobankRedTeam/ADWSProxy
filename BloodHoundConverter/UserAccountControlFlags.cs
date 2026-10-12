namespace BloodHoundConverter
{
    internal partial class BloodHoundConverter
    {
        [Flags]
        public enum UserAccountControlFlags : int
        {
            None = 0,
            ACCOUNTDISABLE = 0x0002,          // 2
            PASSWD_NOTREQD = 0x0020,          // 32
            TRUSTED_FOR_DELEGATION = 0x80000,  // 524,288
            DONT_REQ_PREAUTH = 0x400000,       // 4,194,304
            TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION = 0x1000000 // 16,777,216
        }
    }
}