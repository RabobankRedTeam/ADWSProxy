namespace BloodHoundConverter
{
    [Flags]
    internal enum CertificationAuthorityRights
    {
        None = 0,
        ManageCA = 1, // Administrator
        ManageCertificates = 2, // Officer
        Auditor = 4,
        Operator = 8,
        Read = 256,
        Enroll = 512
    }
}