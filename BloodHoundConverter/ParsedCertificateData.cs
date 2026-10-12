namespace BloodHoundConverter
{
    internal class ParsedCertificateData
    {
        public string Thumbprint { get; set; } = string.Empty;
        public string SubjectName { get; set; } = string.Empty;
        public List<string> CertChain { get; set; } = [];
        public bool HasBasicConstraints { get; set; }
        public int BasicConstraintPathLength { get; set; } = 0;
        public DateTime NotBefore { get; set; }
    }
}