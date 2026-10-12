using System.Security.Cryptography.X509Certificates;

namespace BloodHoundConverter
{
    internal static class CaCertificateParser
    {


        public static ParsedCertificateData ParseCaCertificate(string base64Cert)
        {
            var data = new ParsedCertificateData();

            if (string.IsNullOrWhiteSpace(base64Cert))
            {
                return data;
            }

            try
            {
                // 1. Decode the Base64 payload down to raw DER binary bytes exactly once
                byte[] rawCertBytes = Convert.FromBase64String(base64Cert);

                // 2. Instantiate the single in-memory X509 cryptographic instance
                using X509Certificate2 cert = new(rawCertBytes);

                // 🎯 Extract core fingerprints & identity strings
                data.Thumbprint = cert.Thumbprint.ToUpperInvariant();
                data.SubjectName = !string.IsNullOrEmpty(cert.FriendlyName) ? cert.FriendlyName :
                    !string.IsNullOrEmpty(cert.Subject) ? cert.Subject : cert.Thumbprint;
                data.CertChain = [data.Thumbprint];

                // 🎯 Extract Basic Constraints Extensions out of the same handle
                if (cert.Extensions["2.5.29.19"] is X509BasicConstraintsExtension constraintsExtension)
                {
                    data.HasBasicConstraints = constraintsExtension.CertificateAuthority;
                    data.BasicConstraintPathLength = constraintsExtension.HasPathLengthConstraint
                        ? constraintsExtension.PathLengthConstraint
                        : 0;
                }

                data.NotBefore = cert.NotBefore;
            }
            catch (Exception)
            {
                // Fall back gracefully to default empty values if corrupt data hits the stream
                data.BasicConstraintPathLength = 0;
            }

            return data;
        }
    }
}