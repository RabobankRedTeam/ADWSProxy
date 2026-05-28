using log4net;
using System.Data;
using System.DirectoryServices.Protocols;
using System.Net;

namespace TestClient
{
    internal class LDAPHelpers(string server, int port = 389, NetworkCredential? credential = null, bool secure = false)
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(LDAPHelpers));

        private readonly LdapDirectoryIdentifier ldapDirectoryIdentifier = new(server, port);

        internal List<ResultHolder> ExecuteLdap(string baseDn, string filter, string scope, List<string> attributes)
        {
            // Null credentials + AuthType.Negotiate uses current implicit Windows Session Token
            // Linux clients should use AuthType.Basic with explicit credentials, as Negotiate is not widely supported outside of Windows environments
            AuthType authType;
            var activeCredential = credential;
            if (OperatingSystem.IsWindows())
            {
                authType = AuthType.Negotiate;
            }
            else
            {
                authType = AuthType.Basic;
            }

            if (credential != null)
            {
                activeCredential = new NetworkCredential(
                    @$"{credential.UserName}@{credential.Domain}",
                    credential.Password
                );
            }

            using LdapConnection connection = new(ldapDirectoryIdentifier, activeCredential, authType);
            connection.SessionOptions.SecureSocketLayer = secure;
            connection.SessionOptions.ProtocolVersion = 3;
            connection.SessionOptions.ReferralChasing = ReferralChasingOptions.None;

            if (secure)
            {
                if (OperatingSystem.IsWindows())
                {
                    connection.SessionOptions.VerifyServerCertificate = (conn, cert) =>
                    {
                        log.Debug($"Server Cert Subject: '{cert?.Subject}' Issuer: {cert?.Issuer}");
                        return true;
                    };
                    connection.SessionOptions.QueryClientCertificate = (conn, trustedCAs) => null;
                }
            }
            else
            {
                if (OperatingSystem.IsWindows())
                {
                    connection.SessionOptions.Signing = true;
                    connection.SessionOptions.Sealing = true;
                }
            }

            connection.Bind();

            SearchScope ldapScope;
            switch (scope.ToLowerInvariant())
            {
                case "subtree":
                    ldapScope = SearchScope.Subtree;
                    break;
                case "one":
                    ldapScope = SearchScope.OneLevel;
                    break;
                case "base":
                    ldapScope = SearchScope.Base;
                    break;
                default:
                    log.Warn($"Unknown scope '{scope}' specified. Using default scope/subtree");
                    ldapScope = SearchScope.Subtree;
                    break;
            }

            SearchRequest request = new(baseDn, filter, ldapScope, attributes?.ToArray());
            var sdControl = new SecurityDescriptorFlagControl(SecurityMasks.Dacl | SecurityMasks.Owner | SecurityMasks.Group);
            request.Controls.Add(sdControl);
            var response = (SearchResponse)connection.SendRequest(request);

            List<ResultHolder> results = [];
            try
            {
                var jsonOutputHasBase64Content = false;
                var serializableResults = response.Entries.Cast<SearchResultEntry>().Select(e => new
                {
                    e.DistinguishedName,
                    Attributes = e.Attributes.AttributeNames.Cast<string>().ToDictionary(
                        attrName => attrName,
                        attrName => e.Attributes[attrName].GetValues(typeof(byte[])).Cast<byte[]>().Select(byteArray =>
                        {
                            if (byteArray == null || byteArray.Length == 0)
                            {
                                return string.Empty;
                            }

                            // Look for non-printable control characters to determine if it is raw binary data
                            bool isPrintableText = true;
                            for (int i = 0; i < byteArray.Length; i++)
                            {
                                byte b = byteArray[i];
                                // Flags true binary structures if we see bytes below space (32) 
                                // that aren't common formatting characters like horizontal tabs or line feeds
                                if (b < 32 && b != 9 && b != 10 && b != 13)
                                {
                                    isPrintableText = false;
                                    jsonOutputHasBase64Content = true;
                                    break;
                                }
                            }

                            if (isPrintableText)
                            {
                                string decodedString = System.Text.Encoding.UTF8.GetString(byteArray);
                                return decodedString;
                            }

                            // If it is an ntSecurityDescriptor or objectGUID block, translate it to Base64
                            return Convert.ToBase64String(byteArray);
                        }).ToList()
                    )
                }).ToList();

                results = [.. serializableResults.Select(r => new ResultHolder
                {
                    DistinguishedName = r.DistinguishedName,
                    Attributes = r.Attributes
                })];

                if (jsonOutputHasBase64Content)
                {
                    log.Debug("Some attributes were detected as binary data and have been Base64 encoded in the JSON output");
                }

                LoggerConfig.LogDebug(log, "Result", serializableResults);
            }
            catch (Exception ex)
            {
                log.Error("Error occurred while serializing LDAP results", ex);
            }

            return results;
        }
    }
}