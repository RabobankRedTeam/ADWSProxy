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

            const int pageSize = 500;
            PageResultRequestControl pageRequestControl = new(pageSize);
            request.Controls.Add(pageRequestControl);

            List<SearchResultEntry> allResults = [];
            while (true)
            {
                var response = (SearchResponse)connection.SendRequest(request);
                if (response.ResultCode == ResultCode.Referral)
                {
                    log.Info($"Received referral to: {string.Join(',', response.Referral.Select(x => x.AbsoluteUri))}");
                }
                if (!string.IsNullOrWhiteSpace(response.ErrorMessage))
                {
                    log.Error($"Received error: {response.ErrorMessage}");
                }
                log.Debug($"Received {response.Entries.Count} entries in current page, cookie: {Convert.ToBase64String(pageRequestControl.Cookie)}");
                allResults.AddRange(response.Entries.Cast<SearchResultEntry>());
                var pageResponseControl = response.Controls.OfType<PageResultResponseControl>().FirstOrDefault();
                if (pageResponseControl == null || pageResponseControl.Cookie.Length == 0)
                {
                    break;
                }
                pageRequestControl.Cookie = pageResponseControl.Cookie;
            }

            List<ResultHolder> results = [];
            try
            {
                var strictUtf8 = new System.Text.UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);
                var jsonOutputHasBase64Content = false;
                var serializableResults = allResults.ConvertAll(e => new
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

                            // Fast Control Character Check
                            bool isPrintable = true;
                            for (int i = 0; i < byteArray.Length; i++)
                            {
                                byte b = byteArray[i];
                                // Catch ASCII control characters (< 32 except tab/LF/CR) and non-ASCII bytes (>= 127)
                                if ((b < 32 && b != 9 && b != 10 && b != 13) || b >= 127)
                                {
                                    isPrintable = false;
                                    break;
                                }
                            }
                            string resultString = string.Empty;
                            if (isPrintable)
                            {
                                try
                                {
                                    resultString = strictUtf8.GetString(byteArray);
                                }
                                catch
                                {
                                    isPrintable = false;
                                }
                            }
                            if (!isPrintable)
                            {
                                jsonOutputHasBase64Content = true;
                                resultString = Convert.ToBase64String(byteArray);
                            }
                            return resultString;
                        }).ToList()
                    )
                });

                results = [.. serializableResults.Select(r => new ResultHolder
                {
                    DistinguishedName = r.DistinguishedName,
                    Attributes = r.Attributes
                })];

                if (jsonOutputHasBase64Content)
                {
                    log.Debug("Some attributes were detected as binary data and have been Base64 encoded in the JSON output");
                }

                log.Info($"Number of results: {results.Count}");
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