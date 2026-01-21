using System.DirectoryServices.Protocols;
using System.Net;

namespace TestClient
{
    internal class Program
    {
        static void RunQuery(string server, int port, SearchRequest searchRequest, NetworkCredential credentials)
        {
            using var ldapConnection = new LdapConnection(new LdapDirectoryIdentifier(server, port));
            ldapConnection.SessionOptions.ProtocolVersion = 3;
            ldapConnection.AuthType = AuthType.Basic;

            try
            {
                ldapConnection.Bind(credentials);
                Console.WriteLine("Successfully bound to LDAP Proxy.");

                var response = (SearchResponse)ldapConnection.SendRequest(searchRequest);

                Console.WriteLine($"Found {response.Entries.Count} entries.");
                foreach (SearchResultEntry entry in response.Entries)
                {
                    Console.WriteLine($"DN: {entry.DistinguishedName}");
                }
            }
            catch (LdapException ex)
            {
                Console.WriteLine($"LDAP Error: {ex.Message}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }

        static async Task Main(string[] args)
        {
            ArgumentNullException.ThrowIfNull(args);
            Console.WriteLine("Waiting for Proxy to initialize...");
            await Task.Delay(5000); // 5 second buffer

            string targetServer = "host.docker.internal";
            int ldapPort = 389;
            int gcPort = 3268;

            string domain = "dc=kolen,dc=xyz";
            string query = "(objectClass=user)";
            var searchRequest = new SearchRequest(
                domain,
                query,
                SearchScope.Subtree,
                null
            );
            var credentials = new NetworkCredential("user", "pass", "domain");
            Console.WriteLine("Running LDAP Query against LDAP Proxy...");
            RunQuery(targetServer, ldapPort, searchRequest, credentials);
            Console.WriteLine("Running LDAP Query against GC Proxy...");
            RunQuery(targetServer, gcPort, searchRequest, credentials);
        }
    }
}
