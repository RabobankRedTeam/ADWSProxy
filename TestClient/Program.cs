using System.DirectoryServices.Protocols;
using System.Net;
using System.Security.Principal;
using System.Text;

namespace TestClient
{
    internal class Program
    {
        // Helper to convert binary SID to LDAP hex filter string: \01\05\00...
        static string ConvertSidToHexFilter(byte[] sidBytes)
        {
            StringBuilder sb = new StringBuilder();
            foreach (byte b in sidBytes)
            {
                sb.Append(@"\" + b.ToString("X2"));
            }
            return sb.ToString();
        }

        static void RunQuery(string server, int port, NetworkCredential credentials, string? forcedDomain = null)
        {
            using var ldapConnection = new LdapConnection(new LdapDirectoryIdentifier(server, port));
            ldapConnection.SessionOptions.ProtocolVersion = 3;
            ldapConnection.AuthType = AuthType.Basic;

            try
            {
                ldapConnection.Bind(credentials);

                // 1. Determine which domain to query
                string namingContext;
                if (string.IsNullOrEmpty(forcedDomain))
                {
                    // Discovery phase (LDAP 389)
                    namingContext = GetNamingContext(ldapConnection);
                    Console.WriteLine($"[+] Discovered Naming Context: {namingContext}");
                }
                else
                {
                    // Use the domain handed over from the LDAP test (GC 3268)
                    namingContext = forcedDomain;
                    Console.WriteLine($"[*] Using Provided Context for GC: {namingContext}");
                }

                // 2. Initial Search to find a valid SID
                var initialRequest = new SearchRequest(
                    namingContext,
                    "(&(objectClass=user)(sAMAccountName=administrator))",
                    SearchScope.Subtree,
                    "sAMAccountName", "objectSid"
                );

                var response = (SearchResponse)ldapConnection.SendRequest(initialRequest);
                if (response.Entries.Count == 0)
                {
                    Console.WriteLine("[!] No entries found for initial SID discovery.");
                    return;
                }

                // 3. Round-Trip SID Test
                // This ensures the proxy handles binary filters in the search request
                var entry = response.Entries[0];
                byte[] sidBytes = (byte[])entry.Attributes["objectSid"][0];
                string sidString = ConvertSidToReadable(sidBytes); //new SecurityIdentifier(sidBytes, 0).ToString();
                string hexFilter = ConvertSidToHexFilter(sidBytes);

                Console.WriteLine($"[+] Found Administrator: {sidString}");
                Console.WriteLine($"[*] Testing Binary Round-Trip Filter: (objectSid={hexFilter})");

                var sidRequest = new SearchRequest(
                    namingContext,
                    $"(objectSid={hexFilter})",
                    SearchScope.Subtree,
                    "sAMAccountName"
                );

                var sidResponse = (SearchResponse)ldapConnection.SendRequest(sidRequest);

                if (sidResponse.Entries.Count > 0)
                {
                    Console.WriteLine($"[SUCCESS] Proxy correctly parsed and returned: {sidResponse.Entries[0].DistinguishedName}");
                }
                else
                {
                    Console.WriteLine("[FAIL] Binary SID filter returned no results through proxy.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error on port {port}: {ex.Message}");
            }
        }

        public static string ConvertSidToReadable(byte[] bytes)
        {
            // Basic validation: SIDs are at least 8 bytes
            if (bytes == null || bytes.Length < 8) return "Invalid SID";

            // First byte is the revision (usually 1)
            byte revision = bytes[0];

            // Second byte is the count of sub-authorities
            int subAuthorityCount = bytes[1];

            // Next 6 bytes are the Identifier Authority (big-endian)
            long authority = 0;
            for (int i = 2; i <= 7; i++)
            {
                authority = (authority << 8) | bytes[i];
            }

            StringBuilder sb = new StringBuilder();
            sb.Append($"S-{revision}-{authority}");

            // The rest are 4-byte sub-authorities (little-endian)
            for (int i = 0; i < subAuthorityCount; i++)
            {
                uint subAuthority = BitConverter.ToUInt32(bytes, 8 + (i * 4));
                sb.Append($"-{subAuthority}");
            }

            return sb.ToString();
        }

        static string GetNamingContext(LdapConnection connection)
        {
            var request = new SearchRequest(null, "(objectClass=*)", SearchScope.Base, "defaultNamingContext");
            var response = (SearchResponse)connection.SendRequest(request);
            return response.Entries[0].Attributes["defaultNamingContext"][0].ToString()!;
        }

        static async Task Main(string[] args)
        {
            Console.WriteLine("--- ADWS Proxy Test Client ---");
            Console.WriteLine("Waiting for Proxy to initialize...");
            await Task.Delay(3000);
            string targetServer = "host.docker.internal";
            var credentials = new NetworkCredential("user", "pass", "domain");

            // We need to keep track of the domain discovered on 389 to use on 3268
            string? discoveredDomain = null;

            Console.WriteLine("\n[*] Testing LDAP Port (389) with RootDSE Discovery...");
            using (var ldapConn = new LdapConnection(new LdapDirectoryIdentifier(targetServer, 389)))
            {
                ldapConn.SessionOptions.ProtocolVersion = 3;
                ldapConn.AuthType = AuthType.Basic;
                ldapConn.Bind(credentials);
                discoveredDomain = GetNamingContext(ldapConn);
            }

            if (discoveredDomain != null)
            {
                RunQuery(targetServer, 389, credentials, discoveredDomain);

                Console.WriteLine("\n[*] Testing GC Port (3268) using discovered domain...");
                RunQuery(targetServer, 3268, credentials, discoveredDomain);
            }

            Console.WriteLine("\n[#] Test Complete. Press Enter to exit...");
            Console.ReadLine();
        }
    }
}