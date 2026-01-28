using ARSoft.Tools.Net;
using ARSoft.Tools.Net.Dns;
using System.Net;
using System.Reflection;

namespace ADWSProxy.DNS
{
    internal class Resolver
    {
        private static readonly log4net.ILog logger = log4net.LogManager.GetLogger(MethodBase.GetCurrentMethod()!.DeclaringType!);

        public Resolver(ushort ldapPort, ushort gcPort, IPAddress? localIP = null)
        {
            LdapPort = ldapPort;
            GcPort = gcPort;
            Hostname = Dns.GetHostName();
            LocalIP = localIP ?? GetLocalIPAddress();
            logger.Info($"ARSoft Resolver Initialized. Host: {Hostname}, IP: {LocalIP}");
        }

        private ushort LdapPort { get; }
        private ushort GcPort { get; }
        private string Hostname { get; }
        private IPAddress LocalIP { get; }

        public Task OnQueryReceived(object sender, QueryReceivedEventArgs e)
        {
            var query = e.Query as DnsMessage;
            if (query == null) return Task.CompletedTask;

            // Create a response based on the query
            DnsMessage response = query.CreateResponseInstance();
            response.ReturnCode = ReturnCode.NoError;
            response.IsAuthoritiveAnswer = true;

            foreach (var question in query.Questions)
            {
                string name = question.Name.ToString().ToLower().TrimEnd('.');
                logger.Debug($"Processing {question.RecordType} query for: {name}");

                switch (question.RecordType)
                {
                    case RecordType.A:
                        // Redirect all A-record lookups to the Proxy's IP
                        response.AnswerRecords.Add(new ARecord(question.Name, 3600, LocalIP));
                        break;

                    case RecordType.Srv:
                        ushort targetPort = DetermineSrvPort(name);

                        // Target must be a DomainName object in ARSoft
                        //DomainName targetHost = DomainName.Parse(Hostname);
                        DomainName target = DomainName.Parse(LocalIP.ToString());

                        response.AnswerRecords.Add(new SrvRecord(
                            question.Name,
                            3600,    // TTL
                            0,       // Priority
                            100,     // Weight
                            targetPort,
                            target));

                        logger.Info($"Spoofed SRV: {name} -> {target}:{targetPort}");

                        break;

                    default:
                        // For other types, we return an empty success or let it time out
                        logger.Debug($"Ignoring unsupported record type: {question.RecordType}");
                        break;
                }
            }

            e.Response = response;
            return Task.CompletedTask;
        }

        private ushort DetermineSrvPort(string queryName)
        {
            if (queryName.Contains("_ldap._tcp")) return LdapPort;
            if (queryName.Contains("_gc._tcp")) return GcPort;
            if (queryName.Contains("_identity._tcp") || queryName.Contains("_adws._tcp"))
            {
                return 9389;
            }

            return 1;
        }

        private static IPAddress GetLocalIPAddress()
        {
            return Dns.GetHostEntry(Dns.GetHostName()).AddressList
                .FirstOrDefault(ip => ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                ?? throw new Exception("No IPv4 address found!");
        }
    }
}