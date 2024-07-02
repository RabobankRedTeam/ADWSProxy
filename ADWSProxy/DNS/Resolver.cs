using DNS.Client.RequestResolver;
using DNS.Protocol;
using DNS.Protocol.ResourceRecords;
using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace ADWSProxy.DNS
{
    internal class Resolver : IRequestResolver
    {
        private static readonly log4net.ILog logger = log4net.LogManager.GetLogger(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType);

        public Resolver(ushort ldapPort, ushort gcport)
        {
            logger.Info($"Constructing new {GetType().FullName}");

            LdapPort = ldapPort;
            Gcport = gcport;
            Hostname = Dns.GetHostName();
            IPAddress = GetLocalIPAddress();

            logger.Debug($"DNS Hostname: {Hostname}");
            logger.Debug($"Local IP address: {IPAddress}");
        }

        private ushort Gcport { get; }
        private string Hostname { get; set; }
        private IPAddress IPAddress { get; set; }
        private ushort LdapPort { get; }

        public Task<IResponse> Resolve(IRequest request, CancellationToken cancellationToken = default)
        {
            logger.Info("Resolving new DNS request");

            IResponse response = Response.FromRequest(request);

            foreach (Question question in response.Questions)
            {
                logger.Debug($"DNS request = {question.Name}");

                switch (question.Type)
                {
                    case RecordType.A:
                        IResourceRecord recordA = new IPAddressResourceRecord(question.Name, IPAddress);
                        response.AnswerRecords.Add(recordA);
                        break;

                    //case RecordType.AAAA:
                    //    IResourceRecord recordAAAA = new IPAddressResourceRecord(question.Name, IPAddress.Parse("::1"));
                    //    response.AnswerRecords.Add(recordAAAA);
                    //    break;

                    case RecordType.SRV:
                        ushort port = 1;
                        if (question.Name.ToString().StartsWith("_ldap._tcp.pdc._msdcs.", StringComparison.OrdinalIgnoreCase))
                        {
                            port = LdapPort;
                        }
                        else if (question.Name.ToString().StartsWith("_ldap._tcp.gc._msdcs.", StringComparison.OrdinalIgnoreCase))
                        {
                            port = Gcport;
                        }
                        IResourceRecord recordSRV = new ServiceResourceRecord(question.Name, 0, 100, port, new Domain(Hostname));
                        response.AnswerRecords.Add(recordSRV);
                        break;

                    default:
                        throw new NotImplementedException($"RequestType: {question.Type} has not been implemented");
                }
            }

            logger.Debug($"DNS response = {response}");
            return Task.FromResult(response);
        }

        private static IPAddress GetLocalIPAddress()
        {
            var host = Dns.GetHostEntry(Dns.GetHostName());
            foreach (var ip in host.AddressList)
            {
                if (ip.AddressFamily == AddressFamily.InterNetwork)
                {
                    return ip;
                }
            }

            const string errorString = "No network adapters with an IPv4 address in the system!";
            logger.Error(errorString);
            throw new Exception(errorString);
        }
    }
}