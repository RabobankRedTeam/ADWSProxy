using ADWSProxy.ADWS.Request;
using ADWSProxy.LDAP;
using Flexinets.Ldap.Core;
using log4net;
using System.Net;
using System.Reflection;
using System.Security.Authentication.ExtendedProtection;
using System.ServiceModel;
using System.ServiceModel.Channels;

namespace ADWSProxy.ADWS
{
    internal class Connection
    {
        private static readonly ILog logger = LogManager.GetLogger(type: MethodBase.GetCurrentMethod()!.DeclaringType!);

        private CustomBinding? _binding = null;

        private ResourceClient? _resource = null;

        private SearchClient? _search = null;

        public Connection(string server, int port, string instance, AdwsEndpoint mode, NetworkCredential? credential = null)
        {
            logger.Info($"Constructing new {GetType().FullName}");

            ServicePointManager.ServerCertificateValidationCallback = (s, c, ch, e) => true;

            Server = server;
            Instance = instance;
            Port = port;
            Credential = credential;
            Mode = mode;
        }

        public AdwsEndpoint Mode { get; }

        private string Auth
        {
            get
            {
                return Mode == AdwsEndpoint.Windows ? "Windows" : "UserName";
            }
        }

        private CustomBinding Binding
        {
            get
            {
                if (_binding == null)
                {
                    logger.Debug($"Constructing new {typeof(NetTcpBinding).FullName}.");

                    var binding = new NetTcpBinding
                    {
                        MaxReceivedMessageSize = Helpers.BufferSize,
                        CloseTimeout = new TimeSpan(0, 10, 0),
                        OpenTimeout = new TimeSpan(0, 10, 0),
                        ReceiveTimeout = new TimeSpan(0, 10, 0),
                        SendTimeout = new TimeSpan(0, 10, 0)
                    };

                    binding.ReaderQuotas.MaxDepth = 10;
                    binding.ReaderQuotas.MaxStringContentLength = 32768;
                    binding.ReaderQuotas.MaxArrayLength = 16384;

                    if (Mode == AdwsEndpoint.Windows)
                    {
                        binding.Security.Mode = SecurityMode.Transport;
                        binding.Security.Transport.ClientCredentialType = TcpClientCredentialType.Windows;
                        binding.Security.Transport.ProtectionLevel = System.Net.Security.ProtectionLevel.EncryptAndSign;
                        binding.Security.Message.ClientCredentialType = MessageCredentialType.None;
                    }
                    else
                    {
                        binding.Security.Mode = SecurityMode.TransportWithMessageCredential;
                        binding.Security.Transport.ClientCredentialType = TcpClientCredentialType.None;
                        binding.Security.Message.ClientCredentialType = MessageCredentialType.UserName;
                    }

                    logger.Debug($"Using binding.Security.Mode: {binding.Security.Mode}");
                    logger.Debug($"Using binding.Security.Transport.ClientCredentialType: {binding.Security.Transport.ClientCredentialType}");
                    logger.Debug($"binding.Security.Transport.ProtectionLevel: {binding.Security.Transport.ProtectionLevel}");
                    logger.Debug($"binding.Security.Message.ClientCredentialType: {binding.Security.Message.ClientCredentialType}");

                    _binding = new CustomBinding(binding);
                    var transportElement = _binding.Elements.Find<TcpTransportBindingElement>();
                    if (transportElement != null)
                    {
                        // Setting this value to Always is only supported on Windows at this time.
                        if (OperatingSystem.IsWindows())
                        {
                            transportElement.ExtendedProtectionPolicy = new ExtendedProtectionPolicy(PolicyEnforcement.Always);
                        }
                        else
                        {
                            transportElement.ExtendedProtectionPolicy = new ExtendedProtectionPolicy(PolicyEnforcement.WhenSupported, ProtectionScenario.TransportSelected, new ServiceNameCollection(new[]
                            {
                                $"identity/{Server}",
                                $"identity/{Server.Split('.')[0]}",
                                $"host/{Server}",
                                $"ldap/{Server}",
                                $"ldap/{Server}/{Server[(Server.IndexOf('.') + 1)..]}",
                                $"identity/{Server}:9389"
                            }));
                        }
                        logger.Debug($"transportElement.ExtendedProtectionPolicy: {transportElement.ExtendedProtectionPolicy}");
                    }
                    var securityElement = _binding.Elements.Find<SecurityBindingElement>();
                    if (securityElement != null)
                    {
                        securityElement.IncludeTimestamp = true;
                        logger.Debug($"securityElement.IncludeTimestamp: {securityElement.IncludeTimestamp}");

                    }
                }

                return _binding;
            }
        }

        private NetworkCredential? Credential { get; }
        private string Instance { get; }
        private int Port { get; }

        private EndpointIdentity? Identity
        {
            get
            {
                return Mode switch
                {
                    AdwsEndpoint.Windows => new SpnEndpointIdentity($"host/{Server.ToLower()}"),
                    AdwsEndpoint.Username => new DnsEndpointIdentity(Server),
                    _ => null
                };
            }
        }

        private ResourceClient ResourceClient
        {
            get
            {
                if (_resource == null || _resource.State == CommunicationState.Closed)
                {
                    logger.Debug($"Constructing new {typeof(ResourceClient).FullName}");

                    var endpoint = new EndpointAddress(CreateUri("Resource"), Identity, []);

                    _resource = new ResourceClient(Binding, endpoint);
                    if (Credential != null)
                    {
                        switch (Mode)
                        {
                            case AdwsEndpoint.Windows:
                                _resource.ClientCredentials.Windows.ClientCredential = Credential;
                                _resource.ClientCredentials.Windows.AllowedImpersonationLevel = System.Security.Principal.TokenImpersonationLevel.Impersonation;
                                break;
                            case AdwsEndpoint.Username:
                                _resource.ClientCredentials.UserName.UserName = $"{Credential.UserName}@{Credential.Domain}";
                                _resource.ClientCredentials.UserName.Password = Credential.Password;
                                _resource.ClientCredentials.ServiceCertificate.Authentication.CertificateValidationMode = System.ServiceModel.Security.X509CertificateValidationMode.None;
                                break;
                        }
                    }
                }

                return _resource;
            }
        }

        private SearchClient SearchClient
        {
            get
            {
                if (_search == null || _search.State == CommunicationState.Closed)
                {
                    logger.Debug($"Constructing new {typeof(SearchClient).FullName}");

                    var endpoint = new EndpointAddress(CreateUri("Enumeration"), Identity, []);

                    _search = new SearchClient(Binding, endpoint);

                    if (Credential != null)
                    {
                        switch (Mode)
                        {
                            case AdwsEndpoint.Windows:
                                _search.ClientCredentials.Windows.ClientCredential = Credential;
                                _search.ClientCredentials.Windows.AllowedImpersonationLevel = System.Security.Principal.TokenImpersonationLevel.Impersonation;
                                break;
                            case AdwsEndpoint.Username:
                                _search.ClientCredentials.UserName.UserName = $"{Credential.UserName}@{Credential.Domain}";
                                _search.ClientCredentials.UserName.Password = Credential.Password;
                                _search.ClientCredentials.ServiceCertificate.Authentication.CertificateValidationMode = System.ServiceModel.Security.X509CertificateValidationMode.None;
                                break;
                        }
                    }
                }
                return _search;
            }
        }

        private Uri CreateUri(string endpoint)
        {
            return new UriBuilder()
            {
                Scheme = "net.tcp",
                Host = Server,
                Port = Port,

                Path = $"ActiveDirectoryWebServices/{Auth}/{endpoint}"
            }.Uri;
        }

        private string Server { get; }

        public List<DataHolder> GetRootDSE()
        {
            logger.Debug("Getting RootDSE");
            var result = new List<DataHolder>();

            var messageBuffer = new GetRequest(Instance).CreateBufferedCopy();
            messageBuffer.WriteMessageToDebug(logger);

            var rootDSEResponse = ResourceClient.GetAsync(messageBuffer.CreateMessage()).Result;
            var rootDSEResponseBuffer = rootDSEResponse.CreateBufferedCopy();
            rootDSEResponseBuffer.WriteMessageToDebug(logger);

            if (rootDSEResponse.IsFault)
            {
                throw ADWSException.FromMessageBuffer(rootDSEResponseBuffer);
            }

            var parsedResponse = new GetResponse(rootDSEResponseBuffer.CreateMessage());

            foreach (var item in parsedResponse.Items)
            {
                // These fields return the guid 11111111-1111-1111-1111-111111111111 which is not present in a direct LDAP request to get the RootDSE
                if (item.Key.Equals("container-hierarchy-parent", StringComparison.OrdinalIgnoreCase) || item.Key.Equals("objectReferenceProperty", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                // This applicaiton does not support SASL
                if (item.Key.Equals("supportedSASLMechanisms", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (item.Key.Equals("supportedControl", StringComparison.OrdinalIgnoreCase))
                {
                    foreach (var i in item.Value)
                    {
                        if (i == "1.2.840.113556.1.4.319") // Paging which is not needed and supported by our LDAP endpoint at this time
                        {
                            continue;
                        }
                        if (i == "1.3.6.1.4.1.4203.1.5.1") // (+) Optional attribute query is not supported by our LDAP endpoint at this time
                        {
                            continue;
                        }
                        if (i == "1.3.6.1.4.1.4203.1.5.2") // (@) Retrieve all attributes of a class is not supported by our LDAP endpoint at this time
                        {
                            continue;
                        }
                        result.Add(new DataHolder(item.Key, i, UniversalDataType.OctetString));
                    }
                    continue;
                }

                foreach (var i in item.Value)
                {
                    result.Add(new DataHolder(item.Key, i, UniversalDataType.OctetString));
                }
            }

            return result;
        }

        internal void Enumerate(string dn, string filter, List<string> fields, string scope, Action<(string, List<DataHolder>)> callback)
        {
            if (!fields.Any(field => field.Equals("distinguishedname", StringComparison.OrdinalIgnoreCase)))
            {
                fields.Add("distinguishedname");
            }

            string? enumerateContext = null;
            DateTime? enumerateContextExpires = null;
            int pageNumber = 0;
            try
            {
                var enumerateRequest = new EnumerateRequest(Instance, filter, dn, scope, fields).CreateBufferedCopy();
                enumerateRequest.WriteMessageToDebug(logger);

                var enumerateResponse = SearchClient.EnumerateAsync(enumerateRequest.CreateMessage()).Result;
                var enumerateResponseBuffer = enumerateResponse.CreateBufferedCopy();
                enumerateResponseBuffer.WriteMessageToDebug(logger);

                if (enumerateResponse.IsFault)
                {
                    throw ADWSException.FromMessageBuffer(enumerateResponseBuffer);
                }

                var parsedResponse = new EnumerateResponse(enumerateResponseBuffer.CreateMessage());
                enumerateContext = parsedResponse.EnumerateContext;
                enumerateContextExpires = parsedResponse.Expiration;

                var EndOfSequence = false;

                while (!EndOfSequence)
                {
                    if (enumerateContextExpires.HasValue && enumerateContextExpires.Value.AddMinutes(-5) < DateTime.UtcNow)
                    {
                        logger.Info($"Renewing expiration for {enumerateContext}");

                        var renewRequestBuffer = new RenewRequest(Instance, enumerateContext!, DateTime.Now.AddMinutes(25)).CreateBufferedCopy();
                        renewRequestBuffer.WriteMessageToDebug(logger);

                        var renewResponse = SearchClient.RenewAsync(renewRequestBuffer.CreateMessage()).Result;
                        var renewResponseBuffer = renewResponse.CreateBufferedCopy();
                        renewResponseBuffer.WriteMessageToDebug(logger);

                        if (renewResponse.IsFault)
                        {
                            throw ADWSException.FromMessageBuffer(renewResponseBuffer);
                        }
                        var parsedRenewResponse = new RenewResponse(renewResponseBuffer.CreateMessage());

                        string newEnumerateContext = parsedRenewResponse.EnumerateContext!;
                        DateTime newEnumerateContextExpires = parsedRenewResponse.Expiration;

                        logger.Debug($"Completed Search.Renew, old context: {enumerateContext} would expire at {enumerateContextExpires?.ToShortDateString()} and new context: {newEnumerateContext} which expires at {newEnumerateContextExpires:d}");

                        enumerateContext = newEnumerateContext;
                        enumerateContextExpires = newEnumerateContextExpires;
                    }
                    var pullRequest = new PullRequest(Instance, parsedResponse.EnumerateContext!).CreateBufferedCopy();
                    pullRequest.WriteMessageToDebug(logger);

                    var pullResponse = SearchClient.PullAsync(pullRequest.CreateMessage()).Result;
                    var pullResponseBuffer = pullResponse.CreateBufferedCopy();
                    pullResponseBuffer.WriteMessageToDebug(logger);

                    if (pullResponse.IsFault)
                    {
                        throw ADWSException.FromMessageBuffer(pullResponseBuffer);
                    }

                    var parsedPullResponse = new PullResponse(pullResponseBuffer.CreateMessage());
                    foreach (var i in parsedPullResponse.Items)
                    {
                        callback((i.Key, i.Value));
                    }
                    logger.Info($"Completed page {pageNumber++} for enumerateContext {enumerateContext}");
                    EndOfSequence = parsedPullResponse.EndOfSequence;
                }
            }
            catch (Exception ex)
            {
                logger.Error(ex.Message, ex);
            }
            finally
            {
                if (!string.IsNullOrEmpty(enumerateContext))
                {
                    logger.Info($"Releasing enumerateContext: {enumerateContext}");
                    var releaseRequest = new ReleaseRequest(Instance, enumerateContext).CreateBufferedCopy();
                    releaseRequest.WriteMessageToDebug(logger);
                    var releaseResponse = SearchClient.ReleaseAsync(releaseRequest.CreateMessage()).Result;
                    var releaseResponseBuffer = releaseResponse.CreateBufferedCopy();
                    releaseResponseBuffer.WriteMessageToDebug(logger);
                    if (releaseResponse.IsFault)
                    {
                        var ex = ADWSException.FromMessageBuffer(releaseResponseBuffer);
                        logger.Error($"Error releasing enumerateContext: {enumerateContext}", ex);
                    }
                }
            }
        }
    }
}