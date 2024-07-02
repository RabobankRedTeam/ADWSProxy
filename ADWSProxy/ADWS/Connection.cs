using ADWSProxy.ADWS.Request;
using ADWSProxy.LDAP;
using Flexinets.Ldap.Core;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Reflection;
using System.ServiceModel;

namespace ADWSProxy.ADWS
{
    internal class Connection
    {
        private static readonly log4net.ILog logger = log4net.LogManager.GetLogger(MethodBase.GetCurrentMethod().DeclaringType);

        private NetTcpBinding _binding = null;

        private ResourceClient _resource = null;

        private SearchClient _search = null;

        public Connection(string server, int port, string instance, bool useWindowsAuth, NetworkCredential credential = null)
        {
            logger.Info($"Constructing new {GetType().FullName}");

            Server = server;
            Instance = instance;
            Port = port;
            Credential = credential;
            UseWindowsAuth = useWindowsAuth;
        }

        public bool UseWindowsAuth { get; }

        private string Auth
        {
            get
            {
                return UseWindowsAuth ? "Windows" : "UserName";
            }
        }

        private NetTcpBinding Binding
        {
            get
            {
                if (_binding == null)
                {
                    logger.Debug($"Constructing new {typeof(NetTcpBinding).FullName}.");

                    _binding = new NetTcpBinding
                    {
                        MaxReceivedMessageSize = Helpers.BufferSize,
                        CloseTimeout = new TimeSpan(0, 10, 0),
                        OpenTimeout = new TimeSpan(0, 10, 0),
                        ReceiveTimeout = new TimeSpan(0, 10, 0),
                        SendTimeout = new TimeSpan(0, 10, 0)
                    };

                    _binding.ReaderQuotas.MaxDepth = 10;
                    _binding.ReaderQuotas.MaxStringContentLength = 32768;
                    _binding.ReaderQuotas.MaxArrayLength = 16384;

                    _binding.Security.Transport.ProtectionLevel = System.Net.Security.ProtectionLevel.EncryptAndSign;
                    _binding.Security.Message.ClientCredentialType = UseWindowsAuth ? MessageCredentialType.Windows : MessageCredentialType.UserName;
                    _binding.Security.Mode = UseWindowsAuth ? SecurityMode.Transport : SecurityMode.TransportWithMessageCredential;

                    logger.Debug($"Using EncryptAndSing on Transport {_binding.Security.Transport.ProtectionLevel == System.Net.Security.ProtectionLevel.EncryptAndSign}");

                    logger.Debug($"Using MessageCrentialType.Windows {_binding.Security.Message.ClientCredentialType == MessageCredentialType.Windows}");
                }
                return _binding;
            }
        }

        private NetworkCredential Credential { get; }
        private string Instance { get; }
        private int Port { get; }

        private ResourceClient ResourceClient
        {
            get
            {
                if (_resource == null || _resource.State == CommunicationState.Closed)
                {
                    logger.Debug($"Constructing new {typeof(ResourceClient).FullName}");

                    UriBuilder uriBuilder = new UriBuilder
                    {
                        Scheme = "net.tcp",
                        Host = Server,
                        Port = Port,

                        Path = $"ActiveDirectoryWebServices/{Auth}/Resource"
                    };

                    _resource = new ResourceClient(Binding, new EndpointAddress(uriBuilder.Uri));
                    if (Credential != null)
                    {
                        if (UseWindowsAuth)
                        {
                            _resource.ClientCredentials.Windows.ClientCredential.UserName = Credential.UserName;
                            _resource.ClientCredentials.Windows.ClientCredential.Password = Credential.Password;
                            _resource.ClientCredentials.Windows.ClientCredential.Domain = Credential.Domain;
                        }
                        else
                        {
                            _resource.ClientCredentials.UserName.UserName = $"{Credential.UserName}@{Credential.Domain}";
                            _resource.ClientCredentials.UserName.Password = Credential.Password;
                            _resource.ClientCredentials.ServiceCertificate.Authentication.CertificateValidationMode = System.ServiceModel.Security.X509CertificateValidationMode.None;
                        }
                    }
                    _resource.ClientCredentials.Windows.AllowedImpersonationLevel = System.Security.Principal.TokenImpersonationLevel.Impersonation;
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

                    UriBuilder uriBuilder = new UriBuilder
                    {
                        Scheme = "net.tcp",
                        Host = Server,
                        Port = Port,

                        Path = $"ActiveDirectoryWebServices/{Auth}/Enumeration"
                    };

                    _search = new SearchClient(Binding, new EndpointAddress(uriBuilder.Uri));

                    if (Credential != null)
                    {
                        if (UseWindowsAuth)
                        {
                            _search.ClientCredentials.Windows.ClientCredential.UserName = Credential.UserName;
                            _search.ClientCredentials.Windows.ClientCredential.Password = Credential.Password;
                            _search.ClientCredentials.Windows.ClientCredential.Domain = Credential.Domain;
                        }
                        else
                        {
                            _search.ClientCredentials.UserName.UserName = $"{Credential.UserName}@{Credential.Domain}";
                            _search.ClientCredentials.UserName.Password = Credential.Password;
                            _search.ClientCredentials.ServiceCertificate.Authentication.CertificateValidationMode = System.ServiceModel.Security.X509CertificateValidationMode.None;
                        }
                    }
                    _search.ClientCredentials.Windows.AllowedImpersonationLevel = System.Security.Principal.TokenImpersonationLevel.Impersonation;
                }
                return _search;
            }
        }

        private string Server { get; }

        public List<DataHolder> GetRootDSE()
        {
            logger.Debug("Getting RootDSE");
            var result = new List<DataHolder>();

            var messageBuffer = new GetRequest(Instance).CreateBufferedCopy();
            messageBuffer.WriteMessageToDebug(logger);

            var rootDSEResponse = ResourceClient.Get(messageBuffer.CreateMessage());
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
                if (item.Key.Equals("container-hierarchy-parent", StringComparison.InvariantCultureIgnoreCase) || item.Key.Equals("objectReferenceProperty", StringComparison.InvariantCultureIgnoreCase))
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
            if (!fields.Any(field => field.Equals("distinguishedname", StringComparison.CurrentCultureIgnoreCase)))
            {
                fields.Add("distinguishedname");
            }

            string enumerateContext = null;
            DateTime? enumerateContextExpires = null;
            int pageNumber = 0;
            try
            {
                var enumerateRequest = new EnumerateRequest(Instance, filter, dn, scope, fields).CreateBufferedCopy();
                enumerateRequest.WriteMessageToDebug(logger);

                var enumerateResponse = SearchClient.Enumerate(enumerateRequest.CreateMessage());
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

                        var renewRequestBuffer = new RenewRequest(Instance, enumerateContext, DateTime.Now.AddMinutes(25)).CreateBufferedCopy();
                        renewRequestBuffer.WriteMessageToDebug(logger);

                        var renewResponse = SearchClient.Renew(renewRequestBuffer.CreateMessage());
                        var renewResponseBuffer = renewResponse.CreateBufferedCopy();
                        renewResponseBuffer.WriteMessageToDebug(logger);

                        if (renewResponse.IsFault)
                        {
                            throw ADWSException.FromMessageBuffer(renewResponseBuffer);
                        }
                        var parsedRenewResponse = new RenewResponse(renewResponseBuffer.CreateMessage());

                        string newEnumerateContext = parsedRenewResponse.EnumerateContext;
                        DateTime newEnumerateContextExpires = parsedRenewResponse.Expiration;

                        logger.Debug($"Completed Search.Renew, old context: {enumerateContext} would expire at {enumerateContextExpires?.ToShortDateString()} and new context: {newEnumerateContext} which expires at {newEnumerateContextExpires.ToShortDateString()}");

                        enumerateContext = newEnumerateContext;
                        enumerateContextExpires = newEnumerateContextExpires;
                    }
                    var pullRequest = new PullRequest(Instance, parsedResponse.EnumerateContext).CreateBufferedCopy();
                    pullRequest.WriteMessageToDebug(logger);

                    var pullResponse = SearchClient.Pull(pullRequest.CreateMessage());
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
                    var releaseResponse = SearchClient.Release(releaseRequest.CreateMessage());
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