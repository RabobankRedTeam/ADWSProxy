using ADWSProxy.ADWS;
using Flexinets.Ldap.Core;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;

namespace ADWSProxy.LDAP
{
    internal class Listener : IDisposable
    {
        private static readonly log4net.ILog logger = log4net.LogManager.GetLogger(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType);

        public Listener(IPEndPoint endpoint, string domainController, int adwsPort, string instance, bool useWindowsAuth, NetworkCredential credential = null)
        {
            logger.Info($"Constructing new {GetType().FullName}");

            TcpListener = new TcpListener(endpoint);

            ADWSConnection = new Connection(domainController, adwsPort, instance, useWindowsAuth, credential);
            Instance = instance;
        }

        public string Instance { get; }
        internal Connection ADWSConnection { get; }
        private TcpListener TcpListener { get; }

        public void Dispose()
        {
            Stop();
        }

        public void Start()
        {
            TcpListener.Start();
            _ = StartAcceptingClientsAsync();
        }

        public void Stop()
        { TcpListener.Stop(); }

        /// <summary>
        /// Handle bindrequests
        /// </summary>
        /// <param name="bindrequest"></param>
        private bool HandleBindRequest(Stream stream, LdapPacket requestPacket)
        {
            logger.Info($"Handling bind request");

            var bindrequest = requestPacket.ChildAttributes.SingleOrDefault(o => o.LdapOperation == LdapOperation.BindRequest);
            var passwordAttribute = bindrequest.ChildAttributes[2];

            LdapAttribute ldapResultPacket = null;

            switch (passwordAttribute.ContextType)
            {
                case 0:
                    logger.Debug("Simple authentication");
                    var username = bindrequest.ChildAttributes[1].GetValue<string>();
                    var password = passwordAttribute.GetValue<string>();
                    logger.Debug($"Credentials: {username}:{password}");
                    ldapResultPacket = new LdapResultAttribute(LdapOperation.BindResponse, LdapResult.success);
                    break;

                case 9:
                    logger.Debug("NTLM-1 authentication");
                    ldapResultPacket = new LdapResultAttribute(LdapOperation.BindResponse, LdapResult.success, matchedDN: "NTLM");
                    break;

                case 10:
                    logger.Debug("NTLM-2 authentication");
                    ldapResultPacket = new LdapResultRawMatchedDNAttribute(LdapOperation.BindResponse, LdapResult.success, Helpers.NTLMMatchedDN());
                    break;

                case 11:
                    logger.Debug("NTLM-3 authentication");
                    ldapResultPacket = new LdapResultAttribute(LdapOperation.BindResponse, LdapResult.success, matchedDN: string.Empty);
                    break;

                default:
                    logger.Error($"Unknown authentication type: '{passwordAttribute.ContextType}'");
                    ldapResultPacket = new LdapResultAttribute(LdapOperation.BindResponse, LdapResult.success, matchedDN: string.Empty);
                    break;
            }

            var responsePacket = new LdapPacket(requestPacket.MessageId);

            responsePacket.ChildAttributes.Add(ldapResultPacket);
            var responseBytes = responsePacket.GetBytes();
            stream.Write(responseBytes, 0, responseBytes.Length);
            return ldapResultPacket.ChildAttributes.First(i => i.DataType == UniversalDataType.Enumerated).GetRawValue()[0] == (byte)LdapResult.success;
        }

        private void HandleClient(TcpClient client)
        {
            // By default all LDAP packets will be processed as if the client is authenticated
            var isBound = true;
            var stream = client.GetStream();

            while (LdapPacket.TryParsePacket(stream, out LdapPacket requestPacket))
            {
                try
                {
                    logger.Info($"New LDAP packet received for instance {Instance}. Time to get to work!");
                    LogPacket(requestPacket);

                    if (requestPacket.ChildAttributes.Any(o => o.LdapOperation == LdapOperation.BindRequest))
                    {
                        isBound = HandleBindRequest(stream, requestPacket);
                    }

                    if (requestPacket.ChildAttributes.Any(o => o.LdapOperation == LdapOperation.UnbindRequest))
                    {
                        isBound = false;
                        break;
                    }

                    if (isBound)
                    {
                        logger.Debug("Client is bound. We can continue.");

                        if (requestPacket.ChildAttributes.Any(o => o.LdapOperation == LdapOperation.SearchRequest))
                        {
                            HandleSearchRequest(stream, requestPacket);
                        }
                    }
                    logger.Info("Packet handling done!");
                }
                catch (System.ArgumentException ex)
                {
                    logger.Error("ArgumentException. Continuing.", ex);
                }
                catch (Exception ex)
                {
                    logger.Error(ex.Message, ex);
                }
            }
            logger.Info("Client handling done! Can we go to sleep now? Please?");
        }

        private void HandleSearchRequest(NetworkStream stream, LdapPacket requestPacket)
        {
            logger.Debug("Handling Search request");

            var searchRequest = requestPacket.ChildAttributes.SingleOrDefault(o => o.LdapOperation == LdapOperation.SearchRequest);
            var dnAttribute = searchRequest.ChildAttributes.First();
            var scopeAttribute = searchRequest.ChildAttributes[1];
            var filterAttributes = searchRequest.ChildAttributes.Where(item => item.Class == TagClass.Context);
            var propertiesAttribute = searchRequest.ChildAttributes.Last();

            var filter = ParseFilters(filterAttributes);
            var properties = ParseProperties(propertiesAttribute);
            var dn = dnAttribute.GetValue<string>();

            var scopeValue = scopeAttribute.GetValue();

            string scope;
            switch (scopeValue)
            {
                case "\u0001":
                    scope = "onelevel";
                    break;

                case "\u0002":
                    scope = "subtree";
                    break;

                case "\0":
                    scope = "base";
                    break;

                default:
                    throw new NotImplementedException($"'{scopeValue}' is an unknown scope identifier");
            }

            logger.Info($"Request DN = {dn}");
            logger.Info($"Request filter = {filter}");
            logger.Info($"Request properties = {string.Join(",", properties)}");
            logger.Info($"Request scopeIdentifier = {scopeValue}, Scope: {scope}");

            // TODO: Check if there is a more elegant solution to this.
            if (dn.Equals("") && filter.ToLower().Equals("(objectclass=*)") && scope == "base")
            {
                try
                {
                    var rootDSE = ADWSConnection.GetRootDSE();
                    var rootDSEEntryPacket = new LdapPacket(requestPacket.MessageId);
                    var rootDSEResultEntry = new LdapAttribute(LdapOperation.SearchResultEntry);

                    rootDSEResultEntry.ChildAttributes.Add(new LdapAttribute(UniversalDataType.OctetString, string.Empty));
                    rootDSEResultEntry = rootDSEResultEntry.AddItemsToResponse(rootDSE);

                    rootDSEEntryPacket.ChildAttributes.Add(rootDSEResultEntry);

                    byte[] responseEntryBytes = rootDSEEntryPacket.GetBytes();
                    stream.Write(responseEntryBytes, 0, responseEntryBytes.Length);

                    var ldapPacket = new LdapPacket(requestPacket.MessageId);
                    ldapPacket.ChildAttributes.Add(new LdapResultAttribute(LdapOperation.SearchResultDone, LdapResult.success));
                    var ldapPacketBytes = ldapPacket.GetBytes();
                    stream.Write(ldapPacketBytes, 0, ldapPacketBytes.Length);
                }
                catch (Exception ex)
                {
                    logger.Error(ex.Message, ex);
                    var ldapPacket = new LdapPacket(requestPacket.MessageId);
                    ldapPacket.ChildAttributes.Add(new LdapResultAttribute(LdapOperation.SearchResultDone, LdapResult.operationError, diagnosticMessage: ex.Message));
                    var ldapPacketBytes = ldapPacket.GetBytes();
                    stream.Write(ldapPacketBytes, 0, ldapPacketBytes.Length);
                }
                return;
            }

            var blockedProperties = new List<string>();
            // Bloodhound.py requested the a number of non existing properties during testing.
            // These are removed from the request as this would cause an exception when sent to the ADWS endpoint.
            // Root cause of this issue has not been investigated as manually blocking these properties works for now.
            if (dn.ToLower().StartsWith("cn=aggregate,cn=schema,cn=configuration,dc=")
                && filter.ToLower().Equals("(objectclass=subschema)")
                && scope.Equals("base"))
            {
                blockedProperties.AddRange(new[] { "createtimestamp", "ldapsyntaxes", "matchingrules", "matchingruleuse", "ditstructurerules", "nameforms" });
            }
            foreach (var blockedProperty in blockedProperties)
            {
                properties.RemoveAll(prop => prop.Equals(blockedProperty, StringComparison.OrdinalIgnoreCase));
            }
            logger.Debug($"Filtered request properties = {string.Join(",", properties)}");

            ADWSConnection.Enumerate(dn, filter, properties, scope, ((string, List<DataHolder>) result) =>
            {
                logger.Info($"Result DN = {result.Item1}");

                var responseEntryPacket = new LdapPacket(requestPacket.MessageId);
                var searchResultEntry = new LdapAttribute(LdapOperation.SearchResultEntry);

                searchResultEntry.ChildAttributes.Add(new LdapAttribute(UniversalDataType.OctetString, result.Item1));
                searchResultEntry = searchResultEntry.AddItemsToResponse(result.Item2);

                responseEntryPacket.ChildAttributes.Add(searchResultEntry);

                byte[] responseEntryBytes = responseEntryPacket.GetBytes();
                stream.Write(responseEntryBytes, 0, responseEntryBytes.Length);
            });

            var responseDonePacket = new LdapPacket(requestPacket.MessageId);
            responseDonePacket.ChildAttributes.Add(new LdapResultAttribute(LdapOperation.SearchResultDone, LdapResult.success));
            var responseDoneBytes = responseDonePacket.GetBytes();
            stream.Write(responseDoneBytes, 0, responseDoneBytes.Length);
        }

        private void LogPacket(LdapAttribute attribute)
        {
            var sb = new StringBuilder();
            RecurseAttributes(sb, attribute);
            logger.Debug($"Recieved LDAP Packet dump\n{sb}");
        }

        private string ParseFilter(LdapAttribute filterAttribute, StringBuilder sb = null)
        {
            var context = (LdapFilterChoice?)filterAttribute.ContextType;
            if (context == null)
            {
                return null;
            }

            if (sb == null)
            {
                sb = new StringBuilder();
            }

            sb.Append("(");

            switch (context)
            {
                case LdapFilterChoice.and:
                    sb.Append("&");
                    break;

                case LdapFilterChoice.or:
                    sb.Append("|");
                    break;

                case LdapFilterChoice.not:
                    sb.Append("!");
                    break;

                case LdapFilterChoice.substrings:
                    var subStringAttribute = filterAttribute.ChildAttributes[1].ChildAttributes.First();
                    string substring = subStringAttribute.GetValue<string>();
                    string value;
                    switch (subStringAttribute.ContextType)
                    {
                        case 0:
                            value = $"{substring}*";
                            break;

                        case 1:
                            value = $"*{substring}*";
                            break;

                        case 2:
                            value = $"*{substring}";
                            break;

                        default:
                            throw new NotImplementedException($"Unknown ContextType: '{subStringAttribute.ContextType}' in subStringAttribute");
                    }

                    sb.Append($"{filterAttribute.ChildAttributes[0].GetValue<string>()}={value}");
                    break;

                case LdapFilterChoice.equalityMatch:
                    var name = filterAttribute.ChildAttributes[0].GetValue<string>();
                    if (name.ToLowerInvariant() == "objectsid")
                    {
                        var bytesValue = filterAttribute.ChildAttributes[1].GetRawValue();
                        string sid;
                        try
                        {
                            sid = new SecurityIdentifier(bytesValue, 0).ToString();
                        }
                        catch (Exception ex)
                        {
                            var base64 = Convert.ToBase64String(bytesValue);
                            logger.Debug($"Coudn't parse value to SecurityIdentifier class, will used UTF-8 to get String. Base64 value was {base64}", ex);
                            sid = Encoding.UTF8.GetString(bytesValue);
                        }
                        sb.Append($"{filterAttribute.ChildAttributes[0].GetValue<string>()}={sid}");
                    }
                    else
                    {
                        sb.Append($"{filterAttribute.ChildAttributes[0].GetValue<string>()}={filterAttribute.ChildAttributes[1].GetValue<string>()}");
                    }
                    break;

                case LdapFilterChoice.greaterOrEqual:
                    sb.Append($"{filterAttribute.ChildAttributes[0].GetValue<string>()}>={filterAttribute.ChildAttributes[1].GetValue<string>()}");
                    break;

                case LdapFilterChoice.lessOrEqual:
                    sb.Append($"{filterAttribute.ChildAttributes[0].GetValue<string>()}<={filterAttribute.ChildAttributes[1].GetValue<string>()}");
                    break;

                case LdapFilterChoice.present:
                    sb.Append($"{filterAttribute.GetValue<string>()}=*");
                    break;

                case LdapFilterChoice.approxMatch:
                    sb.Append($"{filterAttribute.ChildAttributes[0].GetValue<string>()}~={filterAttribute.ChildAttributes[1].GetValue<string>()}");
                    break;

                case LdapFilterChoice.extensibleMatch:
                    var extensibleMatchValue = filterAttribute.ChildAttributes[2].GetRawValue();

                    if (extensibleMatchValue.Length == 1 && extensibleMatchValue.First() == 0xff)
                    {
                        sb.Append($"{filterAttribute.ChildAttributes[0].GetValue<string>()}:dn:={filterAttribute.ChildAttributes[1].GetValue<string>()}");
                    }
                    else
                    {
                        var extensibleMatchValueString = Encoding.UTF8.GetString(extensibleMatchValue);
                        sb.Append($"{filterAttribute.ChildAttributes[1].GetValue<string>()}:{filterAttribute.ChildAttributes[0].GetValue<string>()}:={extensibleMatchValueString}");
                    }
                    break;

                default:
                    throw new NotImplementedException($"Unknown ContextType: '{filterAttribute.ContextType}' in filterAttribute");
            }

            foreach (var child in filterAttribute.ChildAttributes.Where(item => item.ChildAttributes.Any()))
            {
                ParseFilter(child, sb);
            }
            sb.Append(")");

            return sb.ToString();
        }

        private string ParseFilters(IEnumerable<LdapAttribute> filterAttribute)
        {
            var sb = new StringBuilder();
            foreach (var attr in filterAttribute)
            {
                var temp = ParseFilter(attr);
                if (!temp.StartsWith("("))
                {
                    temp = $"({temp})";
                }
                sb.Append(temp);
            }
            return sb.ToString();
        }

        private List<string> ParseProperties(LdapAttribute attributes)
        {
            var result = new List<string>();
            if (attributes != null)
            {
                foreach (var attr in attributes.ChildAttributes)
                {
                    var attribute = attr.GetValue<string>();
                    // TODO: Confirm that '+' is not needed
                    if (!attribute.Equals("+"))
                    {
                        result.Add(attribute);
                    }
                }
            }
            return result;
        }

        private void RecurseAttributes(StringBuilder sb, LdapAttribute attribute, int depth = 1)
        {
            if (attribute != null)
            {
                sb.AppendLine($"{Utils.Repeat(">", depth)} {attribute.Class}:{attribute.DataType}{attribute.LdapOperation}{attribute.ContextType} - Type: {attribute.GetValue().GetType()} - {attribute.GetValue()}");
                if (attribute.IsConstructed)
                {
                    attribute.ChildAttributes.ForEach(o => RecurseAttributes(sb, o, depth + 1));
                }
            }
        }

        private async Task StartAcceptingClientsAsync()
        {
            while (TcpListener.Server.IsBound)
            {
                try
                {
                    var client = await TcpListener.AcceptTcpClientAsync();
                    var task = Task.Factory.StartNew(() => HandleClient(client), TaskCreationOptions.LongRunning);
                }
                catch (Exception ex)
                {
                    logger.Error(ex.Message, ex);
                }
            }
        }
    }
}