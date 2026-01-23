using ADWSProxy.LDAP;
using CommandLine;
using CommandLine.Text;
using DNS.Server;
using log4net;
using Newtonsoft.Json;
using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;

namespace ADWSProxy
{
    internal class Program
    {
        private static readonly ILog logger = LogManager.GetLogger(System.Reflection.MethodBase.GetCurrentMethod()?.DeclaringType!);

        // Handles IPv4 and IPv6 notation.
        private static IPEndPoint CreateIPEndPoint(string endPoint)
        {
            string[] ep = endPoint.Split(':');
            if (ep.Length < 2) throw new FormatException("Invalid endpoint format");
            IPAddress? ip;
            if (ep.Length > 2)
            {
                if (!IPAddress.TryParse(string.Join(":", ep, 0, ep.Length - 1), out ip))
                {
                    throw new FormatException("Invalid ip-adress");
                }
            }
            else
            {
                if (!IPAddress.TryParse(ep[0], out ip))
                {
                    throw new FormatException("Invalid ip-adress");
                }
            }
            if (!int.TryParse(ep[^1], NumberStyles.None, NumberFormatInfo.CurrentInfo, out int port))
            {
                throw new FormatException("Invalid port");
            }
            return new IPEndPoint(ip, port);
        }

        private static void Main(string[] args)
        {
            var parser = new Parser(with => with.HelpWriter = null);
            var parsedArgs = parser.ParseArguments<CommandLineOptions>(args);

            if (parsedArgs.Tag == ParserResultType.NotParsed)
            {
                var helpText = HelpText.AutoBuild(parsedArgs, h =>
                {
                    h.Copyright = $"Created by Rabobank Red Team";
                    h.AutoVersion = true;
                    return h;
                });
                Console.WriteLine(helpText);
                Console.WriteLine("Press enter to close");
                Console.ReadLine();
                Environment.Exit(1);
                return;
            }

            LoggerConfig.ConfigureLogger(parsedArgs.Value.ConsoleLogLevel!, parsedArgs.Value.LogDirectory!);

            logger.Info("Starting ADWSproxy.");

            var exitCode = 0;
            Listener? LDAPListener = null;
            Listener? GCListener = null;

            var credentials = parsedArgs.Value.GetNetworkCredential();

            try
            {
                var LDAPEndpoint = $"0.0.0.0:{parsedArgs.Value.LDAPPort}";
                var dc = parsedArgs.Value.DomainController;
                ArgumentNullException.ThrowIfNullOrWhiteSpace(dc);
                if (!dc.Contains('.') && !string.IsNullOrWhiteSpace(parsedArgs.Value.Domain))
                {
                    dc = $"{dc}.{parsedArgs.Value.Domain}";
                }

                LDAPListener = new Listener(CreateIPEndPoint(LDAPEndpoint), dc, parsedArgs.Value.ADWSDCPort, parsedArgs.Value.LDAPInstance!, parsedArgs.Value.Mode, credentials);
                LDAPListener.Start();
                logger.Info($"Succesfully started the LDAPListener on {LDAPEndpoint} using instance {parsedArgs.Value.LDAPInstance}");

                var gc = parsedArgs.Value.GlobalCatalog;
                if (string.IsNullOrWhiteSpace(gc))
                {
                    logger.Info($"No Global Catalog server defined so no Global Catalog listener has been started");
                }
                else
                {
                    if (!gc.Contains('.'))
                    {
                        gc = gc + "." + parsedArgs.Value.Domain;
                    }
                    var GCEndpoint = $"0.0.0.0:{parsedArgs.Value.GCPort}";
                    GCListener = new Listener(CreateIPEndPoint(GCEndpoint), gc, parsedArgs.Value.ADWSGCPort, parsedArgs.Value.GCInstance!, parsedArgs.Value.Mode, credentials);
                    GCListener.Start();
                    logger.Info($"Succesfully started the GCListener on {GCEndpoint} using instance {parsedArgs.Value.GCInstance}");
                }

                try
                {
                    var dnsEndpoint = CreateIPEndPoint($"0.0.0.0:{parsedArgs.Value.DnsPort}");
                    if (StartDNS(true, dnsEndpoint, parsedArgs.Value.LDAPPort, parsedArgs.Value.GCPort))
                    {
                        logger.Info($"Succesfully started the DNSListener on {dnsEndpoint}");
                    }
                    else
                    {
                        const string errorString = "Error starting DNSListner";
                        throw new Exception(errorString);
                    }
                }
                catch (Exception ex)
                {
                    logger.Error(ex.Message, ex);
                }

                try
                {
                    var rootDSE = LDAPListener.ADWSConnection.GetRootDSE();
                    logger.Info("Succesfully got RootDSE via LDAPListener");
                    logger.Debug($"LDAP RootDSE: {JsonConvert.SerializeObject(rootDSE)}");
                }
                catch (Exception ex)
                {
                    logger.Error(ex.Message, ex);
                }

                try
                {
                    if (GCListener != null)
                    {
                        var rootDSE = GCListener.ADWSConnection.GetRootDSE();
                        logger.Info("Succesfully got RootDSE via GCListener");
                        logger.Debug($"GC RootDSE: {JsonConvert.SerializeObject(rootDSE)}");
                    }
                }
                catch (Exception ex)
                {
                    logger.Error(ex.Message, ex);
                }
            }
            catch (Exception ex)
            {
                logger.Error($"Application will close because of an error: {ex.Message}", ex);
                LDAPListener?.Dispose();
                GCListener?.Dispose();
                exitCode = 1;
            }

            Console.WriteLine("Pressing Enter will close the application");
            Console.ReadLine();
            Environment.Exit(exitCode);
        }

        /// <summary>
        /// This wil start a DNS Server listening on UDP/53.
        /// </summary>
        private static bool StartDNS(bool ExitOnDNSStartError, IPEndPoint dnsEndpoint, ushort ldapPort, ushort gcPort)
        {
            bool alreadyinuse = IPGlobalProperties.GetIPGlobalProperties().GetActiveUdpListeners().Any(p => p.Port == dnsEndpoint.Port);
            if (alreadyinuse)
            {
                string errorMessage = $"Port UDP/{dnsEndpoint.Port} is already in use, unable to start DNS resolver.";
                logger.Error(errorMessage);
                if (ExitOnDNSStartError)
                {
                    Environment.Exit(1);
                }
                return false;
            }
            else
            {
                DnsServer dnsServer = new(new DNS.Resolver(ldapPort, gcPort), dnsEndpoint);
                dnsServer.Listen();
                return true;
            }
        }
    }
}