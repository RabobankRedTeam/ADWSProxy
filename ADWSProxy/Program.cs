using ADWSProxy.DNS;
using ADWSProxy.LDAP;
using ARSoft.Tools.Net.Dns;
using CommandLine;
using CommandLine.Text;
using log4net;
using Newtonsoft.Json;
using System.Globalization;
using System.Net;

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
                const string gcInstance = "ldap:3268";
                string ldapInstance = parsedArgs.Value.OnlyUseGCBacked!.Value ? gcInstance : "ldap:389";
                var LDAPEndpoint = $"0.0.0.0:{parsedArgs.Value.LDAPPort}";
                var dc = parsedArgs.Value.DomainController;
                ArgumentNullException.ThrowIfNullOrWhiteSpace(dc);

                LDAPListener = new Listener(CreateIPEndPoint(LDAPEndpoint), dc, parsedArgs.Value.ADWSDCPort, ldapInstance, parsedArgs.Value.Mode, credentials);
                LDAPListener.Start();
                logger.Info($"Succesfully started the LDAPListener on {LDAPEndpoint} using instance {ldapInstance}");

                var gc = parsedArgs.Value.GlobalCatalog;
                if (string.IsNullOrWhiteSpace(gc))
                {
                    logger.Info($"No Global Catalog server defined so no Global Catalog listener has been started");
                }
                else
                {
                    var GCEndpoint = $"0.0.0.0:{parsedArgs.Value.GCPort}";

                    GCListener = new Listener(CreateIPEndPoint(GCEndpoint), gc, parsedArgs.Value.ADWSGCPort, gcInstance, parsedArgs.Value.Mode, credentials);
                    GCListener.Start();
                    logger.Info($"Succesfully started the GCListener on {GCEndpoint} using instance {gcInstance}");
                }

                try
                {
                    if (StartDNS(parsedArgs.Value.ExitOnDNSStartError ?? false, parsedArgs.Value.LDAPPort, parsedArgs.Value.GCPort, parsedArgs.Value.HostIP))
                    {
                        logger.Info($"Succesfully started the DNSListener");
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

        private static bool StartDNS(bool ExitOnDNSStartError, ushort ldapPort, ushort gcPort, string? hostIp = null)
        {
            try
            {
                IPAddress? h = string.IsNullOrWhiteSpace(hostIp) ? null : IPAddress.Parse(hostIp);
                var resolver = new Resolver(ldapPort, gcPort, h);
                DnsServer server = new(10, 10);
                server.QueryReceived += resolver.OnQueryReceived;
                server.Start();
                logger.Info("DNS Server is live on UDP and TCP port 53.");
                return true;
            }
            catch (Exception ex)
            {
                logger.Error("Error starting DNS server", ex);
                if (ExitOnDNSStartError)
                {
                    Environment.Exit(1);
                }
                return false;
            }
        }
    }
}