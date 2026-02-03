using ADWSProxy.DNS;
using ADWSProxy.LDAP;
using ARSoft.Tools.Net.Dns;
using log4net;
using Microsoft.Extensions.Configuration;
using System.Net;

namespace ADWSProxy
{
    public class Program
    {
        private static readonly ILog logger = LogHelper.GetLogger(typeof(Program));

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
            if (!int.TryParse(ep[^1], out int port))
            {
                throw new FormatException("Invalid port");
            }
            return new IPEndPoint(ip, port);
        }

        public static void Main(string[] args)
        {
            if (args.Any(a => a.Equals("--help", StringComparison.OrdinalIgnoreCase) || a.Equals("-h", StringComparison.OrdinalIgnoreCase)))
            {
                CommandLineOptions.ShowHelp();
                return;
            }

            var configuration = new ConfigurationBuilder()
                .AddCommandLine(args, new Dictionary<string, string>{
                    { "-u", "username" },
                    { "-p", "password" },
                    { "-D", "domain" },
                    { "-m", "mode" },
                    { "-dc", "domaincontroller" },
                    { "-gc", "globalcatalog" }
                })
                .Build();

            var options = new CommandLineOptions();
            configuration.Bind(options);

            if (string.IsNullOrWhiteSpace(options.DomainController))
            {
                logger.Error("Error: --domaincontroller is required.");
                CommandLineOptions.ShowHelp();
                return;
            }

            try
            {
                _ = options.GetNetworkCredential();
            }
            catch (Exception ex)
            {
                logger.Error($"Error: {ex.Message}");
                CommandLineOptions.ShowHelp();
                return;
            }

            LoggerConfig.ConfigureLogger(options.ConsoleLogLevel, options.LogDirectory);

            logger.Info("Starting ADWSproxy.");

            var exitCode = 0;
            Listener? LDAPListener = null;
            Listener? GCListener = null;

            try
            {
                const string gcInstance = "ldap:3268";
                string ldapInstance = options.OnlyUseGCBackend ? gcInstance : "ldap:389";
                var LDAPEndpoint = $"{options.ListenIP}:{options.LDAPPort}";
                var dc = options.DomainController;
                ArgumentNullException.ThrowIfNullOrWhiteSpace(dc);

                LDAPListener = new Listener(CreateIPEndPoint(LDAPEndpoint), dc, options.ADWSDCPort, ldapInstance, options.Mode, options.GetNetworkCredential());
                LDAPListener.Start();
                logger.Info($"Succesfully started the LDAPListener on {LDAPEndpoint} using instance {ldapInstance}");

                var gc = options.GlobalCatalog;
                if (string.IsNullOrWhiteSpace(gc))
                {
                    logger.Info($"No Global Catalog server defined so no Global Catalog listener has been started");
                }
                else
                {
                    var GCEndpoint = $"{options.ListenIP}:{options.GCPort}";

                    GCListener = new Listener(CreateIPEndPoint(GCEndpoint), gc, options.ADWSGCPort, gcInstance, options.Mode, options.GetNetworkCredential());
                    GCListener.Start();
                    logger.Info($"Succesfully started the GCListener on {GCEndpoint} using instance {gcInstance}");
                }

                if (options.SkipDns)
                {
                    logger.Info("Skipping DNS listener startup");
                }
                else
                {
                    try
                    {
                        if (StartDNS(options.ExitOnDNSStartError, options.LDAPPort, options.GCPort, options.HostIP))
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
                }


                try
                {
                    var rootDSE = LDAPListener.ADWSConnection.GetRootDSE();
                    logger.Info("Succesfully got RootDSE via LDAPListener");
                    logger.Debug($"LDAP RootDSE: {string.Join("; ", rootDSE.Select(d => d.ToString()))}");
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
                        logger.Debug($"GC RootDSE: {string.Join("; ", rootDSE.Select(d => d.ToString()))}");
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