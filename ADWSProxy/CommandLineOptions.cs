using CommandLine;
using System.Net;

namespace ADWSProxy
{

    internal class CommandLineOptions
    {
        private string? globalCatalog;
        private string? domainController;

        [Option("adwsdcport", Required = false, Default = 9389, HelpText = "The ADWS port to proxy to on the domain controller")]
        public int ADWSDCPort { get; set; }

        [Option("adwsgcport", Required = false, Default = 9389, HelpText = "The ADWS port to proxy to on the global catalog")]
        public int ADWSGCPort { get; set; }

        [Option("consoleloglevel", Required = false, Default = "INFO", HelpText = "Set the log level for the console output")]
        public string? ConsoleLogLevel { get; set; }

        [Option('D', "domain", Required = false, Default = null, HelpText = "The domain to authenticate to ADWS")]
        public string? Domain { get; set; }

        [Option("domaincontroller", Required = true, HelpText = "The domain controller to proxy to, full FQDN")]
        public string? DomainController
        {
            get
            {
                if (string.IsNullOrWhiteSpace(domainController) || !domainController.Contains('.'))
                {
                    throw new ArgumentException($"--domaincontroller '{domainController}' must be a full FQDN.");
                }
                return domainController;
            }
            set => domainController = value;
        }

        [Option("exitondnsstarterror", Required = false, Default = false, HelpText = "Exit the application if the DNS port is already in use")]
        public bool? ExitOnDNSStartError { get; set; }

        [Option("gcport", Required = false, Default = (ushort)3268, HelpText = "The GC port to proxy from")]
        public ushort GCPort { get; set; }

        [Option("globalcatalog", Required = false, HelpText = "The global catalog to proxy to")]
        public string? GlobalCatalog
        {
            get
            {
                if (string.IsNullOrWhiteSpace(globalCatalog))
                {
                    return null;
                }
                else if (!globalCatalog.Contains('.'))
                {
                    throw new ArgumentException($"--globalcatalog '{globalCatalog}' must be a full FQDN unless domain is specified.");
                }
                else
                {
                    return globalCatalog;
                }
            }
            set => globalCatalog = value;
        }

        [Option("hostip", Required = false, Default = null, HelpText = "Override the IP in the DNS respones")]
        public string? HostIP { get; set; }

        [Option("only-use-gc-backend", Required = false, Default = false, HelpText = "Force ADWS to use GC instance (ldap:3268) for backend communication.")]
        public bool? OnlyUseGCBacked { get; set; }

        [Option("ldapport", Required = false, Default = (ushort)389, HelpText = "The LDAP port to proxy from")]
        public ushort LDAPPort { get; set; }

        [Option("logdirectory", Required = false, Default = ".", HelpText = "The log directory to output runtime logs. Defaults to the current working directory.")]
        public string? LogDirectory { get; set; }

        [Option('p', "password", Required = false, Default = null, HelpText = "The password to authenticate to ADWS")]
        public string? Password { get; set; }

        [Option('u', "username", Required = false, Default = null, HelpText = "The username to authenticate to ADWS")]
        public string? Username { get; set; }

        [Option('m', "mode", Required = false, Default = AdwsEndpoint.Windows, HelpText = "ADWS Endpoint Mode: 'Windows' (default, NTLM/Kerberos) or 'Username' (Legacy TLS).")]
        public AdwsEndpoint Mode { get; set; }

        public NetworkCredential? GetNetworkCredential()
        {
            if (Username == null && Password == null && Domain == null) return null;

            return Username == null || Password == null || Domain == null
                ? throw new ArgumentException("Username, Password and Domain all need to be used when one value is entered")
                : new NetworkCredential(Username, Password, Domain);
        }
    }
}