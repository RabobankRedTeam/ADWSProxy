using System.Net;

namespace ADWSProxy
{
    public class CommandLineOptions
    {
        private string? _globalCatalog;
        private string? _domainController;

        // Numeric and Boolean types map automatically from the command line
        public int ADWSDCPort { get; set; } = 9389;
        public int ADWSGCPort { get; set; } = 9389;
        public string ConsoleLogLevel { get; set; } = "INFO";
        public string? Domain { get; set; }

        public string? DomainController
        {
            get
            {
                if (string.IsNullOrWhiteSpace(_domainController))
                {
                    throw new ArgumentException($"--domaincontroller '{_domainController}' must be a full FQDN.");
                }
                return _domainController;
            }
            set
            {
                if (string.IsNullOrWhiteSpace(value))
                {
                    throw new ArgumentException($"--domaincontroller is required.");
                }
                _domainController = Uri.CheckHostName(value).Equals(UriHostNameType.Dns)
                    ? value
                    : throw new ArgumentException($"--domaincontroller '{value}' must be a FQDN.");
            }
        }

        public bool ExitOnDNSStartError { get; set; } = false;
        public ushort GCPort { get; set; } = 3268;

        public string? GlobalCatalog
        {
            get
            {
                if (string.IsNullOrWhiteSpace(_globalCatalog))
                {
                    return null;
                }
                return _globalCatalog;
            }

            set
            {
                if (string.IsNullOrWhiteSpace(value))
                {
                    _globalCatalog = null;
                }
                _globalCatalog = Uri.CheckHostName(value).Equals(UriHostNameType.Dns)
                    ? value
                    : throw new ArgumentException($"--globalcatalog '{value}' must be a FQDN."); 
            }
        }

        public string? HostIP { get; set; }

        private string _listenIP = "0.0.0.0";
        public string ListenIP
        {
            get => _listenIP;
            set
            {
                if (IPAddress.TryParse(value, out var address) &&
                    address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                {
                    _listenIP = value;
                }
                else
                {
                    throw new ArgumentException($"--hostip '{value}' is not a valid IPv4 address.");
                }
            }
        }
        public bool OnlyUseGCBackend { get; set; } = false;
        public ushort LDAPPort { get; set; } = 389;
        public string LogDirectory { get; set; } = ".";
        public string? Password { get; set; }
        public string? Username { get; set; }
        public AdwsEndpoint Mode { get; set; } = AdwsEndpoint.Windows;
        public bool SkipDns { get; set; } = false;

        public NetworkCredential? GetNetworkCredential()
        {
            if (Username == null && Password == null && Domain == null) return null;

            return (Username == null || Password == null || Domain == null)
                ? throw new ArgumentException("Username, Password, and Domain must all be provided if any one is entered.")
                : new NetworkCredential(Username, Password, Domain);
        }

        public static void ShowHelp()
        {
            Console.WriteLine("ADWSProxy - Active Directory Web Services Proxy");
            Console.WriteLine("Created by Rabobank Red Team");
            Console.WriteLine("==============================================");
            Console.WriteLine("Options:");
            Console.WriteLine("  --domaincontroller <fqdn>    (Required) The DC to proxy to.");
            Console.WriteLine("  --globalcatalog <fqdn>       The GC to proxy to.");
            Console.WriteLine("  --ldapport <port>            LDAP port to listen on (Default: 389).");
            Console.WriteLine("  --gcport <port>              GC port to listen on (Default: 3268).");
            Console.WriteLine("  --adwsdcport <port>          Target ADWS DC port (Default: 9389).");
            Console.WriteLine("  --hostip <ip>                The IP used for the DNS responses (Default: IPv4 local IP).");
            Console.WriteLine("  --listenip <ip>              The IP to listen on for LDAP/GC requests (Default: 0.0.0.0).");
            Console.WriteLine("  --mode <Windows|Username>    ADWS Endpoint Mode (Default: Windows).");
            Console.WriteLine("  --skipdns <true|false>       Skip starting the DNS listener.");
            Console.WriteLine("  --username <user>            Username for ADWS authentication.");
            Console.WriteLine("  --password <pass>            Password for ADWS authentication.");
            Console.WriteLine("  --domain <domain>            Domain for ADWS authentication.");
            Console.WriteLine("  --help                       Show this help message.");
            Console.WriteLine();
        }
    }
}