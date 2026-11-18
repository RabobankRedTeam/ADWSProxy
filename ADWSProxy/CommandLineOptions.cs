using System.Net;

namespace ADWSProxy
{
    public class CommandLineOptions
    {
        private string? _globalCatalog;
        private string? _domainController;
        
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
                    throw new ArgumentException($"--domaincontroller '{_domainController}' must be a full FQDN");
                }
                return _domainController;
            }
            set
            {
                if (string.IsNullOrWhiteSpace(value))
                {
                    throw new ArgumentException($"--domaincontroller is required");
                }
                _domainController = value;
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
                _globalCatalog = string.IsNullOrWhiteSpace(value) ? null : value;
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
                    throw new ArgumentException($"--hostip '{value}' is not a valid IPv4 address");
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
        public bool SkipRootDSE { get; set; } = false;
        public bool LogPasswords { get; set; } = true;


        public NetworkCredential? GetNetworkCredential()
        {
            if (Username == null && Password == null && Domain == null) return null;

            return (Username == null || Password == null || Domain == null)
                ? throw new ArgumentException("Username, Password, and Domain must all be provided if any one is entered")
                : new NetworkCredential(Username, Password, Domain);
        }

        public static void ShowHelp()
        {
            Console.WriteLine("ADWSProxy - Active Directory Web Services Proxy");
            Console.WriteLine("Created by Rabobank Red Team");
            Console.WriteLine("==============================================");
            Console.WriteLine("Options:");
            Console.WriteLine("  -dc, --domaincontroller <fqdn>     (Required) The domain controller to proxy to for NTDS");
            Console.WriteLine("  -gc, --globalcatalog <fqdn>        The global catalog to proxy to (Default: only the DC/NTDS is used)");
            Console.WriteLine("       --ldapport <port>             LDAP port to listen on (Default: 389)");
            Console.WriteLine("       --gcport <port>               GC port to listen on (Default: 3268)");
            Console.WriteLine("       --adwsdcport <port>           ADWS port on the domain controller (Default: 9389)");
            Console.WriteLine("       --adwsgcport <port>           ADWS port on the global catalog (Default: 9389)");
            Console.WriteLine("       --onlyusegcbackend <bool>     Use the GC instance (ldap:3268) for all backend communication (Default: false)");
            Console.WriteLine("       --listenip <ip>               The IP to listen on for LDAP/GC requests (Default: 0.0.0.0)");
            Console.WriteLine("       --hostip <ip>                 The IP returned in DNS responses (Default: system IPv4)");
            Console.WriteLine("       --skipdns <bool>              Skip starting the DNS listener (Default: false)");
            Console.WriteLine("       --exitondnsstarterror <bool>  Exit if the DNS listener cannot start, e.g. port 53 in use (Default: false)");
            Console.WriteLine("       --skiprootdse <bool>          Skip querying the RootDSE during startup (Default: false)");
            Console.WriteLine("  -m,  --mode <Windows|Username>     ADWS endpoint mode (Default: Windows)");
            Console.WriteLine("       --consoleloglevel <level>     Log level for the console output (Default: INFO)");
            Console.WriteLine("       --logdirectory <dir>          Directory for runtime logs (Default: .)");
            Console.WriteLine("       --logpasswords <bool>         Log captured LDAP bind passwords at debug level (Default: true)");
            Console.WriteLine();
            Console.WriteLine("Credentials: omit all three to use the current Windows session, or supply all three.");
            Console.WriteLine("  -u,  --username <user>             Username to authenticate to ADWS");
            Console.WriteLine("  -p,  --password <pass>             Password to authenticate to ADWS");
            Console.WriteLine("  -D,  --domain <domain>             Domain to authenticate to ADWS");
            Console.WriteLine("  -h,  --help                        Show this help message");
            Console.WriteLine();
        }
    }
}