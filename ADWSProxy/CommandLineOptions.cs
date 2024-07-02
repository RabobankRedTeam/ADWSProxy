using CommandLine;
using System.Net;

namespace ADWSProxy
{
    internal class CommandLineOptions
    {
        [Option("adwsdcport", Required = false, Default = 9389, HelpText = "The ADWS port to proxy to on the domain controller")]
        public int ADWSDCPort { get; set; }

        [Option("adwsgcport", Required = false, Default = 9389, HelpText = "The ADWS port to proxy to on the global catalog")]
        public int ADWSGCPort { get; set; }

        [Option("consoleloglevel", Required = false, Default = "INFO", HelpText = "Set the log level for the console output")]
        public string ConsoleLogLevel { get; set; }

        [Option("dnsport", Required = false, Default = 53, HelpText = "The DNS port to proxy from")]
        public int DnsPort { get; set; }

        [Option('D', "domain", Required = false, Default = null, HelpText = "The domain to authenticate to ADWS")]
        public string Domain { get; set; }

        [Option("domaincontroller", Required = true, HelpText = "The domain controller to proxy to")]
        public string DomainController { get; set; }

        [Option("exitondnsstarterror", Required = false, Default = true, HelpText = "Exit the application if the DNS port is already in use")]
        public bool? ExitOnDNSStartError { get; set; }

        [Option("gcinstance", Required = false, Default = "ldap:3268", HelpText = "The GC instance within ADWS")]
        public string GCInstance { get; set; }

        [Option("gcport", Required = false, Default = (ushort)3268, HelpText = "The GC port to proxy from")]
        public ushort GCPort { get; set; }

        [Option("globalcatalog", Required = false, HelpText = "The global catalog to proxy to")]
        public string GlobalCatalog { get; set; }

        [Option("ldapinstance", Required = false, Default = "ldap:389", HelpText = "The LDAP instance within ADWS")]
        public string LDAPInstance { get; set; }

        [Option("ldapport", Required = false, Default = (ushort)389, HelpText = "The LDAP port to proxy from")]
        public ushort LDAPPort { get; set; }

        [Option("logdirectory", Required = false, Default = ".", HelpText = "The log directory to output runtime logs. Defaults to the current working directory.")]
        public string LogDirectory { get; set; }

        [Option('p', "password", Required = false, Default = null, HelpText = "The password to authenticate to ADWS")]
        public string Password { get; set; }

        [Option('u', "username", Required = false, Default = null, HelpText = "The username to authenticate to ADWS")]
        public string Username { get; set; }

        [Option("usewindowsauth", Required = false, Default = true, HelpText = "Use Windows Authentication (default) or Username/Password with TLS")]
        public bool? UseWindowsAuth { get; set; }

        public NetworkCredential GetNetworkCredential()
        {
            if (Username == null && Password == null && Domain == null) return null;

            if (Username == null || Password == null || Domain == null) throw new System.ArgumentException("Username, Password and Domain all need to be used when one value is entered");

            return new NetworkCredential(Username, Password, Domain);
        }
    }
}