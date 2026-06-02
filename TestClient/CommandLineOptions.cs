namespace TestClient
{
    internal class CommandLineOptions
    {
        public string TestFile { get; set; } = "./tests.json";
        public bool PauseBetweenEngines { get; set; } = false;

        public string? Username { get; set; } = null;
        public string? Password { get; set; } = null;
        public string? Domain { get; set; } = null;

        public static void ShowHelp()
        {
            Console.WriteLine("ADWS/LDAP Test Client Options:");
            Console.WriteLine("  -f,     --testfile             Path to the configuration tests JSON (Default: ./tests.json)");
            Console.WriteLine("  -pause, --pausebetweenengines  If true, pauses for user input between tests (Default: false)");
            Console.WriteLine("  -h,     --help                 Show this help dialog");
            Console.WriteLine("  -u,     --username             Username for authentication");
            Console.WriteLine("  -p,     --password             Password for authentication");
            Console.WriteLine("  -d,     --domain               Domain for authentication");
        }
    }
}
