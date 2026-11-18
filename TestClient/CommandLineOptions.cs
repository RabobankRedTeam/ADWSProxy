namespace TestClient
{
    internal class CommandLineOptions
    {
        public string TestFile { get; set; } = "./tests.json";
        public bool PauseBetweenEngines { get; set; } = false;
        // Default true. When false, passwords are kept out of outputs: the tests JSON is still logged at debug
        // level but with its password values masked, and generate's -c writes credentials with an empty password.
        public bool LogPasswords { get; set; } = true;

        public string? Username { get; set; } = null;
        public string? Password { get; set; } = null;
        public string? Domain { get; set; } = null;
        // When true, missing fields in a JSON Credentials block (per-query or config-level) are filled from the
        // CLI -u/-p/-d per field, so e.g. the password can come from the CLI and the username/domain from the
        // JSON. Default false: each source is used whole or not at all. A merge is logged as a warning.
        public bool MergeCredentials { get; set; } = false;

        // Generate mode: the server to discover the forest from. When set, the program runs discovery and
        // writes a forest tests file, then exits; it reads nothing from the tests JSON.
        public string? Generate { get; set; } = null;
        // Generate mode: where to write the generated forest tests JSON (default ./forest.tests.json).
        public string? Output { get; set; } = null;
        // Generate mode: comma-separated engines stamped onto every generated query (default ADWS,LDAP,LDAPS).
        public string? Engines { get; set; } = null;
        // Generate mode: when true, write the CLI credentials (-u/-p/-d) into the generated file so it can be
        // run without re-supplying them. Off by default so no secret is persisted to disk.
        public bool WriteCredentials { get; set; } = false;

        public static void ShowHelp()
        {
            Console.WriteLine("ADWS/LDAP Test Client Options:");
            Console.WriteLine("  -f,     --testfile             Path to the configuration tests JSON (Default: ./tests.json)");
            Console.WriteLine("  -pause, --pausebetweenengines  Pause for a key press before each test (Default: false)");
            Console.WriteLine("          --logpasswords         Allow passwords in outputs (Default: true). When false, the tests");
            Console.WriteLine("                                 JSON is logged with password values masked, and generate's -c writes");
            Console.WriteLine("                                 credentials with an empty password.");
            Console.WriteLine("  -h,     --help                 Show this help dialog");
            Console.WriteLine("  -u,     --username             Username for authentication");
            Console.WriteLine("  -p,     --password             Password for authentication");
            Console.WriteLine("  -d,     --domain               Domain for authentication");
            Console.WriteLine("          --mergecredentials     Supply all of -u/-p/-d, or none to use the Windows session.");
            Console.WriteLine("                                 Fill missing fields in a tests-file Credentials block from the CLI");
            Console.WriteLine("                                 -u/-p/-d per field (e.g. password from the CLI, user/domain from the");
            Console.WriteLine("                                 JSON). Default false. A merge is logged as a warning.");
            Console.WriteLine();
            Console.WriteLine("Generate mode (fully CLI-driven; no tests JSON is read):");
            Console.WriteLine("  -g,     --generate <server>    Discover the forest partitions and trusts from <server> and write a");
            Console.WriteLine("                                 reviewable forest tests JSON that pins a concrete DC per query, then exit");
            Console.WriteLine("                                 without running. Credentials come from -u/-p/-d (else the Windows session).");
            Console.WriteLine("  -o,     --output <file>        Where to write the generated forest tests JSON (Default: ./forest.tests.json)");
            Console.WriteLine("  -e,     --engines <csv>        Comma-separated engines stamped onto each generated query");
            Console.WriteLine("                                 (Default: ADWS,LDAP,LDAPS). Valid: ADWS, LDAP, LDAPS, ADWS-GC,");
            Console.WriteLine("                                 LDAP-GC, LDAPS-GC. Generate GC and direct files separately.");
            Console.WriteLine("  -c,     --writecredentials     Also write the -u/-p/-d credentials into the generated file so it");
            Console.WriteLine("                                 can be run without re-supplying them (Default: off). The password");
            Console.WriteLine("                                 is stored in plaintext; protect or delete the file afterwards.");
            Console.WriteLine();
            Console.WriteLine("Boolean switches (-pause, -c, --logpasswords, --mergecredentials) can be given bare or with a value.");
        }
    }
}
