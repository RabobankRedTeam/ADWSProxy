using log4net;
using Microsoft.Extensions.Configuration;
using Newtonsoft.Json;
using System.Net;
using System.Text.RegularExpressions;
using TestClient;

ILog log = LogManager.GetLogger(typeof(Program));

LoggerConfig.InitializeProgrammaticLogging();
log.Info($"Starting TestClient v{AppInfo.GetVersion()}");

if (args.Any(a => a.Equals("--help", StringComparison.OrdinalIgnoreCase) || a.Equals("-h", StringComparison.OrdinalIgnoreCase)))
{
    CommandLineOptions.ShowHelp();
    return;
}

// Boolean switches work bare (-c) as well as with a value (-c true / -c false): the configuration binder needs a
// value, so supply "true" when a bool switch is last or directly followed by another switch.
string[] booleanSwitches = ["-c", "--writecredentials", "-pause", "--pausebetweenengines", "--logpasswords", "--mergecredentials"];
var normalizedArgs = new List<string>(args.Length + 2);
for (int i = 0; i < args.Length; i++)
{
    normalizedArgs.Add(args[i]);
    if (booleanSwitches.Contains(args[i], StringComparer.OrdinalIgnoreCase) &&
        (i + 1 >= args.Length || args[i + 1].StartsWith('-')))
    {
        normalizedArgs.Add("true");
    }
}

var configuration = new ConfigurationBuilder()
    .AddCommandLine([.. normalizedArgs], new Dictionary<string, string>{
                    { "-f", "testfile" },
                    { "-pause", "pausebetweenengines" },
                    { "-u", "username" },
                    { "-p", "password" },
                    { "-d", "domain" },
                    { "-g", "generate" },
                    { "-o", "output" },
                    { "-e", "engines" },
                    { "-c", "writecredentials" }
    })
    .Build();

var options = new CommandLineOptions();
try
{
    configuration.Bind(options);
}
catch (InvalidOperationException ex)
{
    log.Error($"Invalid command line arguments: {ex.InnerException?.Message ?? ex.Message} Use --help for usage.");
    return;
}

// Credentials come only from the CLI (-u/-p/-d), so they can be resolved before any tests JSON is read
// and are available to generate mode, which reads no file.
NetworkCredential? credentials = null;
bool anyCredentialProvided = !string.IsNullOrWhiteSpace(options.Username) || !string.IsNullOrWhiteSpace(options.Password) || !string.IsNullOrWhiteSpace(options.Domain);
bool allCredentialsProvided = !string.IsNullOrWhiteSpace(options.Username) && !string.IsNullOrWhiteSpace(options.Password) && !string.IsNullOrWhiteSpace(options.Domain);
if (anyCredentialProvided)
{
    if (allCredentialsProvided)
    {
        credentials = new NetworkCredential(options.Username, options.Password, options.Domain);
    }
    else if (options.MergeCredentials)
    {
        // Partial CLI credentials are kept so the missing fields can be filled from the tests JSON per query.
        credentials = new NetworkCredential(options.Username ?? string.Empty, options.Password ?? string.Empty, options.Domain ?? string.Empty);
    }
    else
    {
        log.Error("Incomplete credentials provided. All of Username, Password, and Domain must be provided together, or pass --mergecredentials to complete them from the tests JSON. If the goal is to use the current user's credentials, please do not provide any credential arguments.");
        return;
    }
}

// Generate mode is fully CLI-driven: discover the forest from the -g server and write the forest tests
// JSON, reading nothing from a tests file.
if (!string.IsNullOrWhiteSpace(options.Generate))
{
    // Generate reads no tests JSON, so there is nothing to merge a partial CLI credential with.
    if (anyCredentialProvided && !allCredentialsProvided)
    {
        log.Error("Generate mode cannot merge credentials (there is no tests JSON to merge with). Provide all of -u/-p/-d, or none to use the Windows session.");
        return;
    }

    List<string> generateEngines = string.IsNullOrWhiteSpace(options.Engines)
        ? ["ADWS", "LDAP", "LDAPS"]
        : [.. options.Engines.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)];
    string outputPath = string.IsNullOrWhiteSpace(options.Output)
        ? Path.Combine(Directory.GetCurrentDirectory(), "forest.tests.json")
        : options.Output;

    ProgramHelpers.GenerateForestConfig(options.Generate, generateEngines, outputPath, credentials, options.WriteCredentials, options.LogPasswords);
    return;
}

if (string.IsNullOrWhiteSpace(options.TestFile))
{
    options.TestFile = Path.Combine(Directory.GetCurrentDirectory(), "tests.json");
    log.Info($"No JSON file path provided. Using default: {options.TestFile}");
}

if (!File.Exists(options.TestFile))
{
    log.Error($"JSON configuration file not found at path: {options.TestFile}");
    return;
}
string jsonString = File.ReadAllText(options.TestFile);
if (string.IsNullOrWhiteSpace(jsonString))
{
    log.Error("JSON configuration file is empty");
    return;
}

if (jsonString.Contains("{{DOMAIN_DN}}"))
{
    log.Info("Found {{DOMAIN_DN}} placeholder in JSON. Attempting to calculate base DN from current environment");

    string? currentDnsDomain = options.Domain ?? Environment.GetEnvironmentVariable("USERDNSDOMAIN");
    if (string.IsNullOrWhiteSpace(currentDnsDomain))
    {
        log.Error("Current DNS domain is empty. {{DOMAIN_DN}} placeholder can not be replaced");
        return;
    }
    var baseDN = string.Join(",", currentDnsDomain.Split('.').Select(part => $"DC={part.ToUpperInvariant()}"));
    log.Info("Calculated base DN: " + baseDN);
    jsonString = jsonString.Replace("{{DOMAIN_DN}}", baseDN);
}

if (jsonString.Contains("{{LOGONSERVER}}"))
{
    string? currentLogonServer = Environment.GetEnvironmentVariable("LOGONSERVER");
    if (string.IsNullOrWhiteSpace(currentLogonServer))
    {
        log.Error("Current LOGONSERVER is empty. {{LOGONSERVER}} placeholder can not be replaced");
        return;
    }
    while (currentLogonServer.StartsWith("\\\\", StringComparison.Ordinal))
    {
        currentLogonServer = currentLogonServer[2..];
    }
    log.Info("Replacing {{LOGONSERVER}} placeholder with current logonserver: " + currentLogonServer);
    jsonString = jsonString.Replace("{{LOGONSERVER}}", currentLogonServer);
}

if (jsonString.Contains("{{USERNAME}}"))
{
    string currentUsername = options.Username ?? Environment.UserName;
    if (string.IsNullOrWhiteSpace(currentUsername))
    {
        log.Error("Current username is empty. {{USERNAME}} placeholder can not be replaced");
        return;
    }
    log.Info("Replacing {{USERNAME}} placeholder with current username: " + currentUsername);
    jsonString = jsonString.Replace("{{USERNAME}}", currentUsername);
}

// The tests file may carry Credentials blocks. Unless --logpasswords is set, log it with each non-empty
// password value masked so the input is still traceable without the secret reaching trace.log.
log.Debug(options.LogPasswords
    ? jsonString
    : Regex.Replace(jsonString, "(\"Password\"\\s*:\\s*\")(?:[^\"\\\\]|\\\\.)+(\")", "$1***$2", RegexOptions.IgnoreCase));

BenchmarkConfig? config = JsonConvert.DeserializeObject<BenchmarkConfig>(
    jsonString,
    new JsonSerializerSettings()
);

ProgramHelpers.ExecuteTests(config, options.PauseBetweenEngines, credentials, options.MergeCredentials);
