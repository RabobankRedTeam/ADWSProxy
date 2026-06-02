using log4net;
using Microsoft.Extensions.Configuration;
using System.Net;
using System.Text.Json;
using TestClient;

ILog log = LogManager.GetLogger(typeof(Program));

LoggerConfig.InitializeProgrammaticLogging();

if (args.Any(a => a.Equals("--help", StringComparison.OrdinalIgnoreCase) || a.Equals("-h", StringComparison.OrdinalIgnoreCase)))
{
    CommandLineOptions.ShowHelp();
    return;
}

var configuration = new ConfigurationBuilder()
    .AddCommandLine(args, new Dictionary<string, string>{
                    { "-f", "testfile" },
                    { "-pause", "pausebetweenengines" },
                    { "-u", "username" },
                    { "-p", "password" },
                    { "-d", "domain" }
    })
    .Build();

var options = new CommandLineOptions();
configuration.Bind(options);

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

NetworkCredential? credentials = null;
if (!string.IsNullOrWhiteSpace(options.Username) && !string.IsNullOrWhiteSpace(options.Password) && !string.IsNullOrWhiteSpace(options.Domain))
{
    if (string.IsNullOrWhiteSpace(options.Username) && string.IsNullOrWhiteSpace(options.Password) && string.IsNullOrWhiteSpace(options.Domain))
    {
        log.Error("Incomplete credentials provided. All of Username, Password, and Domain must be provided to replace placeholders. If the goal is to use the current user's credentials, please do not provide any credential arguments.");
        return;
    }
    else
    {
        credentials = new NetworkCredential(options.Username, options.Password, options.Domain);
    }
}

log.Debug(jsonString);

BenchmarkConfig? config = JsonSerializer.Deserialize<BenchmarkConfig>(
    jsonString,
    new JsonSerializerOptions() { PropertyNameCaseInsensitive = true }
);
ProgramHelpers.ExecuteTests(config, options.PauseBetweenEngines, credentials);
