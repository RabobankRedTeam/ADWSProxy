using log4net;
using System.Diagnostics;
using System.Net;

namespace TestClient
{
    internal static class ProgramHelpers
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(ProgramHelpers));

        internal static void ExecuteTests(BenchmarkConfig? config, bool pauseBetweenEngines, NetworkCredential? credential = null)
        {
            if (config == null || config.Queries == null)
            {
                log.Error("Failed to parse configuration file");
                return;
            }

            foreach (var test in config.Queries)
            {
                var startTime = DateTime.Now;
                log.Info($"Loaded Test Case: {test.Name}");
                log.Info($"  Target OU: {test.TargetOU}");
                log.Info($"  Filter: {test.Filter}");
                log.Info($"  Scope: {test.Scope}");
                log.Info($"  Attributes: {string.Join(", ", test.Attributes)}");
                log.Info($"  Engines: {string.Join(", ", test.Engines)}");
                log.Info($"  Starttime: {startTime:yyyy-MM-ddTHH:mm:ss}");
                log.Info("-----------------------------");

                List<ResultHolder>? ldapResults = null, ldapsResults = null, ldapGcResults = null, ldapsGcResults = null, adwsResults = null, adwsGcResults = null;
                long? ldapTime = null, ldapsTime = null, ldapGcTime = null, ldapsGcTime = null, adwsTime = null, adwsGcTime = null;

                var adwsHelper = new ADWSHelpers(config.Server, 389, credential);
                var adwsGcHelper = new ADWSHelpers(config.Server, 3268, credential);

                var ldapHelper = new LDAPHelpers(config.Server, 389, credential, secure: false);
                var ldapsHelper = new LDAPHelpers(config.Server, 636, credential, secure: true);
                var ldapGcHelper = new LDAPHelpers(config.Server, 3268, credential, secure: false);
                var ldapsGcHelper = new LDAPHelpers(config.Server, 3269, credential, secure: true);
                foreach (var engine in test.Engines)
                {
                    if (pauseBetweenEngines)
                    {
                        log.Info($"Pausing before next test ('{test.Name}' using engine '{engine}'). Press any key to continue...");
                        Console.ReadKey();
                    }

                    log.Info($"Executing test '{test.Name}' on engine '{engine}'");

                    try
                    {
                        var stopwatch = Stopwatch.StartNew();
                        switch (engine.ToLowerInvariant())
                        {
                            case "ldap":
                                ldapResults = ldapHelper.ExecuteLdap(test.TargetOU, test.Filter, test.Scope, test.Attributes);
                                stopwatch.Stop();
                                ldapTime = stopwatch.ElapsedMilliseconds;
                                break;
                            case "ldaps":
                                ldapsResults = ldapsHelper.ExecuteLdap(test.TargetOU, test.Filter, test.Scope, test.Attributes);
                                stopwatch.Stop();
                                ldapsTime = stopwatch.ElapsedMilliseconds;
                                break;
                            case "ldap-gc":
                                ldapGcResults = ldapGcHelper.ExecuteLdap(test.TargetOU, test.Filter, test.Scope, test.Attributes);
                                stopwatch.Stop();
                                ldapGcTime = stopwatch.ElapsedMilliseconds;
                                break;
                            case "ldaps-gc":
                                ldapsGcResults = ldapsGcHelper.ExecuteLdap(test.TargetOU, test.Filter, test.Scope, test.Attributes);
                                stopwatch.Stop();
                                ldapsGcTime = stopwatch.ElapsedMilliseconds;
                                break;
                            case "adws":
                                adwsResults = adwsHelper.ExecuteAdws(test.TargetOU, test.Filter, test.Scope, test.Attributes);
                                stopwatch.Stop();
                                adwsTime = stopwatch.ElapsedMilliseconds;
                                break;
                            case "adws-gc":
                                adwsGcResults = adwsGcHelper.ExecuteAdws(test.TargetOU, test.Filter, test.Scope, test.Attributes);
                                stopwatch.Stop();
                                adwsGcTime = stopwatch.ElapsedMilliseconds;
                                break;

                            default:
                                log.Warn($"Unknown engine '{engine}' specified for test '{test.Name}'. Skipping");
                                continue;
                        }
                    }
                    catch (Exception ex)
                    {
                        log.Error($"  Error executing test '{test.Name}' on engine '{engine}'", ex);
                    }
                }

                if (ldapResults != null)
                    log.Info($"  Results: {ldapResults} entries returned for LDAP in {ldapTime} ms");
                if (ldapsResults != null)
                    log.Info($"  Results: {ldapsResults} entries returned for LDAPS in {ldapsTime} ms");
                if (ldapGcResults != null)
                    log.Info($"  Results: {ldapGcResults} entries returned for LDAP-GC in {ldapGcTime} ms");
                if (ldapsGcResults != null)
                    log.Info($"  Results: {ldapsGcResults} entries returned for LDAPS-GC in {ldapsGcTime} ms");
                if (adwsResults != null)
                    log.Info($"  Results: {adwsResults} entries returned for ADWS in {adwsTime} ms");
                if (adwsGcResults != null)
                    log.Info($"  Results: {adwsGcResults} entries returned for ADWS-GC in {adwsGcTime} ms");

                try
                {
                    // Create an object to hold the results for this test case and write it to a JSON file
                    var allResults = new
                    {
                        TestName = test.Name,
                        startTime,
                        test.TargetOU,
                        test.Filter,
                        test.Scope,
                        test.Attributes,
                        test.Engines,
                        Results = new
                        {
                            LDAP = ldapResults != null ? new { Values = ldapResults, TimeMs = ldapTime } : null,
                            LDAPS = ldapsResults != null ? new { Values = ldapsResults, TimeMs = ldapsTime } : null,
                            LDAP_GC = ldapGcResults != null ? new { Values = ldapGcResults, TimeMs = ldapGcTime } : null,
                            LDAPS_GC = ldapsGcResults != null ? new { Values = ldapsGcResults, TimeMs = ldapsGcTime } : null,
                            ADWS = adwsResults != null ? new { Values = adwsResults, TimeMs = adwsTime } : null,
                            ADWS_GC = adwsGcResults != null ? new { Values = adwsGcResults, TimeMs = adwsGcTime } : null
                        }
                    };
                    var resultsJson = System.Text.Json.JsonSerializer.Serialize(allResults, new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
                    var fileName = $"{startTime:yyyyMMddhhmmss}_{test.Name}_results.json";
                    File.WriteAllText(fileName, resultsJson);
                    log.Info($"  Results written to file: {fileName}");
                }
                catch (Exception ex)
                {
                    log.Error($"  Error writing results for test '{test.Name}' to file", ex);
                }

                log.Info($"Finished test '{test.Name}'");
                log.Info("-----------------------------");
            }
        }
    }
}