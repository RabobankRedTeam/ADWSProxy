using log4net;
using Newtonsoft.Json;
using System.Diagnostics;
using System.Net;

namespace TestClient
{
    internal static class ProgramHelpers
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(ProgramHelpers));

        public static void SaveResultsInChunks<T>(string baseFileName, string engineName, string targetOU, List<T>? results, DateTime? engineStartTime, long timeMs, LdapQueryTest test, int chunkSize = 50000)
        {
            if (results == null || results.Count == 0)
            {
                return;
            }


            int totalObjects = results.Count;
            int chunkIndex = 1;

            var formatting = Formatting.Indented;
            if (totalObjects > 500)
            {
                formatting = Formatting.None;
            }

            for (int i = 0; i < totalObjects; i += chunkSize)
            {
                int currentChunkSize = Math.Min(chunkSize, totalObjects - i);
                List<T> chunkList = results.GetRange(i, currentChunkSize);

                string chunkFileName = $"{baseFileName}_{engineName}_{targetOU}_part{chunkIndex}.json";
                chunkFileName = string.Join("_", chunkFileName.Split(Path.GetInvalidFileNameChars()));

                var chunkPayload = new
                {
                    Engine = engineName,
                    test,
                    targetOU,
                    engineStartTime,
                    Chunk = chunkIndex,
                    TotalChunks = (int)Math.Ceiling((double)totalObjects / chunkSize),
                    TimeMs = timeMs,
                    chunkList.Count,
                    Values = chunkList,
                    Version = AppInfo.GetVersion()
                };

                using (StreamWriter sw = new(chunkFileName))
                {
                    using JsonTextWriter jw = new(sw) { Formatting = formatting };
                    new JsonSerializer().Serialize(jw, chunkPayload);
                }

                chunkList.Clear();
                chunkIndex++;
            }
        }

        private static IEnumerable<string> ResolveTargetOUs(BenchmarkConfig config, string engine, IEnumerable<string> targetOUs, NetworkCredential? credential)
        {
            foreach (var targetOU in targetOUs)
            {
                string? filterDomain = null;
                bool resolveViaRootDSE = false;
                if (targetOU.Contains("{{allContexts}}"))
                {
                    resolveViaRootDSE = true;
                }
                else if (targetOU.Contains("{{allContexts:"))
                {
                    filterDomain = targetOU.Substring("{{allContexts:".Length, targetOU.Length - "{{allContexts:".Length - 2);
                    resolveViaRootDSE = true;
                }

                if (resolveViaRootDSE)
                {
                    log.Info($"Resolving all contexts {(string.IsNullOrWhiteSpace(filterDomain) ? null : $"for: {filterDomain}")}");
                    var resolvedOUs = ResolveAllContexts(config.Server, engine, credential);
                    foreach (var resolvedOU in resolvedOUs)
                    {
                        if (string.IsNullOrWhiteSpace(filterDomain))
                        {
                            yield return resolvedOU;
                        }
                        else
                        {
                            if (resolvedOU.EndsWith(filterDomain, StringComparison.InvariantCultureIgnoreCase))
                            {
                                log.Debug($"Resolved context '{resolvedOU}' matches filter '{filterDomain}'");
                                yield return resolvedOU;
                            }
                            else
                            {
                                log.Debug($"Resolved context '{resolvedOU}' does not match filter '{filterDomain}'");
                            }
                        }
                    }

                }
                else
                {
                    yield return targetOU;
                }
            }
        }

        private static IEnumerable<string> ResolveAllContexts(string server, string engine, NetworkCredential? credential)
        {
            var normalizedEngine = engine.ToLowerInvariant();
            var (port, secure, isAdws, isGc) = normalizedEngine switch
            {
                "ldap" => (389, false, false, false),
                "ldaps" => (636, true, false, false),
                "ldap-gc" => (3268, false, false, true),
                "ldaps-gc" => (3269, true, false, true),
                "adws" => (389, false, true, false),
                "adws-gc" => (3268, false, true, true),
                _ => (-1, false, false, false)
            };

            if (port == -1)
            {
                log.Warn($"Unknown engine '{engine}' specified for resolving contexts. Returning empty list.");
                yield break;
            }

            var contexts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            string? configContext = null;
            string? defaultDomainContext = null;

            IEnumerable<ResultHolder> ExecuteSearch(string baseDn, string filter, string scope, List<string> attributes)
            {
                if (isAdws)
                {
                    var adwsHelper = new ADWSHelpers(server, port, credential);
                    return adwsHelper.ExecuteAdws(baseDn, filter, scope, attributes);
                }

                var ldapHelper = new LDAPHelpers(server, port, credential, secure);
                return ldapHelper.ExecuteLdap(baseDn, filter, scope, attributes);
            }

            static bool IsAppDirectoryPartition(string dn)
            {
                return dn.StartsWith("DC=DomainDnsZones", StringComparison.OrdinalIgnoreCase) ||
                       dn.StartsWith("DC=ForestDnsZones", StringComparison.OrdinalIgnoreCase);
            }

            // Exact check for built-in AD system crossRef objects that are not domain partitions
            static bool IsBuiltInSystemPartition(string cn)
            {
                return cn.Equals("Enterprise Configuration", StringComparison.OrdinalIgnoreCase) ||
                       cn.Equals("Enterprise Schema", StringComparison.OrdinalIgnoreCase) ||
                       cn.Equals("Enterprise-Configuration", StringComparison.OrdinalIgnoreCase) ||
                       cn.Equals("Enterprise-Schema", StringComparison.OrdinalIgnoreCase);
            }

            // 1. Query RootDSE for local namingContexts + configuration & default domain paths
            foreach (var result in ExecuteSearch(string.Empty, "(objectClass=*)", "Base", ["namingContexts", "configurationNamingContext", "defaultNamingContext"]))
            {
                foreach (var attr in result.Attributes)
                {
                    if (attr.Key.Equals("namingContexts", StringComparison.OrdinalIgnoreCase))
                    {
                        foreach (string context in attr.Value)
                        {
                            if (isGc && IsAppDirectoryPartition(context))
                            {
                                continue;
                            }
                            contexts.Add(context);
                        }
                    }
                    else if (attr.Key.Equals("configurationNamingContext", StringComparison.OrdinalIgnoreCase))
                    {
                        foreach (string configDn in attr.Value)
                        {
                            configContext = configDn;
                        }
                    }
                    else if (attr.Key.Equals("defaultNamingContext", StringComparison.OrdinalIgnoreCase))
                    {
                        foreach (string defaultDn in attr.Value)
                        {
                            defaultDomainContext = defaultDn;
                        }
                    }
                }
            }

            // 2. Query CN=Partitions for cross-domain NCs (subdomains like mini2025)
            if (!string.IsNullOrEmpty(configContext))
            {
                string partitionsDn = $"CN=Partitions,{configContext}";
                string crossRefFilter = "(objectClass=crossRef)";

                foreach (var result in ExecuteSearch(partitionsDn, crossRefFilter, "Subtree", ["nCName", "cn"]))
                {
                    string? ncNameVal = null;
                    string? cnVal = null;

                    foreach (var attr in result.Attributes)
                    {
                        if (attr.Key.Equals("nCName", StringComparison.OrdinalIgnoreCase))
                        {
                            ncNameVal = attr.Value.FirstOrDefault();
                        }
                        else if (attr.Key.Equals("cn", StringComparison.OrdinalIgnoreCase))
                        {
                            cnVal = attr.Value.FirstOrDefault();
                        }
                    }

                    // Path A: Direct nCName available (Standard LDAP / ADWS)
                    if (!string.IsNullOrEmpty(ncNameVal))
                    {
                        if (isGc && IsAppDirectoryPartition(ncNameVal))
                        {
                            continue;
                        }
                        contexts.Add(ncNameVal);
                    }
                    // Path B: Fallback for GC queries where nCName is omitted by AD.
                    // Exclude GUID RDNs, exact built-in system partition names, and root domain self-matches.
                    else if (!string.IsNullOrEmpty(cnVal) &&
                             !string.IsNullOrEmpty(defaultDomainContext) &&
                             !Guid.TryParse(cnVal, out _) &&
                             !IsBuiltInSystemPartition(cnVal) &&
                             !defaultDomainContext.StartsWith($"DC={cnVal},", StringComparison.OrdinalIgnoreCase) &&
                             !defaultDomainContext.Equals($"DC={cnVal}", StringComparison.OrdinalIgnoreCase))
                    {
                        string constructedDn = $"DC={cnVal},{defaultDomainContext}";

                        if (isGc && IsAppDirectoryPartition(constructedDn))
                        {
                            continue;
                        }
                        contexts.Add(constructedDn);
                    }
                }
            }

            log.Info($"Resolved contexts for engine '{engine}': {string.Join(", ", contexts)}");
            foreach (var context in contexts)
            {
                yield return context;
            }
        }

        internal static void ExecuteTests(BenchmarkConfig? config, bool pauseBetweenEngines, NetworkCredential? credential = null)
        {
            if (config == null || config.Queries == null)
            {
                log.Error("Failed to parse configuration file");
                return;
            }

            foreach (var test in config.Queries)
            {
                test.StartTime = DateTime.Now;
                log.Info($"Loaded Test Case: {test.Name}");
                log.Info($"  Target OUs: {string.Join(',', test.TargetOUs)}");
                log.Info($"  Filter: {test.Filter}");
                log.Info($"  Scope: {test.Scope}");
                log.Info($"  Attributes: {string.Join(", ", test.Attributes)}");
                log.Info($"  Engines: {string.Join(", ", test.Engines)}");
                log.Info($"  Starttime: {test.StartTime:yyyy-MM-ddTHH:mm:ss}");
                log.Info("-----------------------------");

                int ldapResultCount = 0, ldapsResultCount = 0, ldapGcResultCount = 0, ldapsGcResultCount = 0, adwsResultCount = 0, adwsGcResultCount = 0;

                var adwsHelper = new ADWSHelpers(config.Server, 389, credential);
                var adwsGcHelper = new ADWSHelpers(config.Server, 3268, credential);

                var ldapHelper = new LDAPHelpers(config.Server, 389, credential, secure: false);
                var ldapsHelper = new LDAPHelpers(config.Server, 636, credential, secure: true);
                var ldapGcHelper = new LDAPHelpers(config.Server, 3268, credential, secure: false);
                var ldapsGcHelper = new LDAPHelpers(config.Server, 3269, credential, secure: true);

                foreach (var engine in test.Engines)
                {
                    foreach (var targetOU in ResolveTargetOUs(config, engine, test.TargetOUs, credential))
                    {
                        if (pauseBetweenEngines)
                        {
                            log.Info($"Pausing before next test ('{test.Name}' using engine '{engine}' and target OU '{targetOU}'). Press any key to continue...");
                            Console.ReadKey();
                        }

                        log.Info($"Executing test '{test.Name}' on target OU '{targetOU}' on engine '{engine}'");

                        try
                        {
                            List<ResultHolder>? engineResult = null;

                            var stopwatch = Stopwatch.StartNew();
                            var engineStartTime = DateTime.Now;
                            switch (engine.ToLowerInvariant())
                            {
                                case "ldap":
                                    engineResult = ldapHelper.ExecuteLdap(targetOU, test.Filter, test.Scope, test.Attributes);
                                    ldapResultCount += engineResult.Count;
                                    break;
                                case "ldaps":
                                    engineResult = ldapsHelper.ExecuteLdap(targetOU, test.Filter, test.Scope, test.Attributes);
                                    ldapsResultCount += engineResult.Count;
                                    break;
                                case "ldap-gc":
                                    engineResult = ldapGcHelper.ExecuteLdap(targetOU, test.Filter, test.Scope, test.Attributes);
                                    ldapGcResultCount += engineResult.Count;
                                    break;
                                case "ldaps-gc":
                                    engineResult = ldapsGcHelper.ExecuteLdap(targetOU, test.Filter, test.Scope, test.Attributes);
                                    ldapsGcResultCount += engineResult.Count;
                                    break;
                                case "adws":
                                    engineResult = adwsHelper.ExecuteAdws(targetOU, test.Filter, test.Scope, test.Attributes);
                                    adwsResultCount += engineResult.Count;
                                    break;
                                case "adws-gc":
                                    engineResult = adwsGcHelper.ExecuteAdws(targetOU, test.Filter, test.Scope, test.Attributes);
                                    adwsGcResultCount += engineResult.Count;
                                    break;

                                default:
                                    log.Warn($"Unknown engine '{engine}' specified for test '{test.Name}'. Skipping");
                                    continue;
                            }

                            stopwatch.Stop();
                            log.Info($"  Results: {engineResult.Count} entries returned for {engine} in {stopwatch.ElapsedMilliseconds} ms");
                            SaveResultsInChunks($"{test.StartTime:yyyyMMddHHmmss}_{test.Name}", engine.ToLowerInvariant(), targetOU, engineResult, engineStartTime, stopwatch.ElapsedMilliseconds, test);

                            engineResult.Clear();
                            engineResult = null;
                            GC.Collect(0, GCCollectionMode.Optimized);
                        }
                        catch (Exception ex)
                        {
                            log.Error($"  Error executing test '{test.Name}' on engine '{engine}'", ex);
                        }


                        log.Info($"Finished test '{test.Name}'");
                        log.Info("-----------------------------");

                    }
                }
            }
        }
    }
}