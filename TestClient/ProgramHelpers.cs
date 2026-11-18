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

        private static IEnumerable<string> ResolveTargetOUs(string server, string engine, IEnumerable<string> targetOUs, NetworkCredential? credential)
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
                    var resolvedOUs = ResolveAllContexts(server, engine, credential);
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

            // A Global Catalog subtree search crosses naming-context boundaries, so a context under another resolved
            // context (Configuration and child domains under the forest root, Schema under Configuration) would only
            // re-collect the same objects. Keep just the outermost contexts.
            if (isGc)
            {
                var outermost = contexts.Where(c => !contexts.Any(o => c.EndsWith("," + o, StringComparison.OrdinalIgnoreCase))).ToList();
                if (outermost.Count < contexts.Count)
                {
                    log.Info($"Dropped {contexts.Count - outermost.Count} nested context(s) already covered by a Global Catalog subtree search");
                }
                contexts = new HashSet<string>(outermost, StringComparer.OrdinalIgnoreCase);
            }

            log.Info($"Resolved contexts for engine '{engine}': {string.Join(", ", contexts)}");
            foreach (var context in contexts)
            {
                yield return context;
            }
        }

        // Builds a NetworkCredential from a config credential block. Returns false (caller falls back) for
        // a null or empty block; warns and returns false for a partial block; true with the credential only
        // when Username, Password and Domain are all present.
        private static bool TryBuildCredential(Credentials? c, out NetworkCredential? credential)
        {
            credential = null;
            if (c == null
                || string.IsNullOrWhiteSpace(c.Username)
                || string.IsNullOrWhiteSpace(c.Password)
                || string.IsNullOrWhiteSpace(c.Domain))
            {
                return false;
            }
            credential = new NetworkCredential(c.Username, c.Password, c.Domain);
            return true;
        }

        // A credential block is valid only when it is absent/empty (fall back) or fully specified. A
        // partial block (some but not all of Username/Password/Domain) is a configuration error: the
        // caller must abort rather than silently fall back to a different identity. Returns false and
        // logs on an invalid block.
        private static bool ValidateCredentialBlock(Credentials? c, string context)
        {
            if (c == null)
            {
                return true;
            }
            bool hasUser = !string.IsNullOrWhiteSpace(c.Username);
            bool hasPass = !string.IsNullOrWhiteSpace(c.Password);
            bool hasDomain = !string.IsNullOrWhiteSpace(c.Domain);
            if ((hasUser || hasPass || hasDomain) && !(hasUser && hasPass && hasDomain))
            {
                log.Error($"Invalid credentials for {context}: Username, Password and Domain must all be set together, or all be empty to fall back. Aborting.");
                return false;
            }
            return true;
        }

        // Merge mode: pick a field from the highest-precedence source that sets it (per-query JSON -> config
        // JSON -> CLI). Returns the value and a label naming its source, or (null, null) when none set it.
        private static (string? value, string? source) PickField(string? queryVal, string? configVal, string? cliVal)
        {
            if (!string.IsNullOrWhiteSpace(queryVal)) return (queryVal, "query JSON");
            if (!string.IsNullOrWhiteSpace(configVal)) return (configVal, "config JSON");
            if (!string.IsNullOrWhiteSpace(cliVal)) return (cliVal, "CLI");
            return (null, null);
        }

        // Merge mode: compose a credential field-by-field across the sources, keeping each field's source
        // label for the merge warning. A field with no value in any source is null.
        private static (string? User, string? UserSrc, string? Pass, string? PassSrc, string? Domain, string? DomainSrc)
            ComposeCredential(Credentials? queryCreds, Credentials? configCreds, NetworkCredential? cli)
        {
            var (user, userSrc) = PickField(queryCreds?.Username, configCreds?.Username, cli?.UserName);
            var (pass, passSrc) = PickField(queryCreds?.Password, configCreds?.Password, cli?.Password);
            var (domain, domainSrc) = PickField(queryCreds?.Domain, configCreds?.Domain, cli?.Domain);
            return (user, userSrc, pass, passSrc, domain, domainSrc);
        }

        // Credential precedence: per-query JSON creds -> config-level JSON creds -> CLI creds -> Windows
        // session (null). Without merge, each source is used whole or skipped (a null/empty/partial block
        // falls through to the next). With merge, each field is taken from the highest-precedence source that
        // sets it, so e.g. a CLI password completes a username/domain from the JSON; when the result draws on
        // more than one source, mergeWarning describes it. A partial merge is rejected by the up-front
        // validation, so here an incomplete composition means "nothing set" -> Windows session.
        private static NetworkCredential? ResolveCredential(Credentials? queryCreds, Credentials? configCreds, NetworkCredential? cliCredential, bool merge, out string? mergeWarning)
        {
            mergeWarning = null;
            if (!merge)
            {
                if (TryBuildCredential(queryCreds, out var fromQuery))
                {
                    return fromQuery;
                }
                if (TryBuildCredential(configCreds, out var fromConfig))
                {
                    return fromConfig;
                }
                return cliCredential;
            }

            var (user, userSrc, pass, passSrc, domain, domainSrc) = ComposeCredential(queryCreds, configCreds, cliCredential);
            if (user == null || pass == null || domain == null)
            {
                return null;
            }
            if (new HashSet<string>([userSrc!, passSrc!, domainSrc!]).Count > 1)
            {
                mergeWarning = $"Merging credentials (--mergecredentials): username from {userSrc}, password from {passSrc}, domain from {domainSrc}.";
            }
            return new NetworkCredential(user, pass, domain);
        }

        // Runs one search against a given server using the named engine, picking the port/security.
        private static List<ResultHolder> RunSearch(string server, string engine, NetworkCredential? credential, string baseDn, string filter, string scope, List<string> attributes)
        {
            return engine.ToLowerInvariant() switch
            {
                "ldaps" => new LDAPHelpers(server, 636, credential, secure: true).ExecuteLdap(baseDn, filter, scope, attributes),
                "ldap-gc" => new LDAPHelpers(server, 3268, credential, secure: false).ExecuteLdap(baseDn, filter, scope, attributes),
                "ldaps-gc" => new LDAPHelpers(server, 3269, credential, secure: true).ExecuteLdap(baseDn, filter, scope, attributes),
                "adws" => new ADWSHelpers(server, 389, credential).ExecuteAdws(baseDn, filter, scope, attributes),
                "adws-gc" => new ADWSHelpers(server, 3268, credential).ExecuteAdws(baseDn, filter, scope, attributes),
                _ => new LDAPHelpers(server, 389, credential, secure: false).ExecuteLdap(baseDn, filter, scope, attributes),
            };
        }

        // Case-insensitive single-value attribute read (LDAP results use a case-sensitive dictionary).
        private static string? GetAttributeValue(ResultHolder result, string key)
        {
            foreach (var kvp in result.Attributes)
            {
                if (kvp.Key.Equals(key, StringComparison.OrdinalIgnoreCase))
                {
                    return kvp.Value?.FirstOrDefault();
                }
            }
            return null;
        }

        // All values of a (possibly multi-valued) attribute; empty list if absent.
        private static List<string> GetAttributeValues(ResultHolder result, string key)
        {
            foreach (var kvp in result.Attributes)
            {
                if (kvp.Key.Equals(key, StringComparison.OrdinalIgnoreCase))
                {
                    return kvp.Value ?? [];
                }
            }
            return [];
        }

        // True for the Global Catalog engines (ADWS-GC / LDAP-GC / LDAPS-GC).
        private static bool IsGcEngine(string engine) => engine.Contains("-gc", StringComparison.OrdinalIgnoreCase);

        // "DC=corp,DC=com" -> "corp.com" (DC components only); null if there are none.
        private static string? NcToDns(string? nc)
        {
            if (string.IsNullOrWhiteSpace(nc)) return null;
            var parts = nc.Split(',')
                .Select(p => p.Trim())
                .Where(p => p.StartsWith("DC=", StringComparison.OrdinalIgnoreCase))
                .Select(p => p[3..])
                .ToArray();
            return parts.Length == 0 ? null : string.Join(".", parts);
        }

        // "corp.com" -> "DC=corp,DC=com".
        private static string DnsToNc(string dns) =>
            string.Join(",", dns.Split('.', StringSplitOptions.RemoveEmptyEntries).Select(p => $"DC={p}"));

        private static LdapQueryTest MakeForestQuery(string name, string server, string baseDn, List<string> engines, Credentials? credentials = null) => new()
        {
            Name = name,
            Server = server,
            Credentials = credentials,
            TargetOUs = [baseDn],
            Filter = "(objectClass=*)",
            Scope = "Subtree",
            Attributes = ["*"],
            Engines = engines.ToList()
        };

        /// <summary>
        /// Discovers the forest's partitions and trusts from the single configured server and writes a
        /// reviewable tests JSON where each query pins a concrete target DC: a holder of the partition for
        /// direct (ADWS/LDAP/LDAPS) runs, or the initial discovery DC for Global Catalog runs. In-forest
        /// partitions come from CN=Partitions crossRefs; cross-forest/external trusts come from trustedDomain
        /// objects (a separate forest usually needs its own credentials and can be expanded by running
        /// generation again against it). Discovery issues extra queries, but the produced file is inert —
        /// running it only executes the listed queries against the listed servers. Nothing is executed here.
        /// </summary>
        internal static void GenerateForestConfig(string? server, List<string>? engines, string outputPath, NetworkCredential? credential = null, bool includeCredentials = false, bool logPasswords = true)
        {
            if (string.IsNullOrWhiteSpace(server))
            {
                log.Error("Cannot generate forest config: no server was provided (-g/--generate <server>).");
                return;
            }

            if (engines is not { Count: > 0 })
            {
                engines = ["ADWS", "LDAP", "LDAPS"];
            }
            string[] knownEngines = ["ADWS", "LDAP", "LDAPS", "ADWS-GC", "LDAP-GC", "LDAPS-GC"];
            var unknownEngines = engines.Where(e => !knownEngines.Contains(e, StringComparer.OrdinalIgnoreCase)).ToList();
            if (unknownEngines.Count > 0)
            {
                log.Error($"Cannot generate forest config: unknown engine(s) {string.Join(", ", unknownEngines)}. Valid engines: {string.Join(", ", knownEngines)}.");
                return;
            }
            if (engines.Any(IsGcEngine) && !engines.All(IsGcEngine))
            {
                log.Warn("Mixing Global Catalog and direct engines in one file: queries pin a per-partition DC for the direct engines, so the GC engines re-collect overlapping data. Generate GC and direct files separately for a clean GC collection.");
            }
            string discoveryEngine = engines.FirstOrDefault(e => !IsGcEngine(e)) ?? engines.First();

            // Discovery uses the CLI credentials (-u/-p/-d) and otherwise the Windows session.
            var discoveryCredential = ResolveCredential(null, null, credential, merge: false, out _);

            log.Info($"Generating forest test file from server '{server}' using '{discoveryEngine}' for discovery (no queries are executed)...");

            List<ResultHolder> SafeSearch(string baseDn, string filter, string scope, List<string> attrs, string what)
            {
                try
                {
                    return RunSearch(server, discoveryEngine, discoveryCredential, baseDn, filter, scope, attrs);
                }
                catch (Exception ex)
                {
                    log.Warn($"Discovery query for {what} failed on '{server}': {ex.Message}");
                    return [];
                }
            }

            var queries = new List<LdapQueryTest>();
            var seenNc = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            // 1. RootDSE: configuration / default / root-domain naming contexts, plus the DNS host name of
            // the DC we actually connected to (used as the concrete server for Global Catalog queries).
            string? configNc = null, defaultNc = null, rootNc = null, discoveredHost = null;
            foreach (var r in SafeSearch(string.Empty, "(objectClass=*)", "Base", ["configurationNamingContext", "defaultNamingContext", "rootDomainNamingContext", "dnsHostName"], "RootDSE"))
            {
                configNc ??= GetAttributeValue(r, "configurationNamingContext");
                defaultNc ??= GetAttributeValue(r, "defaultNamingContext");
                rootNc ??= GetAttributeValue(r, "rootDomainNamingContext");
                discoveredHost ??= GetAttributeValue(r, "dnsHostName");
            }
            string rootDomainDns = NcToDns(rootNc) ?? server;
            string initialDc = string.IsNullOrWhiteSpace(discoveredHost) ? server : discoveredHost;

            // Global Catalog queries all go to a single initial DC; direct (ADWS/LDAP/LDAPS) queries each go to
            // a DC that actually holds the partition. Enumerate the forest's DCs and the NCs they replicate so
            // every generated query can pin a real server, keeping the produced file inert.
            bool gcRun = engines.All(IsGcEngine);
            Dictionary<string, List<string>> ncToDcs = gcRun ? [] : EnumerateForestDcs(configNc);

            // Resolves the concrete server for a naming context: the initial DC for a GC run, otherwise a DC
            // that holds the NC (preferring the discovery DC), falling back to the NC's DNS name.
            string PickServer(string nc)
            {
                if (gcRun)
                {
                    return initialDc;
                }
                if (ncToDcs.TryGetValue(nc, out var holders) && holders.Count > 0)
                {
                    return holders.Contains(initialDc, StringComparer.OrdinalIgnoreCase) ? initialDc : holders[0];
                }
                return NcToDns(nc) ?? rootDomainDns;
            }

            // Human-readable, unique label per NC (Configuration/Schema named explicitly; others by DNS name).
            string NcLabel(string nc, bool isDomain)
            {
                if (!string.IsNullOrEmpty(configNc))
                {
                    if (nc.Equals(configNc, StringComparison.OrdinalIgnoreCase))
                    {
                        return $"Forest Configuration - {nc}";
                    }
                    if (nc.Equals($"CN=Schema,{configNc}", StringComparison.OrdinalIgnoreCase))
                    {
                        return $"Forest Schema - {nc}";
                    }
                }
                string dns = NcToDns(nc) ?? nc;
                return isDomain ? $"Forest Domain - {dns}" : $"Forest Partition - {dns}";
            }

            // Enumerates DCs under CN=Sites and the NCs each one replicates (msDS-hasMasterNCs), so a direct
            // query can target a DC that actually holds the partition. nTDSDSA carries the NC list; its parent
            // server object carries the dNSHostName.
            Dictionary<string, List<string>> EnumerateForestDcs(string? cfgNc)
            {
                var map = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
                if (string.IsNullOrEmpty(cfgNc))
                {
                    return map;
                }
                string sitesDn = $"CN=Sites,{cfgNc}";

                var serverDnToHost = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                foreach (var r in SafeSearch(sitesDn, "(objectClass=server)", "Subtree", ["dNSHostName"], "forest servers"))
                {
                    string? host = GetAttributeValue(r, "dNSHostName");
                    if (!string.IsNullOrWhiteSpace(host))
                    {
                        serverDnToHost[r.DistinguishedName] = host;
                    }
                }

                foreach (var r in SafeSearch(sitesDn, "(objectClass=nTDSDSA)", "Subtree", ["msDS-hasMasterNCs", "hasMasterNCs"], "forest NTDS settings"))
                {
                    int comma = r.DistinguishedName.IndexOf(',');
                    if (comma < 0)
                    {
                        continue;
                    }
                    string serverDn = r.DistinguishedName[(comma + 1)..];
                    if (!serverDnToHost.TryGetValue(serverDn, out var host))
                    {
                        continue;
                    }
                    var ncs = GetAttributeValues(r, "msDS-hasMasterNCs");
                    if (ncs.Count == 0)
                    {
                        ncs = GetAttributeValues(r, "hasMasterNCs");
                    }
                    foreach (var nc in ncs)
                    {
                        if (string.IsNullOrWhiteSpace(nc))
                        {
                            continue;
                        }
                        if (!map.TryGetValue(nc, out var list))
                        {
                            list = [];
                            map[nc] = list;
                        }
                        if (!list.Contains(host, StringComparer.OrdinalIgnoreCase))
                        {
                            list.Add(host);
                        }
                    }
                }
                return map;
            }

            // Direct engine used to probe a foreign forest's RootDSE (a GC cannot read another forest).
            string probeEngine = engines.FirstOrDefault(e => !IsGcEngine(e)) ?? (discoveryEngine.ToLowerInvariant() switch
            {
                "ldaps-gc" => "LDAPS",
                "adws-gc" => "ADWS",
                _ => "LDAP",
            });

            // Best-effort: read a trusted forest's RootDSE to pin a concrete DC. Returns null (keep the domain
            // name) when the partner is unreachable or needs its own credentials.
            string? ResolvePartnerDc(string partnerDns)
            {
                try
                {
                    foreach (var r in RunSearch(partnerDns, probeEngine, discoveryCredential, string.Empty, "(objectClass=*)", "Base", ["dnsHostName"]))
                    {
                        string? host = GetAttributeValue(r, "dnsHostName");
                        if (!string.IsNullOrWhiteSpace(host))
                        {
                            return host;
                        }
                    }
                }
                catch (Exception ex)
                {
                    log.Warn($"Could not resolve a concrete DC for trusted domain '{partnerDns}': {ex.Message}. Leaving the domain name as Server.");
                }
                return null;
            }

            // 2. In-forest partitions via CN=Partitions crossRefs (nCName + dnsRoot + systemFlags).
            if (!string.IsNullOrEmpty(configNc))
            {
                foreach (var r in SafeSearch($"CN=Partitions,{configNc}", "(objectClass=crossRef)", "Subtree", ["nCName", "systemFlags"], "forest partitions"))
                {
                    string? nc = GetAttributeValue(r, "nCName");
                    if (string.IsNullOrWhiteSpace(nc) || !seenNc.Add(nc))
                    {
                        continue;
                    }
                    int.TryParse(GetAttributeValue(r, "systemFlags"), out int systemFlags);
                    bool isDomain = (systemFlags & 0x00000002) != 0; // FLAG_CR_NTDS_DOMAIN
                    queries.Add(MakeForestQuery(NcLabel(nc, isDomain), PickServer(nc), nc, engines));
                }
            }

            // The server's own domain (defaultNamingContext). CrossRef discovery normally covers it, but
            // a Global Catalog does not replicate the crossRef nCName / dnsRoot that discovery relies on
            // (they come back empty over GC), so add it explicitly when it was not already seen — otherwise
            // a GC-sourced forest file silently omits the forest-root domain.
            if (!string.IsNullOrEmpty(defaultNc) && seenNc.Add(defaultNc))
            {
                queries.Add(MakeForestQuery(NcLabel(defaultNc, true), PickServer(defaultNc), defaultNc, engines));
            }

            // Ensure the Configuration and Schema NCs are present (hosted on the root domain).
            if (!string.IsNullOrEmpty(configNc) && seenNc.Add(configNc))
            {
                queries.Add(MakeForestQuery(NcLabel(configNc, false), PickServer(configNc), configNc, engines));
            }
            if (!string.IsNullOrEmpty(configNc))
            {
                string schemaNc = $"CN=Schema,{configNc}";
                if (seenNc.Add(schemaNc))
                {
                    queries.Add(MakeForestQuery(NcLabel(schemaNc, false), PickServer(schemaNc), schemaNc, engines));
                }
            }

            // 3. Cross-forest / external trusts via trustedDomain objects (in-forest ones are already
            // covered above and de-duplicated here; only genuinely foreign partners are added).
            if (!string.IsNullOrEmpty(defaultNc))
            {
                foreach (var r in SafeSearch($"CN=System,{defaultNc}", "(objectClass=trustedDomain)", "Subtree", ["trustPartner", "trustAttributes", "trustDirection"], "trusts"))
                {
                    string? partner = GetAttributeValue(r, "trustPartner");
                    if (string.IsNullOrWhiteSpace(partner))
                    {
                        continue;
                    }
                    string partnerNc = DnsToNc(partner);
                    if (string.IsNullOrEmpty(partnerNc) || !seenNc.Add(partnerNc))
                    {
                        continue;
                    }

                    int.TryParse(GetAttributeValue(r, "trustAttributes"), out int trustAttributes);
                    bool withinForest = (trustAttributes & 0x00000020) != 0; // TRUST_ATTRIBUTE_WITHIN_FOREST
                    if (withinForest)
                    {
                        // An in-forest domain (e.g. a child) surfaced as a trust. Over a Global Catalog,
                        // crossRef discovery omits its nCName, so this is where such domains are picked up;
                        // emit it as a forest domain served by the normal resolution (the initial GC in a GC
                        // run, a holding DC in a direct run). Direct runs already added it from the crossRef
                        // pass, so the seenNc check above keeps it from being duplicated.
                        queries.Add(MakeForestQuery(NcLabel(partnerNc, true), PickServer(partnerNc), partnerNc, engines));
                        continue;
                    }

                    // Cross-forest / external trust: a Global Catalog cannot read a foreign forest, so resolve
                    // a concrete DC in the partner forest (best effort); keep the domain name when it is
                    // unreachable or needs its own credentials.
                    string partnerServer = ResolvePartnerDc(partner) ?? partner;
                    // Emit an empty credential slot so filling in the foreign forest's account is an
                    // obvious review step. Empty fields still fall back to config/CLI/Windows at run time.
                    var trustCreds = new Credentials { Username = "", Password = "", Domain = "" };
                    queries.Add(MakeForestQuery($"Trusted Domain - {partner} (REVIEW: separate forest usually needs its own credentials; re-run generation against it to expand)", partnerServer, partnerNc, engines, trustCreds));
                }
            }

            // A Global Catalog subtree search crosses naming-context boundaries, so in a GC run a query whose base
            // sits under another query's base on the same server returns nothing new (DC=corp,DC=internal already
            // spans its child domains, Configuration and Schema). Drop those so a GC file collects each object once.
            if (gcRun)
            {
                var covering = queries.Select(q => (q.Server, Base: q.TargetOUs[0])).ToList();
                int removed = queries.RemoveAll(q => covering.Any(c =>
                    string.Equals(c.Server, q.Server, StringComparison.OrdinalIgnoreCase) &&
                    q.TargetOUs[0].EndsWith("," + c.Base, StringComparison.OrdinalIgnoreCase)));
                if (removed > 0)
                {
                    log.Info($"Dropped {removed} Global Catalog quer{(removed == 1 ? "y" : "ies")} already covered by a parent naming context's subtree search on the same server.");
                }
            }

            // By default no top-level Credentials are written: the file is meant to be reviewed and then
            // run with credentials supplied on the command line (-u/-p/-d), so no secret is persisted to
            // disk. With -c/--writecredentials the CLI credentials are written into the file for convenience
            // (only when they were actually supplied — the Windows session cannot be serialised).
            Credentials? topLevelCredentials = null;
            if (includeCredentials)
            {
                if (credential != null && !string.IsNullOrEmpty(credential.UserName))
                {
                    topLevelCredentials = new Credentials
                    {
                        Username = credential.UserName,
                        // --logpasswords false keeps the password out of the file; the username and domain are
                        // still written so only the password has to be supplied again at run time.
                        Password = logPasswords ? credential.Password : "",
                        Domain = credential.Domain
                    };
                    if (logPasswords)
                    {
                        log.Warn($"Writing credentials for '{credential.Domain}\\{credential.UserName}' into '{outputPath}' (-c). The password is stored in plaintext; protect or delete this file afterwards.");
                    }
                    else
                    {
                        log.Info($"Writing credentials for '{credential.Domain}\\{credential.UserName}' into '{outputPath}' (-c) with an empty password (--logpasswords false); supply -p at run time.");
                    }
                }
                else
                {
                    log.Warn("-c/--writecredentials was set but no CLI credentials were supplied (-u/-p/-d); nothing to write, the file will rely on the Windows session or run-time credentials.");
                }
            }

            const string serverDescription =
                "The top-level 'Server' is the default DC contacted for any query that does not set its own 'Server'. " +
                "Each query's 'Server' overrides it. In this generated forest file every query pins a concrete DC, so " +
                "the top-level value is only a fallback (the DC discovery was run against). Only servers named in this " +
                "file are ever contacted.";
            var generated = new BenchmarkConfig { ServerDescription = serverDescription, Server = server, Queries = queries, Credentials = topLevelCredentials };
            string json = JsonConvert.SerializeObject(generated, Formatting.Indented, new JsonSerializerSettings { NullValueHandling = NullValueHandling.Ignore });
            File.WriteAllText(outputPath, json);
            string runHint = topLevelCredentials switch
            {
                { Password.Length: > 0 } => $"Review it, then run it with: -f \"{outputPath}\"",
                not null => $"Review it, then run it with: -f \"{outputPath}\" -p <pass>",
                _ => $"Review it, then run it with: -f \"{outputPath}\" -u <user> -p <pass> -d <domain>"
            };
            log.Info($"Wrote {queries.Count} query entries to '{outputPath}'. {runHint}");
        }

        internal static void ExecuteTests(BenchmarkConfig? config, bool pauseBetweenEngines, NetworkCredential? credential = null, bool mergeCredentials = false)
        {
            if (config == null || config.Queries == null)
            {
                log.Error("Failed to parse configuration file");
                return;
            }

            // Validate all credential blocks up front: an invalid block aborts the whole run rather than
            // silently falling back to a different identity. Without merge, each block must be whole or empty.
            // With merge, a partial block is allowed (the CLI fills the gaps), so validate the merged identity
            // per query instead and abort only when it is still partial after merging.
            if (!mergeCredentials)
            {
                if (!ValidateCredentialBlock(config.Credentials, "config-level default credentials"))
                {
                    return;
                }
                foreach (var query in config.Queries)
                {
                    if (!ValidateCredentialBlock(query.Credentials, $"query '{query.Name}'"))
                    {
                        return;
                    }
                }
            }
            else
            {
                foreach (var query in config.Queries)
                {
                    var (user, _, pass, _, domain, _) = ComposeCredential(query.Credentials, config.Credentials, credential);
                    bool anySet = user != null || pass != null || domain != null;
                    bool allSet = user != null && pass != null && domain != null;
                    if (anySet && !allSet)
                    {
                        var missing = new List<string>();
                        if (user == null) missing.Add("username");
                        if (pass == null) missing.Add("password");
                        if (domain == null) missing.Add("domain");
                        log.Error($"Cannot merge credentials for query '{query.Name}': after combining the CLI (-u/-p/-d) and the JSON, {string.Join(" and ", missing)} {(missing.Count == 1 ? "is" : "are")} still missing. Supply the missing field(s) on the CLI or in the JSON, or clear all of them to use the Windows session. Aborting.");
                        return;
                    }
                }
            }

            var warnedMerges = new HashSet<string>();
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

                // A query may name its own Server (e.g. entries in a generated forest file); otherwise
                // the config-level Server is used. Only servers named in the file are ever contacted.
                string effectiveServer = string.IsNullOrWhiteSpace(test.Server) ? config.Server : test.Server;
                var effectiveCredential = ResolveCredential(test.Credentials, config.Credentials, credential, mergeCredentials, out var mergeWarning);
                if (mergeWarning != null && warnedMerges.Add(mergeWarning))
                {
                    log.Warn(mergeWarning);
                }
                log.Info($"  Server: {effectiveServer}");

                var adwsHelper = new ADWSHelpers(effectiveServer, 389, effectiveCredential);
                var adwsGcHelper = new ADWSHelpers(effectiveServer, 3268, effectiveCredential);

                var ldapHelper = new LDAPHelpers(effectiveServer, 389, effectiveCredential, secure: false);
                var ldapsHelper = new LDAPHelpers(effectiveServer, 636, effectiveCredential, secure: true);
                var ldapGcHelper = new LDAPHelpers(effectiveServer, 3268, effectiveCredential, secure: false);
                var ldapsGcHelper = new LDAPHelpers(effectiveServer, 3269, effectiveCredential, secure: true);

                foreach (var engine in test.Engines)
                {
                    foreach (var targetOU in ResolveTargetOUs(effectiveServer, engine, test.TargetOUs, effectiveCredential))
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