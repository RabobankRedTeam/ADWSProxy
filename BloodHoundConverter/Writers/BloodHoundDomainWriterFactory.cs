using Newtonsoft.Json;

namespace BloodHoundConverter.Writers
{
    internal class BloodHoundDomainWriterFactory(string outputDirectoryPath, string baseFileTarget, Formatting formatting = Formatting.Indented) : IDisposable
    {
        private readonly Dictionary<string, Dictionary<BloodHoundFileType, BloodHoundWriter>> _writers = [];

        public IEnumerable<(string Domain, BloodHoundWriter Writer)> GetAllWriters()
        {
            foreach (var (domain, domainWriters) in _writers.OrderBy(kv => kv.Key))
            {
                foreach (var writer in domainWriters.Values)
                {
                    yield return (domain, writer);
                }
            }
        }

        public BloodHoundWriter GetWriter(string domain, BloodHoundFileType fileType)
        {
            // Sanitize domain name for safe file paths
            string safeDomain = string.IsNullOrWhiteSpace(domain) ? "global" : domain.Replace(".", "_").ToLowerInvariant();

            if (!_writers.TryGetValue(safeDomain, out var domainWriters))
            {
                domainWriters = [];
                _writers[safeDomain] = domainWriters;
            }

            if (!domainWriters.TryGetValue(fileType, out var writer))
            {
                string baseFileName = $"{baseFileTarget}_{safeDomain}_{fileType.ToString().ToLowerInvariant()}";
                string fullPath = Path.Combine(outputDirectoryPath, baseFileName);

                writer = new BloodHoundWriter(fullPath, formatting, fileType);

                if (fileType == BloodHoundFileType.Groups)
                {
                    InjectWellKnwonGroups(writer.JsonWriter!);
                }
                domainWriters[fileType] = writer;
            }

            return writer;
        }

        private static void InjectWellKnwonGroups(JsonTextWriter writer)
        {
            foreach (var kvp in BloodHoundModels.WellKnownSystemGroups)
            {
                string sid = kvp.Key;
                var (shortName, description) = kvp.Value;

                string assignedDomain = "NT AUTHORITY";

                if (sid.StartsWith("S-1-5-32", StringComparison.OrdinalIgnoreCase))
                {
                    assignedDomain = "BUILTIN";
                }
                else if (sid.Equals("S-1-1-0", StringComparison.OrdinalIgnoreCase))
                {
                    assignedDomain = "EVERYONE";
                }

                writer.WriteStartObject();
                IADNodeWriter.WriteProperty(writer, "ObjectIdentifier", sid);
                writer.WritePropertyName("Properties");
                writer.WriteStartObject();
                IADNodeWriter.WriteProperty(writer, "domain", assignedDomain);
                IADNodeWriter.WriteProperty(writer, "name", $"{shortName}@{assignedDomain}".ToUpper());
                IADNodeWriter.WriteProperty(writer, "distinguishedname", $"CN={shortName},CN=WellKnownSids,DC=System".ToUpper());
                IADNodeWriter.WriteProperty(writer, "description", description);
                writer.WriteEndObject();

                // System SIDs have empty structural links/ACE arrays by default in exports
                IADNodeWriter.WritePropertyArray(writer, "Members", []);
                IADNodeWriter.WritePropertyArray(writer, "Aces", []);
                writer.WriteEndObject();
            }
        }

        public void Dispose()
        {
            foreach (var domainDict in _writers.Values)
            {
                foreach (var writer in domainDict.Values)
                {
                    writer.Complete();
                    writer.Dispose();
                }
            }
            _writers.Clear();
        }
    }
}