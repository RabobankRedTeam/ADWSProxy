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
                domainWriters[fileType] = writer;
            }

            return writer;
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