using Newtonsoft.Json;

namespace TestClient
{
    internal class BenchmarkConfig
    {
        // Documentation only (ignored at run time): explains how the two Server fields resolve. Written into
        // generated files so they are self-documenting; omitted when null, so hand-written files are unaffected.
        [JsonProperty("_serverDescription", Order = -2, NullValueHandling = NullValueHandling.Ignore)]
        public string? ServerDescription { get; set; } = null;

        public required string Server { get; set; }
        // Optional default credentials for all queries; null/omitted uses CLI creds, then the Windows session.
        public Credentials? Credentials { get; set; } = null;
        public required List<LdapQueryTest> Queries { get; set; }
    }
}
