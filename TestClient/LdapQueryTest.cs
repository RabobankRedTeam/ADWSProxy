namespace TestClient
{
    internal class LdapQueryTest
    {
        public required string Name { get; set; }
        // Optional per-query server override. Used by generated forest files so each partition targets
        // its own DC; when null the config-level Server is used. Only listed servers are ever contacted.
        public string? Server { get; set; } = null;
        // Optional per-query credential override; null/omitted falls back to the config-level creds,
        // then the CLI creds, then the Windows session.
        public Credentials? Credentials { get; set; } = null;
        public required List<string> TargetOUs { get; set; }
        public required string Filter { get; set; }
        public required string Scope { get; set; }
        public required List<string> Attributes { get; set; }
        public required List<string> Engines { get; set; }

        public DateTime? StartTime { get; set; } = null;
    }
}
