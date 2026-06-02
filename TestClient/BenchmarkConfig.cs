namespace TestClient
{
    internal class BenchmarkConfig
    {
        public required string Server { get; set; }
        public required List<LdapQueryTest> Queries { get; set; }
    }
}
