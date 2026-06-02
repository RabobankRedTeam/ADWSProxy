namespace TestClient
{
    internal class LdapQueryTest
    {
        public required string Name { get; set; }
        public required string TargetOU { get; set; }
        public required string Filter { get; set; }
        public required string Scope { get; set; }
        public required List<string> Attributes { get; set; }
        public required List<string> Engines { get; set; }

    }
}
