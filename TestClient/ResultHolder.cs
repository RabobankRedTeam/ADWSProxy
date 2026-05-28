namespace TestClient
{
    internal class ResultHolder
    {
        public required string DistinguishedName { get; set; }
        public Dictionary<string, List<string>> Attributes { get; set; } = [];
    }
}
