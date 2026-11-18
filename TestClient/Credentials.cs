namespace TestClient
{
    // Optional credential block for the config file. All three fields are used together; any field
    // empty/null means "not set", in which case resolution falls back to the next source (see
    // ProgramHelpers.ResolveCredential). An empty or null block therefore uses the Windows session.
    internal class Credentials
    {
        public string? Username { get; set; }
        public string? Password { get; set; }
        public string? Domain { get; set; }
    }
}
