using Newtonsoft.Json;

namespace BloodHoundConverter
{
    internal class DataHolder
    {
        [JsonProperty("DistinguishedName")]
        public string DistinguishedName { get; set; } = string.Empty;

        [JsonProperty("Attributes")]
        public Dictionary<string, List<string>> Attributes { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    }
}
