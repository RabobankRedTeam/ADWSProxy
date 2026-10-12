namespace BloodHoundConverter
{
    internal static class BloodHoundModels
    {
        public static object CreateHeader(string type) => new
        {
            meta = new { version = 5, type },
            SortedKeys = type // Property name placeholder handled during serialization
        };

        public static readonly Dictionary<string, (string Name, string Description)> WellKnownSystemGroups = new(StringComparer.OrdinalIgnoreCase)
        {
            { "S-1-1-0", ("EVERYONE", "Everyone identity encompassing all users.") },
            { "S-1-5-9", ("ENTERPRISE DOMAIN CONTROLLERS", "All domain controllers in the active directory forest.") },
            { "S-1-5-11", ("AUTHENTICATED USERS", "All authenticated user contexts.") },
            { "S-1-5-18", ("SYSTEM", "The local system execution context of the domain controllers.") },
            { "S-1-5-32-544", ("BUILTIN ADMINISTRATORS", "Built-in localized administrative group.") },
            { "S-1-5-32-554", ("PRE-WINDOWS 2000 COMPATIBLE ACCESS", "Backward compatibility read-access mapping group.") },
            { "S-1-5-32-556", ("NETWORK CONFIGURATION OPERATORS", "Members can manage network configuration assets.") }
        };
    }
}
