namespace BloodHoundConverter
{
    internal class BloodHoundModels
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

        public static readonly Dictionary<Guid, string> ExtendedRights = new(EqualityComparer<Guid>.Default)
        {
            // --- Password Abuse Paths ---
            { new Guid("002a95ab-d28d-11d2-873f-00a0c9116b64"), "ForceChangePassword" },
            { new Guid("00299570-246d-11d0-a768-00aa006e0529"), "ForceChangePassword" },

            // --- DCSync / Replication Abuse Paths ---
            { new Guid("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"), "GetChanges" },
            { new Guid("1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"), "GetChangesAll" },
            { new Guid("89e95b76-444d-4c62-991a-0facbeda640c"), "GetChangesInFilteredSet" },

            // --- Blanket Control Rights ---
            { new Guid("00000000-0000-0000-0000-000000000000"), "AllExtendedRights" },
            { new Guid("89eac347-adeb-11d1-97d4-00c04fd65a57"), "AllExtendedRights" },

            // --- ADCS Certificate Blueprint Paths (BloodHound CE Support) ---
            { new Guid("0e10c968-78fb-11d2-8a9d-00c04fa31a4d"), "Enroll" },
            { new Guid("a05b8cc2-178a-4ee9-a7d1-061c9b228732"), "Enroll" }
        };
    }
}
