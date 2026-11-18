namespace BloodHoundConverter
{
    /// <summary>
    /// Universal / well-known security principals that carry the same raw SID in every domain
    /// (Everyone, Authenticated Users, the service and logon identities, etc.). SharpHound resolves
    /// these to a fixed name and type and then domain-scopes the identifier as {DOMAIN}-{SID} so each
    /// domain owns its own copy; see <see cref="Helpers.ScopeSid"/>. Built-in BUILTIN\ groups
    /// (S-1-5-32-RID) are not listed here because they exist as real group objects in every domain's
    /// directory; they are domain-scoped by prefix in ScopeSid and typed from those real objects.
    /// </summary>
    internal static class WellKnownSids
    {
        internal static readonly Dictionary<string, (string Name, ObjectType Type)> Table =
            new(StringComparer.OrdinalIgnoreCase)
        {
            { "S-1-0-0",     ("NOBODY", ObjectType.User) },
            { "S-1-1-0",     ("EVERYONE", ObjectType.Group) },
            { "S-1-2-0",     ("LOCAL", ObjectType.Group) },
            { "S-1-2-1",     ("CONSOLE LOGON", ObjectType.Group) },
            { "S-1-3-0",     ("CREATOR OWNER", ObjectType.User) },
            { "S-1-3-1",     ("CREATOR GROUP", ObjectType.Group) },
            { "S-1-3-2",     ("CREATOR OWNER SERVER", ObjectType.Computer) },
            { "S-1-3-3",     ("CREATOR GROUP SERVER", ObjectType.Computer) },
            { "S-1-3-4",     ("OWNER RIGHTS", ObjectType.Group) },
            { "S-1-5-1",     ("DIALUP", ObjectType.Group) },
            { "S-1-5-2",     ("NETWORK", ObjectType.Group) },
            { "S-1-5-3",     ("BATCH", ObjectType.Group) },
            { "S-1-5-4",     ("INTERACTIVE", ObjectType.Group) },
            { "S-1-5-6",     ("SERVICE", ObjectType.Group) },
            { "S-1-5-7",     ("ANONYMOUS", ObjectType.Group) },
            { "S-1-5-8",     ("PROXY", ObjectType.Group) },
            { "S-1-5-9",     ("ENTERPRISE DOMAIN CONTROLLERS", ObjectType.Group) },
            { "S-1-5-10",    ("PRINCIPAL SELF", ObjectType.User) },
            { "S-1-5-11",    ("AUTHENTICATED USERS", ObjectType.Group) },
            { "S-1-5-12",    ("RESTRICTED CODE", ObjectType.Group) },
            { "S-1-5-13",    ("TERMINAL SERVER USERS", ObjectType.Group) },
            { "S-1-5-14",    ("REMOTE INTERACTIVE LOGON", ObjectType.Group) },
            { "S-1-5-15",    ("THIS ORGANIZATION", ObjectType.Group) },
            { "S-1-5-17",    ("IUSR", ObjectType.User) },
            { "S-1-5-18",    ("LOCAL SYSTEM", ObjectType.User) },
            { "S-1-5-19",    ("LOCAL SERVICE", ObjectType.User) },
            { "S-1-5-20",    ("NETWORK SERVICE", ObjectType.User) },
            { "S-1-5-64-10", ("NTLM AUTHENTICATION", ObjectType.Group) },
            { "S-1-5-64-14", ("SCHANNEL AUTHENTICATION", ObjectType.Group) },
            { "S-1-5-64-21", ("DIGEST AUTHENTICATION", ObjectType.Group) },
            { "S-1-5-65-1",  ("THIS ORGANIZATION CERTIFICATE", ObjectType.Group) },
            { "S-1-5-80-0",  ("ALL SERVICES", ObjectType.Group) },
            { "S-1-5-90-0",  ("WINDOW MANAGER GROUP", ObjectType.Group) },
            { "S-1-5-113",   ("LOCAL ACCOUNT", ObjectType.User) },
            { "S-1-5-114",   ("LOCAL ACCOUNT AND MEMBER OF ADMINISTRATORS GROUP", ObjectType.User) },
            { "S-1-5-1000",  ("OTHER ORGANIZATION", ObjectType.Group) },
            { "S-1-18-1",    ("AUTHENTICATION AUTHORITY ASSERTED IDENTITY", ObjectType.Group) },
            { "S-1-18-2",    ("SERVICE ASSERTED IDENTITY", ObjectType.Group) },
            { "S-1-18-3",    ("FRESH PUBLIC KEY IDENTITY", ObjectType.Group) },
            { "S-1-18-4",    ("KEY TRUST", ObjectType.Group) },
            { "S-1-18-5",    ("MFA KEY PROPERTY", ObjectType.Group) },
            { "S-1-18-6",    ("ATTESTED KEY PROPERTY", ObjectType.Group) },
        };

        /// <summary>True for a SID whose identity is universal/built-in and must be domain-scoped: the
        /// BUILTIN container itself (S-1-5-32), a BUILTIN local group (S-1-5-32-RID), or an entry in
        /// <see cref="Table"/>. Domain-relative SIDs (S-1-5-21-...) and unrecognized SIDs are not scoped.
        /// Scoping bare S-1-5-32 gives each domain its own CN=Builtin node so the built-in groups'
        /// ContainedBy edge resolves to a per-domain container instead of one shared across the forest.</summary>
        internal static bool IsScopable(string? sid) =>
            !string.IsNullOrEmpty(sid) &&
            !sid.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase) &&
            (sid.Equals("S-1-5-32", StringComparison.OrdinalIgnoreCase) ||
             sid.StartsWith("S-1-5-32-", StringComparison.OrdinalIgnoreCase) ||
             Table.ContainsKey(sid));

        /// <summary>Forest-wide identities scoped to the forest root rather than the object's own domain,
        /// matching SharpHound. Only Enterprise Domain Controllers (S-1-5-9) is treated this way.</summary>
        internal static readonly HashSet<string> ForestScoped = new(StringComparer.OrdinalIgnoreCase)
        {
            "S-1-5-9"
        };
    }
}
