using System.Reflection;

namespace BloodHoundConverter
{
    internal static class AppInfo
    {
        private static string? _version;
        internal const bool writeDefaultValues = true;

        public static string GetVersion()
        {
            // Grabs the exact version string set in your .csproj file
            _version ??= Assembly.GetExecutingAssembly()
                                   .GetName()
                                   .Version?.ToString(3) ?? "Unknown version"; // "3" trims it to Major.Minor.Patch (e.g., 1.0.0)
            return _version;
        }
    }
}
