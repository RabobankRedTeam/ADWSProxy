using log4net;
using log4net.Appender;
using log4net.Filter;
using log4net.Layout;
using log4net.Repository.Hierarchy;
using System.Text.Json;

namespace TestClient
{
    internal class LoggerConfig
    {
        private static readonly JsonSerializerOptions jsonOptions = new()
        {
            WriteIndented = false
        };

        public static void LogDebug(ILog log, string message, object data)
        {
            log.Debug($"{message} - {JsonSerializer.Serialize(data, jsonOptions)}");
        }

        public static void InitializeProgrammaticLogging(string logDirectory = "")
        {
            Hierarchy hierarchy = (Hierarchy)LogManager.GetRepository();
            string baseDir = string.IsNullOrWhiteSpace(logDirectory) ? Directory.GetCurrentDirectory() : Path.GetFullPath(logDirectory);

            // 1. Structural Layout Definitions
            PatternLayout clientPatternLayout = new()
            {
                ConversionPattern = "%date %logger - %message%newline"
            };
            clientPatternLayout.ActivateOptions();

            PatternLayout tracePatternLayout = new()
            {
                ConversionPattern = "%date | %-40logger [ %level ] %message%newline"
            };
            tracePatternLayout.ActivateOptions();

            // 2. Global Minimum Thresholds
            LevelRangeFilter infoAndAboveFilter = new()
            {
                LevelMin = log4net.Core.Level.Info,
                LevelMax = log4net.Core.Level.Fatal
            };
            infoAndAboveFilter.ActivateOptions();

            // 3. Only allow "TestClient" logs here
            LoggerMatchFilter acceptOnlyClientFilter = new()
            {
                LoggerToMatch = "TestClient",
                AcceptOnMatch = true
            };
            acceptOnlyClientFilter.ActivateOptions();

            // Deny everything else that didn't match the TestClient prefix
            DenyAllFilter denyEverythingElseFilter = new();
            denyEverythingElseFilter.ActivateOptions();

            // 4. Trace File Appender
            RollingFileAppender traceAppender = new()
            {
                Name = "TraceFileAppender",
                File = Path.Combine(baseDir, "trace.log"),
                AppendToFile = true,
                RollingStyle = RollingFileAppender.RollingMode.Size,
                MaxFileSize = 100 * 1024 * 1024,
                MaxSizeRollBackups = 500,
                StaticLogFileName = true,
                Layout = tracePatternLayout
            };
            traceAppender.ActivateOptions();

            // 5. Info File Appender (INFO+ only)
            RollingFileAppender infoAppender = new()
            {
                Name = "InfoFileAppender",
                File = Path.Combine(baseDir, "info.log"),
                AppendToFile = true,
                RollingStyle = RollingFileAppender.RollingMode.Size,
                MaxFileSize = 100 * 1024 * 1024,
                MaxSizeRollBackups = 500,
                StaticLogFileName = true,
                Layout = clientPatternLayout
            };
            infoAppender.AddFilter(infoAndAboveFilter);        // Restrict to INFO+
            infoAppender.ActivateOptions();

            // 6. Console Appender (TestClient INFO+ only)
            ConsoleAppender consoleAppender = new()
            {
                Name = "ConsoleAppender",
                Layout = clientPatternLayout
            };
            consoleAppender.AddFilter(infoAndAboveFilter);      // Restrict to INFO+
            consoleAppender.AddFilter(acceptOnlyClientFilter);   // Pass if TestClient
            consoleAppender.AddFilter(denyEverythingElseFilter); // Drop if not TestClient
            consoleAppender.ActivateOptions();

            // 7. Establish the Hierarchy Root Boundary
            hierarchy.Root.RemoveAllAppenders();
            hierarchy.Root.AddAppender(traceAppender);
            hierarchy.Root.AddAppender(infoAppender);
            hierarchy.Root.AddAppender(consoleAppender);

            // Open the floodgates at the root level so everything flows to the trace appender
            hierarchy.Root.Level = log4net.Core.Level.Verbose;

            hierarchy.Configured = true;
            hierarchy.RaiseConfigurationChanged(EventArgs.Empty);
        }
    }
}