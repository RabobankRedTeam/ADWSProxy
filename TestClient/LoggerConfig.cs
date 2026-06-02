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

        public static void InitializeProgrammaticLogging()
        {
            Hierarchy hierarchy = (Hierarchy)LogManager.GetRepository();

            // 1. Define the shared pattern layout
            PatternLayout patternLayout = new()
            {
                ConversionPattern = "%date %logger - %message%newline"
            };
            patternLayout.ActivateOptions();

            // 2. Filter out DEBUG logs (Shared by Info file and Console)
            LevelRangeFilter infoAndAboveFilter = new()
            {
                LevelMin = log4net.Core.Level.Info,
                LevelMax = log4net.Core.Level.Fatal
            };
            infoAndAboveFilter.ActivateOptions();

            // 3. Trace File Appender (Captures ALL levels down to DEBUG)
            RollingFileAppender traceAppender = new()
            {
                Name = "TraceFileAppender",
                File = Path.Combine(Directory.GetCurrentDirectory(), "trace.log"),
                AppendToFile = true,
                RollingStyle = RollingFileAppender.RollingMode.Size,
                MaxFileSize = 100 * 1024 * 1024,
                MaxSizeRollBackups = 500,
                StaticLogFileName = true,
                Layout = patternLayout
            };
            traceAppender.ActivateOptions();

            // 4. Info File Appender (INFO and ERROR only)
            RollingFileAppender infoAppender = new()
            {
                Name = "InfoFileAppender",
                File = Path.Combine(Directory.GetCurrentDirectory(), "info.log"),
                AppendToFile = true,
                RollingStyle = RollingFileAppender.RollingMode.Size,
                MaxFileSize = 100 * 1024 * 1024,
                MaxSizeRollBackups = 500,
                StaticLogFileName = true,
                Layout = patternLayout
            };
            infoAppender.AddFilter(infoAndAboveFilter);
            infoAppender.ActivateOptions();

            // 5. Console Appender (INFO and ERROR only)
            ConsoleAppender consoleAppender = new()
            {
                Name = "ConsoleAppender",
                Layout = patternLayout
            };
            consoleAppender.AddFilter(infoAndAboveFilter);
            consoleAppender.ActivateOptions();

            // 6. Attach all three destinations to the root hierarchy
            hierarchy.Root.AddAppender(traceAppender);
            hierarchy.Root.AddAppender(infoAppender);
            hierarchy.Root.AddAppender(consoleAppender);

            // Ensure root level allows DEBUG to pass through to the Trace appender
            hierarchy.Root.Level = log4net.Core.Level.Debug;

            if (hierarchy.GetLogger("ADWSProxy") is Logger proxyLogger)
            {
                proxyLogger.Level = log4net.Core.Level.Verbose;
                proxyLogger.Additivity = false;
            }

            hierarchy.Configured = true;
            hierarchy.RaiseConfigurationChanged(EventArgs.Empty);
        }
    }
}