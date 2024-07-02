using log4net;
using log4net.Appender;
using log4net.Core;
using log4net.Filter;
using log4net.Layout;
using log4net.Repository.Hierarchy;
using System.IO;

namespace ADWSProxy
{
    internal class LoggerConfig
    {
        public static void ConfigureLogger(string ConsoleFilterLevel, string LogDirectory)
        {
            var hierarchy = (Hierarchy)LogManager.GetRepository();

            // Pattern layout
            var patternLayout = new PatternLayout
            {
                ConversionPattern = "[ %level ] %message%newline"
            };
            patternLayout.ActivateOptions();

            // Console logger
            Level consoleLogLevel = hierarchy.LevelMap[ConsoleFilterLevel] ?? Level.Info;

            var consoleAppender = new ConsoleAppender
            {
                Layout = patternLayout
            };

            var consoleFilter = new LevelRangeFilter
            {
                LevelMin = consoleLogLevel,
                LevelMax = Level.Off
            };
            consoleAppender.AddFilter(consoleFilter);

            consoleAppender.ActivateOptions();
            hierarchy.Root.AddAppender(consoleAppender);

            // Pattern layout
            patternLayout = new PatternLayout
            {
                ConversionPattern = "%date | %40class [ %level ] %message%newline"
            };
            patternLayout.ActivateOptions();

            // Trace file logger
            var traceFileAppender = new FileAppender
            {
                File = Path.Combine(Path.GetFullPath(LogDirectory), "trace.log"),
                Layout = patternLayout
            };

            var traceFilter = new LevelRangeFilter
            {
                LevelMin = Level.All,
                LevelMax = Level.Off
            };
            traceFileAppender.AddFilter(traceFilter);

            traceFileAppender.ActivateOptions();
            hierarchy.Root.AddAppender(traceFileAppender);

            // Info file logger
            var infoFileAppender = new FileAppender
            {
                File = Path.Combine(Path.GetFullPath(LogDirectory), "info.log"),
                Layout = patternLayout
            };

            var infoFilter = new LevelRangeFilter
            {
                LevelMin = Level.Info,
                LevelMax = Level.Off
            };
            infoFileAppender.AddFilter(infoFilter);

            infoFileAppender.ActivateOptions();
            hierarchy.Root.AddAppender(infoFileAppender);

            // Error file logger
            var errorFileAppender = new FileAppender
            {
                File = Path.Combine(Path.GetFullPath(LogDirectory), "error.log"),
                Layout = patternLayout
            };

            var errorFilter = new LevelRangeFilter
            {
                LevelMin = Level.Error,
                LevelMax = Level.Off
            };
            errorFileAppender.AddFilter(errorFilter);

            errorFileAppender.ActivateOptions();
            hierarchy.Root.AddAppender(errorFileAppender);

            hierarchy.Root.Level = Level.All;
            hierarchy.Configured = true;
        }
    }
}