using log4net;
using log4net.Appender;
using log4net.Filter;
using log4net.Layout;
using log4net.Repository.Hierarchy;

namespace BloodHoundConverter
{
    internal class LoggerConfig
    {
        public static void InitializeProgrammaticLogging()
        {
            Hierarchy hierarchy = (Hierarchy)LogManager.GetRepository();

            PatternLayout clientPatternLayout = new()
            {
                ConversionPattern = "%date %logger - %message%newline"
            };
            clientPatternLayout.ActivateOptions();

            LevelRangeFilter debugAndAboveFilter = new()
            {
                LevelMin = log4net.Core.Level.Debug,
                LevelMax = log4net.Core.Level.Fatal
            };
            debugAndAboveFilter.ActivateOptions();

            ConsoleAppender consoleAppender = new()
            {
                Name = "ConsoleAppender",
                Layout = clientPatternLayout
            };
            consoleAppender.AddFilter(debugAndAboveFilter);
            consoleAppender.ActivateOptions();

            hierarchy.Root.RemoveAllAppenders();
            hierarchy.Root.AddAppender(consoleAppender);

            hierarchy.Root.Level = log4net.Core.Level.Verbose;

            hierarchy.Configured = true;
            hierarchy.RaiseConfigurationChanged(EventArgs.Empty);
        }
    }
}