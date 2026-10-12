using log4net;

namespace ADWSProxy
{
    internal static class LogHelper
    {
        private static readonly string RepoName = LogManager.GetRepository(typeof(LogHelper).Assembly).Name;

        public static ILog GetLogger(Type type)
        {
            // This overload is AOT-safe because it doesn't call GetCallingAssembly()
            return LogManager.GetLogger(RepoName, type);
        }
    }
}
