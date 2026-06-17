using log4net;

namespace BloodHoundConverter
{
    internal class Program
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(Program));

        static void Main(string[] args)
        {
            LoggerConfig.InitializeProgrammaticLogging();

            if (args.Length == 0)
            {
                log.Error("No input file provided.");
                return;
            }
            var testFile = args[0];
            log.Info($"Processing file: {testFile}");

            BloodHoundConverter.ProcessJsonDump(testFile, @"C:\Users\luc\Downloads\TESTOUTPUT");
        }
    }
}
