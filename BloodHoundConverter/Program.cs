using log4net;
using System.Diagnostics;

namespace BloodHoundConverter
{
    internal class Program
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(Program));

        static void Main(string[] args)
        {
            Stopwatch stopwatch = Stopwatch.StartNew();
            LoggerConfig.InitializeProgrammaticLogging();
            log.Info($"Starting BloodHound Converter {AppInfo.GetVersion()}");

            if (args.Length == 0)
            {
                log.Error("No input path or file provided.");
                return;
            }

            string inputPath = args[0];
            List<string> targetFiles = [];
            string outputDirectory;

            if (Directory.Exists(inputPath))
            {
                outputDirectory = inputPath;
                targetFiles.AddRange(Directory.GetFiles(inputPath, "*_part*.json"));
            }
            else if (File.Exists(inputPath))
            {
                outputDirectory = Path.GetDirectoryName(inputPath) ?? AppDomain.CurrentDomain.BaseDirectory;
                targetFiles.Add(inputPath);
            }
            else
            {
                string? directoryPattern = Path.GetDirectoryName(inputPath);
                string filePattern = Path.GetFileName(inputPath);
                string searchDir = string.IsNullOrEmpty(directoryPattern) ? AppDomain.CurrentDomain.BaseDirectory : directoryPattern;

                if (Directory.Exists(searchDir))
                {
                    outputDirectory = searchDir;
                    targetFiles.AddRange(Directory.GetFiles(searchDir, filePattern));
                }
                else
                {
                    log.Error($"Provided path context does not exist: {inputPath}");
                    return;
                }
            }

            if (targetFiles.Count == 0)
            {
                log.Warn($"No matching json chunk data files found for processing path: {inputPath}");
                return;
            }

            log.Info($"Found {targetFiles.Count} partition file(s) for parsing pass.");

            outputDirectory = Path.Combine(outputDirectory, "BloodHoundOutput", $"{DateTime.Now:yyyyMMdd_HHmmss}");

            BloodHoundConverter.ProcessJsonChunks(targetFiles, outputDirectory);

            log.Info($"Completed conversion in {stopwatch.Elapsed:hh'h 'mm'm 'ss's'}");
        }
    }
}
