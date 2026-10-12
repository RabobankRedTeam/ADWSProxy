using log4net;
using Newtonsoft.Json;
using System.Text;

namespace BloodHoundConverter.Writers
{
    internal class BloodHoundWriter : IDisposable
    {
        private readonly ILog log = LogManager.GetLogger(typeof(BloodHoundWriter));
        public StreamWriter? StreamWriter { get; private set; }
        public JsonTextWriter? JsonWriter { get; private set; }
        public BloodHoundFileType NodeType { get; }
        public string BaseFilePath { get; }
        public Formatting Formatting { get; }
        public int TotalCount { get; private set; } = 0;
        public int Count { get; private set; }
        private int MaxCount { get; } = 20000;
        private int Part { get; set; }

        public BloodHoundWriter(string filePath, Formatting formatting, BloodHoundFileType nodeType)
        {
            BaseFilePath = filePath;
            Formatting = formatting;
            NodeType = nodeType;

            Part = 0;
            InitializeNew();
        }

        private void InitializeNew()
        {
            Part++;
            Count = 0;
            StreamWriter = new StreamWriter($"{BaseFilePath}_{Part}.json", false, Encoding.UTF8, 65536);
            JsonWriter = new JsonTextWriter(StreamWriter) { Formatting = Formatting };

            JsonWriter.WriteStartObject();
            JsonWriter.WritePropertyName("data");
            JsonWriter.WriteStartArray();
        }

        public void WriteNode(IADNodeWriter iADNodeWriter, NodeProcessingContext context)
        {
            ArgumentNullException.ThrowIfNull(JsonWriter, nameof(JsonWriter));
            ArgumentNullException.ThrowIfNull(iADNodeWriter, nameof(iADNodeWriter));
            ArgumentNullException.ThrowIfNull(context, nameof(context));

            if (Count >= MaxCount)
            {
                Complete();
                Dispose();
                InitializeNew();
            }
            Count++;
            TotalCount++;
            iADNodeWriter.WriteNode(JsonWriter, context);
        }

        private static readonly Dictionary<BloodHoundFileType, string> MetaTypeMap = new()
        {
            [BloodHoundFileType.AIACAs] = "aiacas",
            [BloodHoundFileType.CertTemplates] = "certtemplates",
            [BloodHoundFileType.Computers] = "computers",
            [BloodHoundFileType.Containers] = "containers",
            [BloodHoundFileType.Domains] = "domains",
            [BloodHoundFileType.EnterpriseCAs] = "enterprisecas",
            [BloodHoundFileType.GPOs] = "gpos",
            [BloodHoundFileType.Groups] = "groups",
            [BloodHoundFileType.IssuancePolicies] = "issuancepolicies",
            [BloodHoundFileType.NTAuthStores] = "ntauthstores",
            [BloodHoundFileType.Others] = "containers",
            [BloodHoundFileType.OUs] = "ous",
            [BloodHoundFileType.RootCAs] = "rootcas",
            [BloodHoundFileType.Users] = "users"
        };

        public void Complete()
        {
            ArgumentNullException.ThrowIfNull(JsonWriter, nameof(JsonWriter));

            JsonWriter.WriteEndArray();
            JsonWriter.WritePropertyName("meta");
            JsonWriter.WriteStartObject();
            JsonWriter.WritePropertyName("version");
            JsonWriter.WriteValue(6);
            JsonWriter.WritePropertyName("type");
            if (MetaTypeMap.TryGetValue(NodeType, out var metaType))
            {
                JsonWriter.WriteValue(metaType);
            }
            else
            {
                log.Debug($"Unknown BloodHound file type: {NodeType}. Defaulting to 'containers'.");
                JsonWriter.WriteValue("containers");
            }
            JsonWriter.WritePropertyName("count");
            JsonWriter.WriteValue(Count);
            JsonWriter.WritePropertyName("collectorversion");
            JsonWriter.WriteValue(AppInfo.GetVersion());
            JsonWriter.WriteEndObject();
            JsonWriter.Flush();
        }

        public void Dispose()
        {
            JsonWriter?.Close();
            StreamWriter?.Dispose();
            JsonWriter = null;
            StreamWriter = null;
        }
    }
}
