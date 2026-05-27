using ADWSProxy;
using log4net;
using System.Net;

namespace TestClient
{
    internal class ADWSHelpers(string server, int instancePort = 389, NetworkCredential? credential = null)
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(ADWSHelpers));

        private ADWSProxy.ADWS.Connection Connection { get; set; } = new ADWSProxy.ADWS.Connection(server, 9389, $"ldap:{instancePort}", AdwsEndpoint.Windows, credential);

        internal int ExecuteAdws(string baseDn, string filter, string scope, List<string> attributes)
        {
            var results = new List<(string Dn, List<(string Name, string DataType, object Data)> Attributes)>();
            Connection.Enumerate(baseDn, filter, attributes, scope.ToString(), result =>
            {
                var (dn, dataHolders) = result;
                results.Add((dn, dataHolders.Select(dh => (dh.Name, dh.DataType.ToString(), dh.Data)).ToList()));
            });

            try
            {
                var jsonOutputHasBase64Content = false;
                var serializableResults = results.Select(r => new
                {
                    DistinguishedName = r.Dn,
                    Attributes = r.Attributes.GroupBy(attr => attr.Name, StringComparer.OrdinalIgnoreCase).ToDictionary(
                        group => group.Key,
                        group => group.SelectMany(attr =>
                        {
                            if (attr.Data is string stringData)
                            {
                                return [stringData];
                            }
                            if (attr.Data is byte[] byteArray)
                            {
                                jsonOutputHasBase64Content = true;
                                return [Convert.ToBase64String(byteArray)];
                            }
                            if (attr.Data is System.Collections.IEnumerable enumerable)
                            {
                                return enumerable.Cast<object>().Select(item =>
                                {
                                    if (item is byte[] itemBytes)
                                    {
                                        jsonOutputHasBase64Content = true;
                                        return Convert.ToBase64String(itemBytes);
                                    }
                                    return item.ToString() ?? string.Empty;
                                });
                            }
                            return [attr.Data?.ToString() ?? string.Empty];
                        }))
                }).ToList();

                if (jsonOutputHasBase64Content)
                {
                    log.Debug("Some attributes were detected as binary data and have been Base64 encoded in the JSON output");
                }

                LoggerConfig.LogDebug(log, "Result", serializableResults);
            }
            catch (Exception ex)
            {
                log.Error("Error occurred while serializing ADWS results", ex);

            }
            return results.Count;
        }
    }
}