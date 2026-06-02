using ADWSProxy;
using log4net;
using System.Net;

namespace TestClient
{
    internal class ADWSHelpers(string server, int instancePort = 389, NetworkCredential? credential = null)
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(ADWSHelpers));

        private ADWSProxy.ADWS.Connection Connection { get; set; } = new ADWSProxy.ADWS.Connection(server, 9389, $"ldap:{instancePort}", AdwsEndpoint.Windows, credential);

        internal List<ResultHolder> ExecuteAdws(string baseDn, string filter, string scope, List<string> attributes)
        {
            var results = new List<ResultHolder>();
            Connection.Enumerate(baseDn, filter, attributes, scope.ToString(), result =>
            {
                var (dn, dataHolders) = result;
                results.Add(new ResultHolder
                {
                    DistinguishedName = dn,
                    Attributes = dataHolders.GroupBy(dh => dh.Name, StringComparer.OrdinalIgnoreCase).ToDictionary(
                        group => group.Key,
                        group => group.SelectMany(dh =>
                        {
                            if (dh.Data is string stringData)
                            {
                                return [stringData];
                            }
                            if (dh.Data is byte[] byteArray)
                            {
                                return [Convert.ToBase64String(byteArray)];
                            }
                            if (dh.Data is System.Collections.IEnumerable enumerable)
                            {
                                return enumerable.Cast<object>().Select(item =>
                                {
                                    if (item is byte[] itemBytes)
                                    {
                                        return Convert.ToBase64String(itemBytes);
                                    }
                                    return item?.ToString() ?? string.Empty;
                                });
                            }
                            return [dh.Data?.ToString() ?? string.Empty];
                        }).ToList())
                });
            });

            try
            {
                LoggerConfig.LogDebug(log, "Result", results);
            }
            catch (Exception ex)
            {
                log.Error("Error occurred while serializing ADWS results", ex);

            }
            return results;
        }
    }
}