using System.ServiceModel.Channels;
using System.Xml;

namespace ADWSProxy.ADWS.Request
{
    internal class GetResponse(Message response) : ADWSResponse(response)
    {
        public Dictionary<string, List<string>> Items { get; set; } = [];

        protected override void OnReadBodyContents(XmlDictionaryReader reader)
        {
            while (reader.Read())
            {
                if (reader.NodeType == XmlNodeType.Element && reader.LocalName != "value")
                {
                    var elementName = reader.LocalName;
                    while (reader.Read())
                    {
                        if (reader.NodeType == XmlNodeType.Text)
                        {
                            var nodeValue = reader.Value;
#pragma warning disable CA1854 // Prefer the 'IDictionary.TryGetValue(TKey, out TValue)' method
                            if (Items.ContainsKey(elementName))
                            {
                                Items[elementName].Add(nodeValue);
                            }
                            else
                            {
                                Items.Add(elementName, [nodeValue]);
                            }
#pragma warning restore CA1854 // Prefer the 'IDictionary.TryGetValue(TKey, out TValue)' method
                        }
                        if (reader.NodeType == XmlNodeType.EndElement && reader.LocalName != "value")
                        {
                            break;
                        }
                    }
                }
            }
        }
    }
}