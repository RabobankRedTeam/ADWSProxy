using System.Collections.Generic;
using System.ServiceModel.Channels;
using System.Xml;

namespace ADWSProxy.ADWS.Request
{
    internal class GetResponse : ADWSResponse
    {
        public GetResponse(Message response) : base(response)
        {
        }

        public Dictionary<string, List<string>> Items { get; set; } = new Dictionary<string, List<string>> { };

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
                            if (Items.ContainsKey(elementName))
                            {
                                Items[elementName].Add(nodeValue);
                            }
                            else
                            {
                                Items.Add(elementName, new List<string>() { nodeValue });
                            }
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