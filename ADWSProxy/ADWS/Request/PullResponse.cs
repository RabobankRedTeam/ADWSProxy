using ADWSProxy.LDAP;
using Flexinets.Ldap.Core;
using System;
using System.Collections.Generic;
using System.ServiceModel.Channels;
using System.Xml;

namespace ADWSProxy.ADWS.Request
{
    internal class PullResponse : ADWSResponse
    {
        public PullResponse(Message response) : base(response)
        {
        }

        public bool EndOfSequence { get; private set; } = false;
        public string EnumerateContext { get; private set; }

        public Dictionary<string, List<DataHolder>> Items { get; set; } = new Dictionary<string, List<DataHolder>>();

        protected override void OnReadBodyContents(XmlDictionaryReader reader)
        {
            reader.ReadStartElement("PullResponse", "http://schemas.xmlsoap.org/ws/2004/09/enumeration");
            if (reader.IsStartElement("EnumerationContext", "http://schemas.xmlsoap.org/ws/2004/09/enumeration"))
            {
                EnumerateContext = reader.ReadElementContentAsString();
            }
            if (reader.IsStartElement("EndOfSequence", "http://schemas.xmlsoap.org/ws/2004/09/enumeration"))
            {
                EndOfSequence = true;
                return;
            }
            if (reader.IsStartElement("Items", "http://schemas.xmlsoap.org/ws/2004/09/enumeration"))
            {
                reader.Read();
                var ldapObjectDepth = reader.Depth;
                reader.Read();

                var item = new List<DataHolder>();
                string dn = null;
                do
                {
                    if (reader.NodeType == XmlNodeType.Element)
                    {
                        var elementName = reader.LocalName;
                        if (elementName.Equals("distinguishedName", StringComparison.InvariantCultureIgnoreCase))
                        {
                            reader.Read();
                            dn = reader.ReadElementContentAsString();
                            item.Add(new DataHolder("distinguishedName", dn, UniversalDataType.OctetString));
                        }
                        else
                        {
                            do
                            {
                                reader.Read();
                                if (reader.NodeType == XmlNodeType.Element)
                                {
                                    string type = reader.GetAttribute("type", "http://www.w3.org/2001/XMLSchema-instance");

                                    reader.Read();
                                    string contentString = reader.ReadContentAsString();
                                    switch (type)
                                    {
                                        case "xsd:string":
                                            item.Add(new DataHolder(elementName, contentString, UniversalDataType.OctetString));
                                            break;

                                        case "xsd:base64Binary":
                                            var content = Convert.FromBase64String(contentString);
                                            item.Add(new DataHolder(elementName, content, UniversalDataType.OctetString));
                                            break;

                                        default:
                                            throw new NotImplementedException($"Type: {type} has not been implemented. This is used for node {elementName}");
                                    }
                                }
                            } while (reader.NodeType != XmlNodeType.EndElement || reader.LocalName != elementName);
                        }
                    }

                    if (reader.Depth == ldapObjectDepth)
                    {
                        if (item != null && !string.IsNullOrEmpty(dn))
                        {
                            Items.Add(dn, item);
                        }
                        item = new List<DataHolder>();
                        dn = null;
                        reader.Read();
                        if (reader.NodeType == XmlNodeType.EndElement && reader.LocalName.Equals("items", StringComparison.InvariantCultureIgnoreCase))
                        {
                            reader.Read();
                            if (reader.IsStartElement("EndOfSequence", "http://schemas.xmlsoap.org/ws/2004/09/enumeration"))
                            {
                                EndOfSequence = true;
                            }
                        }
                    }
                } while (reader.Read());
            }
        }
    }
}