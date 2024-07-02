using System;
using System.ServiceModel.Channels;
using System.Xml;

namespace ADWSProxy.ADWS.Request
{
    internal class RenewResponse : ADWSResponse
    {
        public RenewResponse(Message response) : base(response)
        {
        }

        public string EnumerateContext { get; set; }
        public DateTime Expiration { get; set; }

        protected override void OnReadBodyContents(XmlDictionaryReader reader)
        {
            reader.ReadStartElement("RenewResponse", "http://schemas.xmlsoap.org/ws/2004/09/enumeration");
            do
            {
                if (reader.NodeType == XmlNodeType.Element)
                {
                    if (reader.LocalName == "Expires")
                    {
                        var expirationString = reader.ReadElementContentAsString();

                        Expiration = XmlConvert.ToDateTime(expirationString, XmlDateTimeSerializationMode.Utc);
                    }
                    if (reader.LocalName == "EnumerationContext")
                    {
                        EnumerateContext = reader.ReadElementContentAsString();
                    }
                }
            } while (reader.Read());
        }
    }
}