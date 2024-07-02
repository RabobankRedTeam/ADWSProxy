using System;
using System.Xml;

namespace ADWSProxy.ADWS.Request
{
    internal class RenewRequest : ADWSRequest
    {
        public RenewRequest(string instance, string enumerationContext, DateTime? expires) : base(instance: instance)
        {
            if (string.IsNullOrWhiteSpace(enumerationContext))
            {
                throw new ArgumentNullException(nameof(enumerationContext));
            }
            EnumerationContext = enumerationContext;
            Expires = expires;
        }

        public override string Action => "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Renew";
        private string EnumerationContext { get; }
        private DateTime? Expires { get; }

        protected override void OnWriteBodyContents(XmlDictionaryWriter writer)
        {
            writer.WriteStartElement("Renew", "http://schemas.xmlsoap.org/ws/2004/09/enumeration");
            writer.WriteElementString("EnumerationContext", "http://schemas.xmlsoap.org/ws/2004/09/enumeration", EnumerationContext);
            if (Expires.HasValue)
            {
                writer.WriteStartElement("Expires", "http://schemas.xmlsoap.org/ws/2004/09/enumeration");
                writer.WriteValue(XmlConvert.ToString(Expires.Value, XmlDateTimeSerializationMode.Utc));
                writer.WriteEndElement();
            }
            writer.WriteEndElement();
        }

        protected override void OnWriteStartBody(XmlDictionaryWriter writer)
        {
            base.OnWriteStartBody(writer);
            writer.WriteXmlAttribute("wsen", "http://schemas.xmlsoap.org/ws/2004/09/enumeration");
        }
    }
}