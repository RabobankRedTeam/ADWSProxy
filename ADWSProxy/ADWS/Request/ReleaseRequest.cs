using System;
using System.Xml;

namespace ADWSProxy.ADWS.Request
{
    internal class ReleaseRequest : ADWSRequest
    {
        public ReleaseRequest(string instance, string enumerationContext) : base(instance: instance)
        {
            if (string.IsNullOrWhiteSpace(enumerationContext))
            {
                throw new ArgumentNullException(nameof(enumerationContext));
            }
            EnumerationContext = enumerationContext;
        }

        public override string Action => "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Release";
        private string EnumerationContext { get; }

        protected override void OnWriteBodyContents(XmlDictionaryWriter writer)
        {
            writer.WriteStartElement("Release", "http://schemas.xmlsoap.org/ws/2004/09/enumeration");
            writer.WriteElementString("EnumerationContext", "http://schemas.xmlsoap.org/ws/2004/09/enumeration", EnumerationContext);
            writer.WriteEndElement();
        }

        protected override void OnWriteStartBody(XmlDictionaryWriter writer)
        {
            base.OnWriteStartBody(writer);
            writer.WriteXmlAttribute("wsen", "http://schemas.xmlsoap.org/ws/2004/09/enumeration");
        }
    }
}