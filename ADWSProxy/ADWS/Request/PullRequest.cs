using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Xml;

namespace ADWSProxy.ADWS.Request
{
    internal class PullRequest : ADWSRequest
    {
        public PullRequest(string instance, string enumerationContext) : base(instance: instance)
        {
            if (string.IsNullOrWhiteSpace(enumerationContext))
            {
                throw new ArgumentNullException(nameof(enumerationContext));
            }
            EnumerationContext = enumerationContext;
        }

        public override string Action => "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Pull";

        private List<DirectoryControl> Controls { get; } = new List<DirectoryControl>()
        {
            new DirectoryControl("1.2.840.113556.1.4.801", new byte[] { 0x30, 0x84, 0x00, 0x00, 0x00, 0x03, 0x02, 0x01, 0x07 }, true, true)
        };

        private string EnumerationContext { get; }

        /// <summary>
        /// This is the number of items per page.
        /// </summary>
        private int MaxElements { get; } = 256;

        protected override void OnWriteBodyContents(XmlDictionaryWriter writer)
        {
            writer.WriteStartElement("Pull", "http://schemas.xmlsoap.org/ws/2004/09/enumeration");
            writer.WriteElementString("EnumerationContext", "http://schemas.xmlsoap.org/ws/2004/09/enumeration", EnumerationContext);
            if (MaxElements > 0)
            {
                writer.WriteStartElement("MaxElements", "http://schemas.xmlsoap.org/ws/2004/09/enumeration");
                writer.WriteValue(MaxElements);
                writer.WriteEndElement();
            }
            if (Controls != null && Controls.Count > 0)
            {
                writer.WriteStartElement("controls", "http://schemas.microsoft.com/2008/1/ActiveDirectory");
                foreach (var control in Controls)
                {
                    writer.WriteStartElement("control", "http://schemas.microsoft.com/2008/1/ActiveDirectory");
                    writer.WriteAttributeString("type", control.Type);
                    writer.WriteAttributeString("criticality", control.IsCritical ? "true" : "false");

                    var buffer = control.GetValue();
                    if (buffer != null && buffer.Length > 0)
                    {
                        writer.WriteStartElement("controlValue", "http://schemas.microsoft.com/2008/1/ActiveDirectory");
                        string prefix = writer.LookupPrefix("http://www.w3.org/2001/XMLSchema");
                        writer.WriteAttributeString("type", "http://www.w3.org/2001/XMLSchema-instance", $"{prefix}:base64Binary");
                        writer.WriteBase64(buffer, 0, buffer.Length);
                        writer.WriteEndElement();
                    }
                    writer.WriteEndElement();
                }
                writer.WriteEndElement();
            }

            writer.WriteEndElement();
        }

        protected override void OnWriteStartBody(XmlDictionaryWriter writer)
        {
            base.OnWriteStartBody(writer);
            writer.WriteXmlAttribute("wsen", "http://schemas.xmlsoap.org/ws/2004/09/enumeration");
            writer.WriteXmlAttribute("xsi", "http://www.w3.org/2001/XMLSchema-instance");
            writer.WriteXmlAttribute("xsd", "http://www.w3.org/2001/XMLSchema");
        }
    }
}