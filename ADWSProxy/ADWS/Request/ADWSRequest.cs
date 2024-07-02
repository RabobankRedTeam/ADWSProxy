using System.ServiceModel.Channels;
using System.Xml;

namespace ADWSProxy.ADWS.Request
{
    internal abstract class ADWSRequest : ADWSMessage
    {
        private const int _initialHeaderBufferSize = 7;

        protected ADWSRequest(string instance)
        {
            MessageHeaders = new MessageHeaders(Version, _initialHeaderBufferSize);
            Headers.Action = Action;
            Headers.Add(MessageHeader.CreateHeader("instance", "http://schemas.microsoft.com/2008/1/ActiveDirectory", instance));
        }

        protected ADWSRequest(string instance, string objectReferenceProperty) : this(instance: instance)
        {
            if (string.IsNullOrEmpty(objectReferenceProperty))
                return;
            Headers.Add(MessageHeader.CreateHeader(nameof(objectReferenceProperty), "http://schemas.microsoft.com/2008/1/ActiveDirectory", objectReferenceProperty));
        }

        public abstract string Action { get; }
        public override MessageHeaders Headers => MessageHeaders;
        public override MessageProperties Properties => MessageProperties;
        public override MessageVersion Version => MessageVersion.Soap12WSAddressing10;
        private MessageHeaders MessageHeaders { get; }
        private MessageProperties MessageProperties { get; } = new MessageProperties();

        protected abstract override void OnWriteBodyContents(XmlDictionaryWriter writer);

        protected override void OnWriteStartEnvelope(XmlDictionaryWriter writer)
        {
            base.OnWriteStartEnvelope(writer);
            writer.WriteXmlnsAttribute("addata", "http://schemas.microsoft.com/2008/1/ActiveDirectory/Data");
            writer.WriteXmlnsAttribute("ad", "http://schemas.microsoft.com/2008/1/ActiveDirectory");
            writer.WriteXmlnsAttribute("xsd", "http://www.w3.org/2001/XMLSchema");
            writer.WriteXmlnsAttribute("xsi", "http://www.w3.org/2001/XMLSchema-instance");
            if (writer.LookupPrefix("http://www.w3.org/2005/08/addressing") == null)
                writer.WriteXmlnsAttribute("wsa", "http://www.w3.org/2005/08/addressing");

        }

        protected override void OnWriteStartHeaders(XmlDictionaryWriter writer)
        {
            base.OnWriteStartHeaders(writer);
        }
    }
}