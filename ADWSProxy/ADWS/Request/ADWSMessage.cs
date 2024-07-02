using System.ServiceModel.Channels;
using System.Xml;

namespace ADWSProxy.ADWS.Request
{
    internal abstract class ADWSMessage : Message
    {
        public override string ToString()
        {
            if (State == MessageState.Read || State == MessageState.Closed)
                return $"{State}:{base.ToString()}";

            return $"{State}:{Helpers.GetMessageString(CreateBufferedCopy(Helpers.BufferSize))}";
        }

        protected override void OnWriteBodyContents(XmlDictionaryWriter writer)
        {
        }

        protected override void OnWriteStartEnvelope(XmlDictionaryWriter writer)
        {
            base.OnWriteStartEnvelope(writer);
        }

        protected override void OnWriteStartHeaders(XmlDictionaryWriter writer)
        {
            base.OnWriteStartHeaders(writer);
        }
    }
}