using System.ServiceModel.Channels;
using System.Xml;

namespace ADWSProxy.ADWS.Request
{
    internal abstract class ADWSResponse : ADWSMessage
    {
        protected ADWSResponse(Message response) => DeserializeMessage(response);

        public override MessageHeaders Headers
        {
            get
            {
                return Response == null ? throw new ObjectDisposedException(nameof(Response)) : Response.Headers;
            }
        }

        public override bool IsEmpty => Response?.IsEmpty ?? throw new NullReferenceException();
        public override bool IsFault => Response?.IsFault ?? throw new NullReferenceException();

        public override MessageProperties Properties
        {
            get
            {
                return Response == null ? throw new ObjectDisposedException(nameof(Response)) : Response.Properties;
            }
        }

        public override MessageVersion Version
        {
            get
            {
                return Response == null ? throw new ObjectDisposedException(nameof(Response)) : Response.Version;
            }
        }

        internal string? ObjectReference { get; private set; } = null;
        private Message? Response { get; set; }

        protected void DeserializeMessage(Message response)
        {
            this.OnReadHeaders(response.Headers);
            if (!response.IsEmpty)
            {
                using XmlDictionaryReader reader = response.GetReaderAtBodyContents();
                OnReadBodyContents(reader);
            }
            Response = response;
        }

        protected override void OnClose()
        {
            base.OnClose();
            Response?.Close();
        }

        protected abstract void OnReadBodyContents(XmlDictionaryReader reader);

        protected virtual void OnReadHeaders(MessageHeaders headers)
        {
            var objectReferenceHeader = headers.FindHeader("objectReferenceProperty", "http://schemas.microsoft.com/2008/1/ActiveDirectory");
            if (objectReferenceHeader > 0)
            {
                ObjectReference = headers.GetReaderAtHeader(objectReferenceHeader).ReadElementString("objectReferenceProperty", "http://schemas.microsoft.com/2008/1/ActiveDirectory");
            }
        }
    }
}
