using System.Xml;

namespace ADWSProxy.ADWS.Request
{
    internal class GetRequest : ADWSRequest
    {
        public GetRequest(string instance) : base(instance: instance, objectReferenceProperty: "11111111-1111-1111-1111-111111111111")
        {
        }

        public override string Action => "http://schemas.xmlsoap.org/ws/2004/09/transfer/Get";

        protected override void OnWriteBodyContents(XmlDictionaryWriter writer)
        {
            return;
        }
    }
}