using Newtonsoft.Json;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.Xml;

namespace ADWSProxy.ADWS.Request
{
    internal class ADWSException(MessageFault fault, FaultReason reason, FaultCode code, string action, string? ErrorType, Dictionary<string, string> Errors) : FaultException(reason, code, action)
    {
        public MessageFault Fault { get; private set; } = fault ?? throw new ArgumentNullException(nameof(fault));

        public override string Message => $"ADWS Encountered '{ErrorType}', {JsonConvert.SerializeObject(Errors)}";

        public string? ErrorType { get; private set; } = ErrorType;
        public Dictionary<string, string> Errors { get; private set; } = Errors;

        public static ADWSException FromMessageBuffer(MessageBuffer messageBuffer)
        {
            ArgumentNullException.ThrowIfNull(messageBuffer);

            var message = messageBuffer.CreateMessage();
            if (!message.IsFault)
            {
                throw new Exception("Tried to throw an ADWSException for a non faulted message");
            }

            var fault = MessageFault.CreateFault(message, Helpers.BufferSize);
            string? errorType = null;
            var errors = new Dictionary<string, string>();
            if (fault.HasDetail)
            {
                XmlReader reader = fault.GetReaderAtDetailContents();
                if (reader.IsStartElement("FaultDetail", "http://schemas.microsoft.com/2008/1/ActiveDirectory"))
                {
                    reader.Read();
                    errorType = reader.LocalName;

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
                                    errors.Add(elementName, nodeValue);
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

            return new ADWSException(fault, fault.Reason, fault.Code, message.Headers.Action, errorType, errors);
        }
    }
}