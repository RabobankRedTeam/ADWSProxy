using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.Xml;

namespace ADWSProxy.ADWS.Request
{
    internal class ADWSException : FaultException
    {
        public ADWSException(MessageFault fault, FaultReason reason, FaultCode code, string ErrorType, Dictionary<string, string> Errors) : base(reason, code)
        {
            Fault = fault ?? throw new ArgumentNullException(nameof(fault));
            this.ErrorType = ErrorType;
            this.Errors = Errors;
        }

        public MessageFault Fault { get; private set; }

        public override string Message => $"ADWS Encountered '{ErrorType}', {JsonConvert.SerializeObject(Errors)}";

        public string ErrorType { get; private set; } = null;
        public Dictionary<string, string> Errors { get; private set; } = new Dictionary<string, string>();

        public static ADWSException FromMessageBuffer(MessageBuffer messageBuffer)
        {
            if (messageBuffer is null)
            {
                throw new ArgumentNullException(nameof(messageBuffer));
            }

            var message = messageBuffer.CreateMessage();
            if (!message.IsFault)
            {
                return null;
            }

            var fault = MessageFault.CreateFault(message, Helpers.BufferSize);
            string errorType = null;
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

            return new ADWSException(fault, fault.Reason, fault.Code, errorType, errors);
        }
    }
}