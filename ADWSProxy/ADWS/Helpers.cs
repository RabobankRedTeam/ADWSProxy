using log4net;
using System.ServiceModel.Channels;
using System.Text;
using System.Xml;

namespace ADWSProxy.ADWS
{
    internal static class Helpers
    {
        public const int BufferSize = int.MaxValue;

        /// <summary>
        /// Stores an entire <see cref="Message"/> into a memory buffer for future access
        /// </summary>
        /// <returns>A newly creacted <see cref="MessageBuffer"/></returns>
        public static MessageBuffer CreateBufferedCopy(this Message message)
        {
            return message.CreateBufferedCopy(maxBufferSize: BufferSize);
        }

        public static string GetMessageString(MessageBuffer messageBuffer)
        {
            XmlWriterSettings settings = new XmlWriterSettings()
            {
                Indent = true,
                NewLineOnAttributes = false
            };
            StringBuilder output = new StringBuilder();
            using (XmlWriter writer = XmlWriter.Create(output, settings))
            {
                using (XmlDictionaryWriter dictionaryWriter = XmlDictionaryWriter.CreateDictionaryWriter(writer))
                {
                    messageBuffer.CreateMessage().WriteMessage(dictionaryWriter);
                }
            }

            return output.ToString();
        }

        public static void WriteMessageToDebug(this MessageBuffer buffer, ILog logger)
        {
            var data = GetMessageString(buffer);
            logger.Debug(data);
        }
    }
}