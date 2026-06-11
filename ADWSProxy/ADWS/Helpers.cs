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
            StringBuilder output = new();

            XmlWriterSettings settings = new()
            {
                Indent = true,
                NewLineOnAttributes = false,
                ConformanceLevel = ConformanceLevel.Fragment,
                CheckCharacters = false
            };

            using StringWriter stringWriter = new(output);
            using XmlWriter writer = XmlWriter.Create(stringWriter, settings);
            using (XmlDictionaryWriter dictionaryWriter = XmlDictionaryWriter.CreateDictionaryWriter(writer))
            {
                messageBuffer.CreateMessage().WriteMessage(dictionaryWriter);
                dictionaryWriter.Flush();
            }

            return output.ToString();
        }

        public static void WriteMessageToDebug(this MessageBuffer buffer, ILog logger, string title)
        {
            if (logger.IsDebugEnabled)
            {
                string sizeTelemetry = $"[Size: {buffer.BufferSize:N0} bytes]";
                try
                {

                    var data = GetMessageString(buffer);

                    logger.Debug($"{title}-{sizeTelemetry}\n{data}");

                }
                catch (Exception ex)
                {
                    logger.Error($"Failed to write message, {title}, to debug. Size: {sizeTelemetry} bytes", ex);
                }
            }
        }
    }
}