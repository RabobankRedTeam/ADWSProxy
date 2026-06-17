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
            try
            {
                StringBuilder output = new();

                XmlWriterSettings settings = new()
                {
                    Indent = true,
                    NewLineOnAttributes = false,
                    ConformanceLevel = ConformanceLevel.Fragment,
                    CheckCharacters = false
                };

                var message = messageBuffer.CreateMessage();
                if (message == null || message.IsEmpty)
                {
                    return "[Empty Message]";
                }
                using StringWriter stringWriter = new(output);
                using XmlWriter writer = XmlWriter.Create(stringWriter, settings);
                using (XmlDictionaryWriter dictionaryWriter = XmlDictionaryWriter.CreateDictionaryWriter(writer))
                {
                    message.WriteMessage(dictionaryWriter);
                    dictionaryWriter.Flush();
                }

                return output.ToString();
            }
            catch (Exception ex)
            {
                try
                {
                    using MemoryStream ms = new();
                    using var writer = XmlDictionaryWriter.CreateTextWriter(ms, Encoding.UTF8);
                    messageBuffer.CreateMessage().WriteMessage(writer);
                    writer.Flush();

                    byte[] rawBytes = ms.ToArray();
                    string rawText = Encoding.UTF8.GetString(rawBytes);

                    return rawText.Contains('\0') || rawText.Any(c => char.IsControl(c) && c != '\r' && c != '\n' && c != '\t')
                        ? $"[Malformed XML Payload - Raw Base64 Dump]: {Convert.ToBase64String(rawBytes)}"
                        : $"[Raw Fallback Text]: {rawText}";
                }
                catch (Exception fallbackEx)
                {
                    return $"[Critical Serialization Failure]: Could not interpret message buffer. Native Error: {ex.Message}. Fallback Error: {fallbackEx.Message}";
                }
            }
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