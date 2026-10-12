using log4net;
using Newtonsoft.Json;

namespace BloodHoundConverter.Writers
{
    internal class DomainNodeWriter : IADNodeWriter
    {
        internal override ILog Log => LogManager.GetLogger(typeof(DomainNodeWriter));

        public override void WriteNode(JsonTextWriter writer, NodeProcessingContext context)
        {
            writer.WriteStartObject();
            WriteGPOChanges(writer, context);
            WriteProperties(writer, context);

            //TODO: Implement this
            WritePropertyArray(writer, "ChildObjects", []);
            WritePropertyArray(writer, "Trusts", []);
            WritePropertyArray(writer, "Links", []);
            WritePropertyArray(writer, "InheritanceHashes", []);
            var domainParts = context.DomainName.Split('.', StringSplitOptions.RemoveEmptyEntries);
            string? resolvedForestSid = null;
            for (int i = 2; i <= domainParts.Length; i++)
            {
                string candidate = string.Join('.', domainParts[^i..]);

                if (BloodHoundConverter.DomainToSidMap.TryGetValue(candidate, out string? foundSid))
                {
                    resolvedForestSid = foundSid;
                    break; // Matched the shortest valid domain in our map
                }
            }
            WriteProperty(writer, "ForestRootIdentifier", resolvedForestSid, context.DomainSid);
            WriteBaseNodeValues(writer, context, context.ObjectSid);
            AceParser.WriteAcesFromDescriptor(writer, context);

            WriteContaineredBy(writer, context);
            writer.WriteEndObject();
        }

        internal override void WriteProperties(JsonTextWriter writer, NodeProcessingContext context)
        {
            writer.WritePropertyName("Properties");
            writer.WriteStartObject();

            WriteBasePropertyValues(writer, context);

            WriteProperty(writer, "expirepasswordsonsmartcardonlyaccounts", context.GetFirstAttributeValue("msds-expirepasswordsonsmartcardonlyaccounts"));
            WritePropertyInt(writer, "machineaccountquota", context.GetFirstAttributeValue("ms-ds-machineaccountquota"));
            WritePropertyInt(writer, "minpwdlength", context.GetFirstAttributeValue("minpwdlength"));
            WritePropertyInt(writer, "pwdproperties", context.GetFirstAttributeValue("pwdproperties"));
            WritePropertyInt(writer, "pwdhistorylength", context.GetFirstAttributeValue("pwdhistorylength"));
            WritePropertyInt(writer, "lockoutthreshold", context.GetFirstAttributeValue("lockoutthreshold"));
            WriteProperty(writer, "minpwdage", long.TryParse(context.GetFirstAttributeValue("minpwdage"), out long minPwdAge) ? Helpers.ParseAdTimePeriod(minPwdAge) : null);
            WriteProperty(writer, "maxpwdage", long.TryParse(context.GetFirstAttributeValue("maxpwdage"), out long maxPwdAge) ? Helpers.ParseAdTimePeriod(maxPwdAge) : null);
            WriteProperty(writer, "lockoutduration", long.TryParse(context.GetFirstAttributeValue("lockoutduration"), out long lockoutDuration) ? Helpers.ParseAdTimePeriod(lockoutDuration) : null);
            WriteProperty(writer, "lockoutobservationwindow", long.TryParse(context.GetFirstAttributeValue("lockoutobservationwindow"), out long lockoutobservationwindow) ? Helpers.ParseAdTimePeriod(lockoutobservationwindow) : null);
            WriteProperty(writer, "functionallevel", Helpers.ParseBehaviorVersion(context.GetFirstAttributeValue("msds-behavior-version")));
            WriteProperty(writer, "netbios",
                context.GetFirstAttributeValue("name")?.ToUpperInvariant(),
                (context.GetFirstAttributeValue("dc") ?? context.DomainName.Split('.').FirstOrDefault())?.ToUpper());
            WritePropertyBool(writer, "collected", null, true);

            writer.WriteEndObject();
        }
    }
}
