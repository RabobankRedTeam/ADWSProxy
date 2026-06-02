using System.Xml;

namespace ADWSProxy.ADWS.Request
{
    internal class EnumerateRequest(string instance, string filter, string searchBase, string searchScope, IList<string> attributes) : ADWSRequest(instance: instance)
    {
        public override string Action => "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate";
        private IList<string> Attributes { get; } = attributes;
        private string Filter { get; } = filter;
        private string SearchBase { get; } = searchBase;
        private string SearchScope { get; } = searchScope;

        protected override void OnWriteBodyContents(XmlDictionaryWriter writer)
        {
            writer.WriteXmlnsAttribute("wsen", "http://schemas.xmlsoap.org/ws/2004/09/enumeration");
            writer.WriteXmlnsAttribute("adlq", "http://schemas.microsoft.com/2008/1/ActiveDirectory/Dialect/LdapQuery");

            writer.WriteStartElement("Enumerate", "http://schemas.xmlsoap.org/ws/2004/09/enumeration");

            writer.WriteStartElement("Filter", "http://schemas.xmlsoap.org/ws/2004/09/enumeration");
            writer.WriteAttributeString("Dialect", "http://schemas.microsoft.com/2008/1/ActiveDirectory/Dialect/LdapQuery");

            writer.WriteStartElement("LdapQuery", "http://schemas.microsoft.com/2008/1/ActiveDirectory/Dialect/LdapQuery");
            writer.WriteXmlnsAttribute("adlq", "http://schemas.microsoft.com/2008/1/ActiveDirectory/Dialect/LdapQuery");
            writer.WriteElementString("Filter", "http://schemas.microsoft.com/2008/1/ActiveDirectory/Dialect/LdapQuery", Filter);
            writer.WriteElementString("BaseObject", "http://schemas.microsoft.com/2008/1/ActiveDirectory/Dialect/LdapQuery", SearchBase);
            writer.WriteElementString("Scope", "http://schemas.microsoft.com/2008/1/ActiveDirectory/Dialect/LdapQuery", SearchScope);
            writer.WriteEndElement();
            writer.WriteEndElement();

            if (Attributes != null && Attributes.Count > 0)
            {
                writer.WriteStartElement("Selection", "http://schemas.microsoft.com/2008/1/ActiveDirectory");
                writer.WriteAttributeString("Dialect", "http://schemas.microsoft.com/2008/1/ActiveDirectory/Dialect/XPath-Level-1");
                foreach (var attr in Attributes)
                {
                    if (attr.Equals("distinguishedname", StringComparison.OrdinalIgnoreCase))
                    {
                        writer.WriteElementString("ad", "SelectionProperty", null, "ad:distinguishedName");
                    }
                    else if (attr.Equals("*", StringComparison.OrdinalIgnoreCase))
                    {
                        writer.WriteElementString("ad", "SelectionProperty", null, "ad:all");
                    }
                    else if (attr.Equals("**", StringComparison.OrdinalIgnoreCase))
                    {
                        writer.WriteElementString("ad", "SelectionProperty", null, "addata:all");
                    }
                    else
                    {
                        writer.WriteElementString("ad", "SelectionProperty", null, $"addata:{attr}");
                    }
                }
                writer.WriteEndElement();
            }

            writer.WriteEndElement();
        }
    }
}