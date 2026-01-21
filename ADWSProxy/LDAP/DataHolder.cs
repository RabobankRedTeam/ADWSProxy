using Flexinets.Ldap.Core;

namespace ADWSProxy.LDAP
{
    internal class DataHolder(string name, object data, UniversalDataType? dataType)
    {
        public object Data { get; } = data;
        public UniversalDataType DataType { get; } = dataType ?? throw new ArgumentNullException(nameof(dataType));
        public string Name { get; } = name;
    }
}