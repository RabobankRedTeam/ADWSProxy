using Flexinets.Ldap.Core;
using System;

namespace ADWSProxy.LDAP
{
    internal class DataHolder
    {
        public DataHolder(string name, object data, UniversalDataType? dataType)
        {
            Name = name ?? throw new ArgumentNullException(nameof(name));
            Data = data ?? throw new ArgumentNullException(nameof(data));
            DataType = dataType ?? throw new ArgumentNullException(nameof(DataType));
        }

        public object Data { get; }
        public UniversalDataType DataType { get; }
        public string Name { get; }
    }
}