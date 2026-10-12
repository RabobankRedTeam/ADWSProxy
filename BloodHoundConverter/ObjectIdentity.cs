namespace BloodHoundConverter
{
    internal class ObjectIdentity
    {
        /// <summary>
        /// This will be the SID of the object, or the GUID if the object does not have a SID
        /// </summary>
        public string Id { get; set; } = string.Empty;
        public ObjectType Type { get; set; } = ObjectType.Base;
        public string? PrimaryGroupSid { get; set; } = null;
    }
}