namespace BloodHoundConverter
{
    internal class ObjectIdentitySidComparer : IEqualityComparer<ObjectIdentity>
    {
        public bool Equals(ObjectIdentity? x, ObjectIdentity? y)
        {
            if (ReferenceEquals(x, y)) return true;
            if (x is null || y is null) return false;
            return string.Equals(x.Id, y.Id, StringComparison.OrdinalIgnoreCase);
        }

        public int GetHashCode(ObjectIdentity obj)
        {
            return obj.Id?.ToUpperInvariant().GetHashCode() ?? 0;
        }
    }
}