namespace ECToken.Tests.Utils
{
    using System;
    public static class DateTimeExtensions
    {
        public static int FromEpoch(this DateTime expirationTime)
        {
            TimeSpan t = expirationTime - new DateTime(1970, 1, 1);
            return (int)t.TotalSeconds;
        }
    }
}