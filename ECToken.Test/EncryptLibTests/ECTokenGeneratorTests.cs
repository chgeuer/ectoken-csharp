namespace ECToken.Tests.EncryptLibTests
{
    using ecencryptstdlib;
    using ECToken.Tests.Utils;
    using System;
    using Xunit;


    public class ECTokenGeneratorTests
    {
        [Fact]
        public void EncryptV3_WithDateTimeAndClientIP_ReturnsEcnryptedTokenWithBoth()
        {
            //arrange

            var expireTime = DateTime.Now.AddMilliseconds(300);
            string clientIp = Faker.Internet.IPv4Address();
            EdgeCastKey key = new (Faker.Name.FullName());

            //act
            var token = ECTokenGenerator.EncryptV3(
                key: key, 
                expirationTime: expireTime, 
                clientIPAddress: clientIp);

            //assert

            Assert.NotNull(token);
            var decryptdToken = token.DecryptV3(key);

            string expected = $"ec_expire={expireTime.FromEpoch()}&ec_clientip={clientIp}";
            Assert.Equal(expected, decryptdToken.Value);
        }

        [Fact]
        public void EncryptV3_WithDateTimeOnly_ReturnsEncryptedTokenWithOnlyDate()
        {
            //arrange
            var expireTime = DateTime.Now.AddMilliseconds(300);
            EdgeCastKey key = new (Faker.Name.FullName());

            //act
            var token = ECTokenGenerator.EncryptV3(
                key: key,
                expirationTime: expireTime);

            //assert
            Assert.NotNull(token);
            var decryptdToken = token.DecryptV3(key);

            string expected = $"ec_expire={expireTime.FromEpoch()}";
            Assert.Equal(expected, decryptdToken.Value);
        }
    }
}
