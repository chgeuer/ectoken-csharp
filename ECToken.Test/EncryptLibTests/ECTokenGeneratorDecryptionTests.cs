namespace ECToken.Tests.EncryptLibTests
{
    using ecencryptstdlib;
    using Xunit;

    public class ECTokenGeneratorDecryptionTests
    {
        [Fact]
        public void DecryptV3_WithCorrectKey_DecryptsMessage()
        {
            //arrange
            var key = new ECTokenGenerator.Key("thisisakey");
            var encrypted = new ECTokenGenerator.Token("24JJvrIX--LTuT_BN4WTB_n_uNtl91zrGmMzcSiKODAh0FukUT-O0WaudZ4mVc4yJmYp8bGQzIqE6toLqn40GaK98xfDe0xmrgfB46OEQiNGCAErwzed3XAy5a45Z-RVduxvppoUvga17mG8W5mEafPsfU9RgVyH6eajPosJSssIeywFFybVDf4kRZod");
            //act
            var token = encrypted.DecryptV3(key);

            //assert
            Assert.NotNull(token);
            Assert.Equal("ec_expire=1522944645&ec_clientip=0.0.0.0&ec_country_allow=US&ec_country_deny=NA&ec_ref_allow=1234&ec_ref_deny=456", token.Value);
        }
    }
}
