namespace ec_encryptcore
{
    using System;
    using ecencryptstdlib;

    class Program
    {
        static void Main(string[] args)
        {

            string c = "24JJvrIX--LTuT_BN4WTB_n_uNtl91zrGmMzcSiKODAh0FukUT-O0WaudZ4mVc4yJmYp8bGQzIqE6toLqn40GaK98xfDe0xmrgfB46OEQiNGCAErwzed3XAy5a45Z-RVduxvppoUvga17mG8W5mEafPsfU9RgVyH6eajPosJSssIeywFFybVDf4kRZod";
            Console.WriteLine(EdgeCastToken.Create(c).DecryptV3(new EdgeCastKey("thisisakey")).Value);

            return;


            EdgeCastKey k = new("primary202109099dc4cf480b17a94f5eef938bdb08c18535bcc777cc0420c29133d0134d635aa78a1e28f6b883619ed5f920bd3cd79bfe10c42b5d96b7eeb84571ceee4cb51d89");

            string v = ECTokenGenerator.EncryptV3(
                key: k,
                expirationTime: DateTime.UtcNow.AddDays(365)).Value;


            Console.WriteLine(v);

            Console.WriteLine(EdgeCastToken.Create(v).DecryptV3(k).Value);
            Console.WriteLine($"https://bltdemo202109091.azureedge.net/assets/1.svg?t={v}");
            return;

            try
            {
                if (args.Length == 1)
                {
                    Console.WriteLine("EC Token encryption and decryption utility.  Version: 3.0.0");
                    Console.WriteLine(".NET Core Version supported by ecencryptstdlib (.NET Standard 1.4) ");
                    Environment.Exit(0);
                }

                if (args.Length < 2)
                {
                    // display some examples of how to use this application
                    Console.WriteLine("----------------------------------------------------------------");
                    Console.WriteLine("| Usage / Help:");
                    Console.WriteLine("|       ec_encryptcore.exe <key> <text>             | create v3 encrypt token using <text> and <key>");
                    Console.WriteLine("|       ec_encryptcore.exe decrypt <key> <text>     | decrypt token");
                    Console.WriteLine("---------------------------------------------------------------");
                    Environment.Exit(1);
                }

                bool isEncrypt = args[0] != "decrypt";

                var (key, strToken) = isEncrypt 
                    ? (new EdgeCastKey(args[0]), new EdgeCastToken(args[1])) 
                    : (new EdgeCastKey(args[1]), new EdgeCastToken(args[2]));

                var result = isEncrypt
                    ? strToken.EncryptV3(key)
                    : strToken.DecryptV3(key);

                Console.WriteLine(result);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Exception occured while encrypting/decrypting token: {ex.Message}");
            }
        }
    }
}