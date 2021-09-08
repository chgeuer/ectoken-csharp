namespace ec_encryptcore
{
    using System;
    using ecencryptstdlib;

    class Program
    {
        static void Main(string[] args)
        {
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
                    ? (new ECTokenGenerator.Key(args[0]), new ECTokenGenerator.Token(args[1])) 
                    : (new ECTokenGenerator.Key(args[1]), new ECTokenGenerator.Token(args[2]));

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