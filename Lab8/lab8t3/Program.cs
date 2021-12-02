using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace lab8t3
{
    class Program
    {
        private readonly static string CspContainerName = "RsaContainer";
        public static void AssignNewKey(string PublicKeyPath)
        {
            CspParameters cspParameters = new CspParameters(1)
            {
                KeyContainerName = CspContainerName,
                ProviderName = "Microsoft Strong Cryptographic Provider"

            };
            var rsa = new RSACryptoServiceProvider(cspParameters)
            {
                PersistKeyInCsp = true
            };
            File.WriteAllText(PublicKeyPath, rsa.ToXmlString(false));

        }
        public static byte[] EncryptData(string publicKeyPath, byte[] dataToEncrypt)
        {
            byte[] cipherbytes;
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.PersistKeyInCsp = false;
                rsa.FromXmlString(File.ReadAllText(publicKeyPath));
                cipherbytes = rsa.Encrypt(dataToEncrypt, true);
            }
            return cipherbytes;
        }
        public static byte[] DecryptData(byte[] dataToDecrypt)
        {
            byte[] plainBytes;
            var cspParams = new CspParameters
            {
                KeyContainerName = CspContainerName,

            };
            using (var rsa = new RSACryptoServiceProvider(cspParams))
            {
                rsa.PersistKeyInCsp = true;
                plainBytes = rsa.Decrypt(dataToDecrypt, true); 
            }
            return plainBytes;
        }


        static void Main(string[] args)
        {
            string Message = "Hello, Yana!";

            ////Uncomment to encryption
            //var encrypted = EncryptData("TsehelnaYana.xml", Encoding.UTF8.GetBytes(Message));
            //File.WriteAllBytes("MessageForYana(3).dat", encrypted);
            //Console.WriteLine("Message = " + Message);
            //Console.WriteLine();
            //Console.WriteLine("Encrypted message = " + Convert.ToBase64String(encrypted));

            //AssignNewKey("Dolmatova.xml");

            //Uncomment to decryption
            var encryptedmessage = File.ReadAllBytes("MessageForVictoria.dat");
            var decrypted = DecryptData(encryptedmessage);
            Console.WriteLine("Decrypted message = " + Encoding.UTF8.GetString(decrypted));
        }
    }
}
