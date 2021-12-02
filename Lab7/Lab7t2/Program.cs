using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Lab7t2
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
                cipherbytes = rsa.Encrypt(dataToEncrypt, false);
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
                plainBytes = rsa.Decrypt(dataToDecrypt, false);
            }
            return plainBytes;
        }


        static void Main(string[] args)
        {
            string Message = "Some message";
            AssignNewKey("FileForKey.xml");
            var encrypted = EncryptData("FileForKey.xml", Encoding.Unicode.GetBytes(Message));
            var decrypted = DecryptData(encrypted);
            Console.WriteLine("Original message = " + Message);
            Console.WriteLine("Encrypted message = " + Convert.ToBase64String(encrypted));
            Console.WriteLine("Decrypted message = " + Encoding.UTF8.GetString(decrypted));
        }
    }
}