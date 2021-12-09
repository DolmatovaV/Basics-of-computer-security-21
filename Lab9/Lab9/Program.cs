using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Lab9
{
    class Program
    {
        private readonly static string CspContainerName = "RsaContainer";
        public static void GenerateKeys(string publicKeyPath)
        {
            CspParameters cspParameters = new CspParameters(1)
            {
                KeyContainerName = CspContainerName,
                Flags = CspProviderFlags.UseMachineKeyStore
            };

            using (var rsa = new RSACryptoServiceProvider(2048, cspParameters))
            {
                rsa.PersistKeyInCsp = true;
                File.WriteAllText(publicKeyPath, rsa.ToXmlString(false));
            }
        }
        public static byte[] SignData(byte[] dataToSign)
        {
            CspParameters cspParameters = new CspParameters
            {
                KeyContainerName = CspContainerName,
                Flags = CspProviderFlags.UseMachineKeyStore

            };

            using (var rsa = new RSACryptoServiceProvider(2048, cspParameters))
            {
                rsa.PersistKeyInCsp = true;
                var rsaFormatter = new RSAPKCS1SignatureFormatter(rsa);
                rsaFormatter.SetHashAlgorithm(nameof(SHA512));


                byte[] hashData;
                using (var sha512 = SHA512.Create())
                {
                    hashData = sha512.ComputeHash(dataToSign);
                }

                return rsaFormatter.CreateSignature(hashData);
            }
        }


        public static bool Verify(string publicKeyPath, byte[] dataToSign, byte[] Sign)
        {
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.PersistKeyInCsp = false;
                rsa.FromXmlString(File.ReadAllText(publicKeyPath));

                var rsaDeformatter = new RSAPKCS1SignatureDeformatter(rsa);
                rsaDeformatter.SetHashAlgorithm(nameof(SHA512));

                byte[] hashData;
                using (var sha512 = SHA512.Create())
                {
                    hashData = sha512.ComputeHash(dataToSign);
                }
                return rsaDeformatter.VerifySignature(hashData, Sign);



            }
        }


        static void Main(string[] args)
        {
            string data = "Some data";
            byte[] byteData = Encoding.UTF8.GetBytes(data);
            var signedData = SignData(byteData);

            GenerateKeys("Dolmatova(2).xml");

            //bool verData = Verify("Dolmatova.xml", byteData, signedData);
            bool verData = Verify("Dolmatova(2).xml", byteData, signedData);
            if (verData)
            {
                Console.WriteLine("Signature is verified");
            }
            else
            {
                Console.WriteLine("Signature is not verified");
            }



        }
    }
}