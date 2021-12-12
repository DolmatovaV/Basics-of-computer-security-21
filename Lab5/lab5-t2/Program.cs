using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace lab5_t2
{
    class PBKDF2
    {
        public static byte[] GenerateSalt()
        {
            using (var randomNumberGenerator = new RNGCryptoServiceProvider())
            {
                var randomNumber = new byte[32];
                randomNumberGenerator.GetBytes(randomNumber);
                return randomNumber;
            }
        }

        public static byte[] HashKey(byte[] toBeHashed, byte[] salt, int numberOfRounds, System.Security.Cryptography.HashAlgorithmName hashAlgorithm)
        {
            using (var rfc2898 = new Rfc2898DeriveBytes(toBeHashed, salt, numberOfRounds, HashAlgorithmName.SHA512))
            {
                return rfc2898.GetBytes(32);
            }
        }

        public static byte[] HashIv(byte[] toBeHashed, byte[] salt, int numberOfRounds, System.Security.Cryptography.HashAlgorithmName hashAlgorithm)
        {
            using (var rfc2898 = new Rfc2898DeriveBytes(toBeHashed, salt, numberOfRounds, HashAlgorithmName.SHA512))
            {
                return rfc2898.GetBytes(16);
            }
        }
    }

    class aesChipher
    {
        public byte[] Encryption(byte[] dataToEncrypt, byte[] key, byte[] iv)
        {
            using (var aes = new AesCryptoServiceProvider())
            {
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                aes.Key = key;
                aes.IV = iv;
                using (var memoryStream = new MemoryStream())
                {
                    var CryptoStream = new CryptoStream(memoryStream, aes.CreateEncryptor(), CryptoStreamMode.Write);
                    CryptoStream.Write(dataToEncrypt, 0, dataToEncrypt.Length);
                    CryptoStream.FlushFinalBlock();
                    return memoryStream.ToArray();
                }
            }
        }

        public byte[] Decryption(byte[] dataToDecrypt, byte[] key, byte[] iv)
        {
            using (var aes = new AesCryptoServiceProvider())
            {
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                aes.Key = key;
                aes.IV = iv;
                using (var memoryStream = new MemoryStream())
                {
                    var CryptoStream = new CryptoStream(memoryStream, aes.CreateDecryptor(), CryptoStreamMode.Write);
                    CryptoStream.Write(dataToDecrypt, 0, dataToDecrypt.Length);
                    CryptoStream.FlushFinalBlock();
                    return memoryStream.ToArray();
                }
            }
        }
    }

    class Program
    {
        static void Main(string[] args)
        {
            const string message = "Some Text";
            var pass = PBKDF2.GenerateSalt();
            var aes = new aesChipher();
            var key = PBKDF2.HashKey(pass, PBKDF2.GenerateSalt(), 100000, HashAlgorithmName.SHA512);
            var iv = PBKDF2.HashIv(pass, PBKDF2.GenerateSalt(), 100000, HashAlgorithmName.SHA512);
            var enc = aes.Encryption(Encoding.UTF8.GetBytes(message), key, iv);
            var dec = aes.Decryption(enc, key, iv);
            var decMessage = Encoding.UTF8.GetString(dec);

            Console.WriteLine("Message");
            Console.WriteLine(message);
            Console.WriteLine();

            Console.WriteLine("Encrypted");
            Console.WriteLine(Convert.ToBase64String(enc));
            Console.WriteLine();

            Console.WriteLine("Decrypted");
            Console.WriteLine(decMessage);
            Console.WriteLine();
        }
    }
}

