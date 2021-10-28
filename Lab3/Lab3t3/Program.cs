using System;
using System.Security.Cryptography;
using System.Text;


namespace Lab3t3
{
    class Program
    {
        public static byte[] ComputeHmacsha1(byte[] toBeHashed, byte[] key)
        {
            using (var hmac = new HMACSHA1(key))
            {
                return hmac.ComputeHash(toBeHashed);
            }
        }
        static void Main(string[] args)
        {
            const string origMessage = "There is the original message";
            const string damagMessage = "Some message";

            Console.WriteLine($"Our original message: '{origMessage}'");
            Console.WriteLine($"Second message: '{damagMessage}'");

            string CreatePassword(int length)
            {
                const string valid = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
                StringBuilder res = new StringBuilder();
                Random rnd = new Random();
                while (0 < length--)
                {
                    res.Append(valid[rnd.Next(valid.Length)]);
                }
                return res.ToString();
            }
            string key = CreatePassword(5);
            Console.WriteLine($"Only to see the password: {key}");
            string origHash = Convert.ToBase64String(ComputeHmacsha1(Encoding.Unicode.GetBytes(origMessage), Encoding.Unicode.GetBytes(key)));
            Console.WriteLine($"HMAC for original message: {origHash}");
            Console.WriteLine();
            Console.WriteLine();
            void authentication(string message, string key, string origHash)
            {
                var hash = ComputeHmacsha1(Encoding.Unicode.GetBytes(message), Encoding.Unicode.GetBytes(key));
                if (origHash== Convert.ToBase64String(hash)){
                    Console.WriteLine("Message corresponds to original");
                }
                else
                {
                    Console.WriteLine("Message corrupted");
                }
            }
            Console.WriteLine();
            authentication(origMessage, key, origHash);
            Console.WriteLine();
            authentication(damagMessage, key, origHash);


        }
    }
}
