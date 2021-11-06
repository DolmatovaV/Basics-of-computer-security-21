using System;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

namespace Lab4t2
{
    public class PBKDF2
    {
        public static byte[] GenerateSalt()
        {
            using (var randomNumberGenerator =
            new RNGCryptoServiceProvider())
            {
                var randomNumber = new byte[32];
                randomNumberGenerator.GetBytes(randomNumber);
                return randomNumber;
            }
        }

        public static byte[] HashPasswordSHA512(byte[] toBeHashed, byte[] salt, int numberOfRounds)
        {
            using (var rfc2898 = new Rfc2898DeriveBytes(toBeHashed, salt, numberOfRounds, HashAlgorithmName.SHA512))
            {
                return rfc2898.GetBytes(64);
            }
        }
    }
    class Program
    {
        static void Main(string[] args)
        {
            const string passwordToHash = "Password";
            HashPassword(passwordToHash, 100000, 1); //10 variant = 100 000
            HashPassword(passwordToHash, 150000, 2);   //100 000 + 50 000
            HashPassword(passwordToHash, 200000, 3);
            HashPassword(passwordToHash, 250000, 4);
            HashPassword(passwordToHash, 300000, 5);
            HashPassword(passwordToHash, 350000, 6);
            HashPassword(passwordToHash, 400000, 7);
            HashPassword(passwordToHash, 450000, 8);
            HashPassword(passwordToHash, 500000, 9);
            HashPassword(passwordToHash, 550000, 10);
            Console.ReadLine();
        }
        private static void HashPassword(string passwordToHash,
        int numberOfRounds, int counter)
        {
            var sw = new Stopwatch();
            sw.Start();
            var hashedPassword = PBKDF2.HashPasswordSHA512(
            Encoding.UTF8.GetBytes(passwordToHash),
            PBKDF2.GenerateSalt(),
            numberOfRounds);
            sw.Stop();
            
            Console.WriteLine("Password to hash : " + passwordToHash);
            Console.WriteLine("Hashed Password : " +
            Convert.ToBase64String(hashedPassword));
            Console.WriteLine(counter + ")" + " Iterations <" + numberOfRounds + ">Elapsed Time: " + sw.ElapsedMilliseconds + "ms");
            Console.WriteLine();

        }

    }
    }

