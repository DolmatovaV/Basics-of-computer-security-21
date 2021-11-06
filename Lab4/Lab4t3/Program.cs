using System;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

namespace Lab4t3
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
        public static byte[] HashPassword(byte[] toBeHashed,
        byte[] salt, int numberOfRounds)
        {
            using (var rfc2898 = new Rfc2898DeriveBytes(
            toBeHashed, salt, numberOfRounds))
            {
                return rfc2898.GetBytes(20);
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
            byte[] salt = PBKDF2.GenerateSalt();
            Console.Write("Enter your name:");
            string registerName = Console.ReadLine();
            Console.Write("Enter your password:");
            var scriptedPW = PBKDF2.HashPasswordSHA512(Encoding.Unicode.GetBytes(Console.ReadLine()), salt, 100000);
            Console.WriteLine($"(In order to see the hash {Convert.ToBase64String(scriptedPW)})");
            Console.WriteLine("Register completed");


            Console.WriteLine("Enter your name for autorization:");
            string authName = Console.ReadLine();
            Console.WriteLine("Enter your password for autorization:");
            var authScriptedPW = PBKDF2.HashPasswordSHA512(Encoding.Unicode.GetBytes(Console.ReadLine()), salt, 100000);
            Console.WriteLine($"(In order to see the hash {Convert.ToBase64String(authScriptedPW)})");
            if (registerName == authName && scriptedPW.Length == authScriptedPW.Length)
            {
                int i = 0;
                while ((i < scriptedPW.Length) && (scriptedPW[i] == authScriptedPW[i]))
                {
                    i++;
                }
                if (i == scriptedPW.Length)
                {
                    Console.WriteLine("Authorization successful");
                }
                else
                {
                    Console.WriteLine("Wrong login or password");
                }
            }
            else
            {
                 Console.WriteLine("Wrong login or password");
            }
        }
    }
    }

