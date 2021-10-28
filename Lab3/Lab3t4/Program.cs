using System;
using System.Security.Cryptography;
using System.Text;

namespace Lab3t4
{
    class Program
    {
        static void Main(string[] args)
        {

            static byte[] ComputeHashSha512(byte[] toBeHashed)
            {
                using (var sha512 = SHA512.Create())
                {
                    return sha512.ComputeHash(toBeHashed);
                }
            }

            Console.Write("Enter your name:");
            string registerName= Console.ReadLine();
            Console.Write("Enter your password:");
            string registerPassword = Console.ReadLine();
            Console.WriteLine();
            Console.WriteLine("Register completed");

            var scriptedPW = ComputeHashSha512(Encoding.Unicode.GetBytes(registerPassword));
            Console.WriteLine($"(In order to see the hash {Convert.ToBase64String(scriptedPW)})");

            Console.WriteLine("Enter your name for autorization:");
            string authName = Console.ReadLine();
            Console.WriteLine("Enter your password for autorization:");
            string authPW = Console.ReadLine();

            var authScriptedPW = ComputeHashSha512(Encoding.Unicode.GetBytes(authPW));
            Console.WriteLine($"(In order to see the hash {Convert.ToBase64String(authScriptedPW)})");
            Console.WriteLine();

            if (registerName==authName && scriptedPW.Length == authScriptedPW.Length)
            {
                int i = 0;
                while ((i < scriptedPW.Length) && (scriptedPW[i] == authScriptedPW[i]))
                {
                    i++;
                }
                if (i == scriptedPW.Length)
                {
                    Console.WriteLine("Authorization successful");
                }else
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
