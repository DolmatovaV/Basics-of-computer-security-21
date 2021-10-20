using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace lab2
{
    class Program
    {
        static void Main(string[] args)
        {
            byte[] decData = File.ReadAllBytes("text.txt").ToArray();
            byte[] encData = new byte[decData.Length];
            byte key = 113;
            Console.WriteLine("Unscripted text: ");
            for (int i = 0; i < decData.Length; i++)
            {
                Console.Write((char)decData[i]);
            }
            Console.WriteLine(" ");
            Console.WriteLine(" ");

            for (int i = 0; i < decData.Length; i++)
            {
                encData[i] = (byte)(decData[i] ^ key);
            }
            Console.WriteLine("Scripted:");
            for (int i = 0; i < decData.Length; i++)
            {
                Console.Write((char)encData[i]);
            }
            Console.WriteLine(" ");
            Console.WriteLine(" ");

            File.WriteAllBytes("text.dat", encData);
            Console.WriteLine("Unscripted text after decryption:");

            byte[] encDataNew = File.ReadAllBytes("text.txt").ToArray();
            byte[] decDataNew = new byte[decData.Length];
            for (int i = 0; i < decData.Length; i++)
            {
                decDataNew[i] = (byte)(encData[i] ^ key);
                Console.Write((char)decDataNew[i]);
            }
            Console.WriteLine(" ");





        }
    }
}
