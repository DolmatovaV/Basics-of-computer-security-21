using System;
using System.Security.Cryptography;
using System.Text;


//Lab3 task1


namespace Lab3
{
    class Program
    {
        static void Main(string[] args)
        {
            static byte[] ComputeHashMd5(byte[] dataForHash)
            {
                using (var md5 = MD5.Create())
                {
                    return md5.ComputeHash(dataForHash);
                }
            }

            const string firstMessage = "first message";
            const string firstMessage2 = "first message";
            const string secMesssage = "First message";

            var md5firstM = ComputeHashMd5(Encoding.Unicode.GetBytes(firstMessage));
            var md5firstM2 = ComputeHashMd5(Encoding.Unicode.GetBytes(firstMessage2));
            var md5secM = ComputeHashMd5(Encoding.Unicode.GetBytes(secMesssage));
            Guid guid1 = new Guid(md5firstM);
            Guid guid2 = new Guid(md5firstM2);
            Guid guid3 = new Guid(md5secM);



            Console.WriteLine("MD5:");
            Console.WriteLine("MD5 for first message:");
            Console.WriteLine(firstMessage);
            Console.WriteLine(Convert.ToBase64String(md5firstM));
            Console.WriteLine(guid1);
            Console.WriteLine();
            Console.WriteLine();

            Console.WriteLine("MD5 for first message(2):");
            Console.WriteLine(firstMessage2);
            Console.WriteLine(Convert.ToBase64String(md5firstM2));
            Console.WriteLine(guid2);
            Console.WriteLine();
            Console.WriteLine();

            Console.WriteLine("MD5 for second message");
            Console.WriteLine(secMesssage);
            Console.WriteLine(Convert.ToBase64String(md5secM));
            Console.WriteLine(guid3);
            Console.WriteLine();
            Console.WriteLine();



            static byte[] ComputeHashSha1(byte[] toBeHashed)
            {
                using (var sha1 = SHA1.Create())
                {
                    return sha1.ComputeHash(toBeHashed);
                }
            }

            var sha1forM = ComputeHashSha1(Encoding.Unicode.GetBytes(firstMessage));
            var sha1forM1 = ComputeHashSha1(Encoding.Unicode.GetBytes(firstMessage2));
            var sha1forM2 = ComputeHashSha1(Encoding.Unicode.GetBytes(secMesssage));

            Console.WriteLine("SHA1:");
            Console.WriteLine(firstMessage);
            Console.WriteLine(Convert.ToBase64String(sha1forM));
            Console.WriteLine();

            Console.WriteLine(firstMessage2);
            Console.WriteLine(Convert.ToBase64String(sha1forM1));
            Console.WriteLine();

            Console.WriteLine(secMesssage);
            Console.WriteLine(Convert.ToBase64String(sha1forM2));
            Console.WriteLine();

            static byte[] ComputeHashSha256(byte[] toBeHashed)
            {
                using (var sha256 = SHA256.Create())
                {
                    return sha256.ComputeHash(toBeHashed);
                }
            }
            var sha256forM = ComputeHashSha256(Encoding.Unicode.GetBytes(firstMessage));
            var sha256forM1 = ComputeHashSha256(Encoding.Unicode.GetBytes(firstMessage2));
            var sha256forM2 = ComputeHashSha256(Encoding.Unicode.GetBytes(secMesssage));

            Console.WriteLine("SHA256:");
            Console.WriteLine(firstMessage);
            Console.WriteLine(Convert.ToBase64String(sha256forM));
            Console.WriteLine();

            Console.WriteLine(firstMessage2);
            Console.WriteLine(Convert.ToBase64String(sha256forM1));
            Console.WriteLine();

            Console.WriteLine(secMesssage);
            Console.WriteLine(Convert.ToBase64String(sha256forM2));
            Console.WriteLine();

            static byte[] ComputeHashSha384(byte[] toBeHashed)
            {
                using (var sha384 = SHA384.Create())
                {
                    return sha384.ComputeHash(toBeHashed);
                }
            }

            var sha384forM = ComputeHashSha384(Encoding.Unicode.GetBytes(firstMessage));
            var sha384forM1 = ComputeHashSha384(Encoding.Unicode.GetBytes(firstMessage2));
            var sha384forM2 = ComputeHashSha384(Encoding.Unicode.GetBytes(secMesssage));

            Console.WriteLine("SHA384:");
            Console.WriteLine(firstMessage);
            Console.WriteLine(Convert.ToBase64String(sha384forM));
            Console.WriteLine();

            Console.WriteLine(firstMessage2);
            Console.WriteLine(Convert.ToBase64String(sha384forM1));
            Console.WriteLine();

            Console.WriteLine(secMesssage);
            Console.WriteLine(Convert.ToBase64String(sha384forM2));
            Console.WriteLine();

            static byte[] ComputeHashSha512(byte[] toBeHashed)
            {
                using (var sha512 = SHA512.Create())
                {
                    return sha512.ComputeHash(toBeHashed);
                }
            }

            var sha512forM = ComputeHashSha512(Encoding.Unicode.GetBytes(firstMessage));
            var sha512forM1 = ComputeHashSha512(Encoding.Unicode.GetBytes(firstMessage2));
            var sha512forM2 = ComputeHashSha512(Encoding.Unicode.GetBytes(secMesssage));

            Console.WriteLine("SHA512:");
            Console.WriteLine(firstMessage);
            Console.WriteLine(Convert.ToBase64String(sha512forM));
            Console.WriteLine();

            Console.WriteLine(firstMessage2);
            Console.WriteLine(Convert.ToBase64String(sha512forM1));
            Console.WriteLine();

            Console.WriteLine(secMesssage);
            Console.WriteLine(Convert.ToBase64String(sha512forM2));
            Console.WriteLine();




        }
    }
}
