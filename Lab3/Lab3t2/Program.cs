using System;
using System.Security.Cryptography;
using System.Text;



//Lab3 task2


namespace Lab3t2
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

            Guid guid = new Guid("564c8da6-0440-88ec-d453-0bbad57c6036");
            

            
            for (int i = 100000000; i < 200000000; i++)
            {
                var md5 = ComputeHashMd5(Encoding.Unicode.GetBytes(i.ToString().Substring(1, 8)));
                if (new Guid(md5) == guid)
                {
                    Console.WriteLine("Password= " + i);
                    Console.WriteLine(Convert.ToBase64String(md5));
                    
                }
            }



        }
    }
}
