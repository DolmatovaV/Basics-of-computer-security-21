using System;
using System.Collections.Generic;
using System.Security;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading;

namespace Lab11
{
    //roles: administrator, moderator, user, guest

    class PBKDF2
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
    class User
    {
        public string Login { get; set; }
        public string PasswordHash { get; set; }
        public string Salt { get; set; }
        public string[] Roles { get; set; }
    }

    class Protector
    {
        private static Dictionary <string, User> _users = new Dictionary <string, User>();

        public static User Register(string userName, string password, string[] roles = null)
        {
            if (_users.ContainsKey(userName))
            {
                Console.WriteLine("Already registred");
                return null;
            }
            else
            {
                User newUser = new User();
                byte[] salt = PBKDF2.GenerateSalt();
                byte[] hashedPassword = PBKDF2.HashPasswordSHA512(Encoding.Default.GetBytes(password), salt, 100000);
                newUser.Login = userName;
                newUser.Salt = Convert.ToBase64String(salt);
                newUser.PasswordHash = Convert.ToBase64String(hashedPassword);
                newUser.Roles = roles;
                _users.Add(userName, newUser);
                Console.WriteLine("Registration complete");
                return null;
            }

        }
        public static bool CheckPassword(string userName, string password)
        {
            if (_users.ContainsKey(userName))
            {
                var nameToCheck = _users[userName];
                var hashToCheck = PBKDF2.HashPasswordSHA512(Encoding.Default.GetBytes(password), Convert.FromBase64String(nameToCheck.Salt), 100000);
                if (Convert.ToBase64String(hashToCheck) == nameToCheck.PasswordHash)
                {
                    return true;
                }
                else
                {
                    Console.WriteLine("Wrong password");
                    return false;
                }
            }
            else
            {
                Console.WriteLine("User not registred yet");
                return false;
            }
        }

        public static void LogIn(string userName, string password)
        {
            if (CheckPassword(userName, password))
            {
                var identity = new GenericIdentity(userName, "OIBAuth");
                var principal = new GenericPrincipal(identity, _users[userName].Roles);
                System.Threading.Thread.CurrentPrincipal = principal;
            }
        }

        public static void OnlyForAdminsFeature()
        {
            if (Thread.CurrentPrincipal == null)
            {
                throw new SecurityException("Thread.CurrentPrincipal cannot be null.");
            }
            if (!Thread.CurrentPrincipal.IsInRole("admin"))
            {
                throw new SecurityException("User must be a member of Admins to access this feature.");
            }
            Console.WriteLine("You have access to this admin feature.");
        }

        public static void ModerFeature()
        {
            if (Thread.CurrentPrincipal == null)
            {
                throw new SecurityException("Thread.CurrentPrincipal cannot be null.");
            }
            if (!Thread.CurrentPrincipal.IsInRole("mod") && (!Thread.CurrentPrincipal.IsInRole("admin")))
            {
                throw new SecurityException("User must be a member of Admins or Moderators to access this feature.");
            }
            Console.WriteLine("You have access to this moderator feature.");
        }

        public static void UserFeature()
        {
            if (Thread.CurrentPrincipal == null)
            {
                throw new SecurityException("Thread.CurrentPrincipal cannot be null.");
            }
            if (!Thread.CurrentPrincipal.IsInRole("user") && (!Thread.CurrentPrincipal.IsInRole("guest")) &&(!Thread.CurrentPrincipal.IsInRole("mod"))&&(!Thread.CurrentPrincipal.IsInRole("admin")))
            {
                throw new SecurityException("User must be a member of user to access this feature.");
            }
            Console.WriteLine("You have access to this user feature.");
        }
    }


    class Program
    {
        static void Main(string[] args)
        {

            int counter = 0;
            while (counter < 4)
            {
                Console.Write("Enter login: ");
                var login = Console.ReadLine();
                Console.Write("Enter password: ");
                var pass = Console.ReadLine();
                Console.Write("Enter roles: ");
                string rolesString = Console.ReadLine();

                string[] roles = rolesString.Split(" ");



                Protector.Register(login, pass, roles);
                Console.WriteLine();
                counter++;
            }


            while (true)
            {
                Console.WriteLine("Now you can log in");
                Console.WriteLine();
                Console.Write("Enter login: ");
                string entLog = Convert.ToString(Console.ReadLine());
                Console.Write("Enter password: ");
                string entPass = Convert.ToString(Console.ReadLine());

                if (Protector.CheckPassword(entLog, entPass))
                {
                    Protector.LogIn(entLog, entPass);

                }

                try
                {
                    Protector.UserFeature();
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"{ex.GetType()}: {ex.Message}");
                }
                try
                {
                    Protector.ModerFeature();
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"{ex.GetType()}: {ex.Message}");
                }

                try
                {
                    Protector.OnlyForAdminsFeature();
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"{ex.GetType()}: {ex.Message}");
                }
            }
            
        }
    }
}
