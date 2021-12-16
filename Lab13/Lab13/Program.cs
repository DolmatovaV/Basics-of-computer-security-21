using System;
using System.Collections.Generic;
using System.Security;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading;
using NLog;
using Microsoft.Extensions.Logging;

namespace Lab13
{
    //roles: administrator, moderator, user, guest

    class PBKDF2
    {
        private static Logger log = NLog.LogManager.GetCurrentClassLogger();
        public static byte[] GenerateSalt()
        {
            
            using (var randomNumberGenerator =
            new RNGCryptoServiceProvider())
            {
                
                var randomNumber = new byte[32];
                randomNumberGenerator.GetBytes(randomNumber);
                log.Trace($"{randomNumber} to randomNumber");
                log.Debug($"{randomNumber} to randomNumber");
                return randomNumber;
            }
        }

        public static byte[] HashPasswordSHA512(byte[] toBeHashed, byte[] salt, int numberOfRounds)
        {
            log.Trace($"creating Rfc2898DeriveBytes");
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
        private static Logger log = NLog.LogManager.GetCurrentClassLogger();
        
        private static Dictionary<string, User> _users = new Dictionary<string, User>();

        public static User Register(string userName, string password, string[] roles = null)
        {
            log.Trace($"Checking Name before registration");
            log.Debug($"Checking Name before registration");
            if (_users.ContainsKey(userName))
            {
                log.Warn("Already registred user");
                Console.WriteLine("Already registred");
                return null;
            }
            else
            {
                log.Info("registration of new user");
                log.Trace("creating new user");
                User newUser = new User();
                log.Trace("generate salt");
                log.Debug("generate salt");
                byte[] salt = PBKDF2.GenerateSalt();
                log.Trace("hash password");
                log.Debug("hash password");
                byte[] hashedPassword = PBKDF2.HashPasswordSHA512(Encoding.Default.GetBytes(password), salt, 100000);
                log.Trace("save user info");
                log.Debug("save user info");
                newUser.Login = userName;
                newUser.Salt = Convert.ToBase64String(salt);
                newUser.PasswordHash = Convert.ToBase64String(hashedPassword);
                newUser.Roles = roles;
                log.Trace("add user to dictionary");
                log.Debug("add user to dictionary");
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
                log.Trace($"create temporary var for name. Now it is {_users[userName]}");
                log.Debug($"create temporary var for name. Now it is {_users[userName]}");
                
                var hashToCheck = PBKDF2.HashPasswordSHA512(Encoding.Default.GetBytes(password), Convert.FromBase64String(nameToCheck.Salt), 100000);
                log.Debug($"create temporary var for hash. {hashToCheck}");
                log.Trace($"create temporary var for hash. {hashToCheck}");

                if (Convert.ToBase64String(hashToCheck) == nameToCheck.PasswordHash)
                {
                    log.Info("correct password");
                    return true;
                }
                else
                {
                    Console.WriteLine("Wrong password");
                    log.Warn("wrong password");
                    return false;
                }

            }
            else
            {
                Console.WriteLine("User not registred yet");
                log.Warn("wrong login");
                return false;
            }
        }

        public static void LogIn(string userName, string password)
        {
            if (CheckPassword(userName, password))
            {

                var identity = new GenericIdentity(userName, "OIBAuth");
                var principal = new GenericPrincipal(identity, _users[userName].Roles);

                log.Trace($"two vars to authorize. {identity} and {principal}");
                System.Threading.Thread.CurrentPrincipal = principal;
            }
        }

        public static void OnlyForAdminsFeature()
        {
            if (Thread.CurrentPrincipal == null)
            {
                log.Warn("Thread.CurrentPrincipal cannot be null");
                log.Error("Thread.CurrentPrincipal can`t be null");
                throw new SecurityException("Thread.CurrentPrincipal cannot be null.");
            }
            if (!Thread.CurrentPrincipal.IsInRole("admin"))
            {
                log.Warn("no right to access");
                log.Error("no right to access");
                throw new SecurityException("User must be a member of Admins to access this feature.");
            }
            Console.WriteLine("You have access to this admin feature.");
            log.Trace("access to admin feature");
        }

        public static void ModerFeature()
        {
            if (Thread.CurrentPrincipal == null)
            {
                log.Warn("Thread.CurrentPrincipal cannot be null");
                log.Error("Thread.CurrentPrincipal can`t be null");
                throw new SecurityException("Thread.CurrentPrincipal cannot be null.");
            }
            if (!Thread.CurrentPrincipal.IsInRole("mod") && (!Thread.CurrentPrincipal.IsInRole("admin")))
            {
                log.Warn("no right to access");
                log.Error("no right to access");
                throw new SecurityException("User must be a member of Admins or Moderators to access this feature.");
            }
            Console.WriteLine("You have access to this moderator feature.");
            log.Trace("access to moderator feature");
        }

        public static void UserFeature()
        {
            if (Thread.CurrentPrincipal == null)
            {
                log.Warn("Thread.CurrentPrincipal cannot be null");
                log.Error("Thread.CurrentPrincipal can`t be null");
                throw new SecurityException("Thread.CurrentPrincipal cannot be null.");
            }
            if (!Thread.CurrentPrincipal.IsInRole("user") && (!Thread.CurrentPrincipal.IsInRole("guest")) && (!Thread.CurrentPrincipal.IsInRole("mod")) && (!Thread.CurrentPrincipal.IsInRole("admin")))
            {
                log.Warn("no right to access");
                log.Error("no right to access");
                throw new SecurityException("User must be a member of user to access this feature.");
            }
            Console.WriteLine("You have access to this user feature.");
            log.Trace("access to userfeature");
        }
    }


    class Program
    {


        static void Main(string[] args)
        {
            Logger log = NLog.LogManager.GetCurrentClassLogger();


            int counter = 0;
            log.Debug("counter = 0");
            log.Trace("start registration");
            while (counter < 4)
            {
                log.Trace($"user №{counter}");
                Console.Write("Enter login: ");
                var login = Console.ReadLine();
                log.Debug($"var for login {login}");
                Console.Write("Enter password: ");
                var pass = Console.ReadLine();
                log.Debug($"var for password {pass}");
                Console.Write("Enter roles: ");
                string rolesString = Console.ReadLine();
                log.Debug("var for string");

                string[] roles = rolesString.Split(" ");
                log.Debug("string array");


                Protector.Register(login, pass, roles);
                log.Info($"registration of user №{counter} complete");
                Console.WriteLine();
                counter++;
            }


            log.Trace("start login");
            while (true)
            {
                Console.WriteLine("Now you can log in");
                Console.WriteLine();
                Console.Write("Enter login: ");
                string enteredLogin = Convert.ToString(Console.ReadLine());
                log.Trace("var for entered login");
                log.Debug("var for entered login");
                Console.Write("Enter password: ");
                log.Trace("var for entered password");
                log.Debug("var for entered password");
                string enteredPassword = Convert.ToString(Console.ReadLine());

                if (Protector.CheckPassword(enteredLogin, enteredPassword)==true)
                {
                    Protector.LogIn(enteredLogin, enteredPassword);
                log.Trace("check features");

                //logs for special features are in protector
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
}

