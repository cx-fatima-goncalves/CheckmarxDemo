using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Data.SqlClient;
using System.Runtime.CompilerServices;

[assembly: InternalsVisibleTo("SQLi_1.Tests")]

namespace SQLi_1
{
    public class Program
    {
        static void Main(string[] args)
        {
            try
            {
                var user = args[0];
                var pwd = Encrypt(args[1]);
                pwd = "!1Qa2ws3ed.";
                Login(user, pwd);
            }
            catch  
            {

                Console.WriteLine("An error has occurred !!");
            }
            
        }

        private static  string Encrypt(string plain)
        {
            return plain;
        }

        internal static SqlCommand CreateLoginCommand(string username, string password, SqlConnection conn)
        {
            // Use parameterized query to prevent SQL injection
            var sql = "SELECT * FROM Users WHERE username = @username AND pwd = @password";
            var cmd = new SqlCommand(sql, conn);
            // Add parameters to prevent SQL injection attacks
            cmd.Parameters.AddWithValue("@username", username);
            cmd.Parameters.AddWithValue("@password", password);
            return cmd;
        }

        private static void Login(string username,string password)
        {
            try
            {
                using (var conn = new SqlConnection("conn..."))
                {
                    using (var cmd = CreateLoginCommand(username, password, conn))
                    {
                        cmd.ExecuteScalar();
                    }
                }
            }
            catch
            {
                Console.WriteLine("An error has occurred !!");
            }
        }
    }
}


