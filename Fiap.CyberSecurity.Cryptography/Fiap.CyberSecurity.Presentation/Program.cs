using Fiap.CyberSecurity.Cryptography;
using System;
using System.Diagnostics;

namespace Fiap.CyberSecurity.Presentation
{
    class Program
    {
        static void Main(string[] args)
        {
            Stopwatch stopwatch = new Stopwatch();
            stopwatch.Start();

            AFLN2 afln2 = new AFLN2(512);
            afln2.GenerateKeys();

            string message = "Tamires da Silva Mota tornou-se Tamires Mota Dantas no dia 23/03/2019";

            string encryptedMessage = afln2.Encrypt(message);
            string decryptedMessage = afln2.Decrypt(encryptedMessage);

            stopwatch.Stop();

            Console.WriteLine(String.Format("KEY LENGTH   : {0}", afln2.KeyLength));
            Console.WriteLine(String.Format("VARIABLE P   : {0}", afln2.P));
            Console.WriteLine(String.Format("VARIABLE Q   : {0}", afln2.Q));
            Console.WriteLine(String.Format("VARIABLE M   : {0}", afln2.M));
            Console.WriteLine(String.Format("VARIABLE N   : {0}", afln2.N));
            Console.WriteLine(String.Format("VARIABLE E   : {0}", afln2.E));
            Console.WriteLine(String.Format("VARIABLE D   : {0}", afln2.D));
            Console.WriteLine("====================================================================================");
            Console.WriteLine(String.Format("MESSAGE      : {0}", message));
            Console.WriteLine("====================================================================================");
            Console.WriteLine(String.Format("ENCRYPTED    : {0}", encryptedMessage));
            Console.WriteLine("====================================================================================");
            Console.WriteLine(String.Format("DECRYPTED    : {0}", decryptedMessage));
            Console.WriteLine("====================================================================================");
            Console.WriteLine(String.Format("TIME ELAPSED : {0}", stopwatch.Elapsed));

            Console.Read();
        }
    }
}

