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

            Console.WriteLine("Informe a mensagem que deseja criptografar:");
            string message = Console.ReadLine();

            string encryptedMessage = afln2.Encrypt(message);
            string decryptedMessage = afln2.Decrypt(encryptedMessage);

            stopwatch.Stop();

            Console.WriteLine("====================================================================================");
            Console.WriteLine(String.Format("TAMANHO CHAVE    : {0}", afln2.KeyLength));
            Console.WriteLine(String.Format("VARIAVEL P       : {0}", afln2.P));
            Console.WriteLine(String.Format("VARIAVEL Q       : {0}", afln2.Q));
            Console.WriteLine(String.Format("VARIAVEL M       : {0}", afln2.M));
            Console.WriteLine(String.Format("VARIAVEL N       : {0}", afln2.N));
            Console.WriteLine(String.Format("VARIAVEL E       : {0}", afln2.E));
            Console.WriteLine(String.Format("VARIAVEL D       : {0}", afln2.D));
            Console.WriteLine("====================================================================================");
            Console.WriteLine(String.Format("MENSAGEM         : {0}", message));
            Console.WriteLine("====================================================================================");
            Console.WriteLine(String.Format("CRIPTOGRAFADA    : {0}", encryptedMessage));
            Console.WriteLine("====================================================================================");
            Console.WriteLine(String.Format("DESCRIPTOGRAFADA : {0}", decryptedMessage));
            Console.WriteLine("====================================================================================");
            Console.WriteLine(String.Format("TEMPO DECORRIDO  : {0}", stopwatch.Elapsed));

            Console.Read();
        }
    }
}

