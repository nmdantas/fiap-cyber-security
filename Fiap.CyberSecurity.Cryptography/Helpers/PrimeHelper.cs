using System;
using System.Numerics;

namespace Fiap.CyberSecurity.Cryptography.Helpers
{
    public static class PrimeHelper
    {
        public static BigInteger GetNextRandom()
        {
            Random random = new Random();            
            BigInteger n = new BigInteger(random.NextDouble() * long.MaxValue);
            BigInteger prime = new BigInteger();

            prime = BigInteger.Pow(n, 2) - n + 41;

            return prime;            
        }
    }
}