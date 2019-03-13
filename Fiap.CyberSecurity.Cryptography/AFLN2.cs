using System;
using System.Numerics;
using Fiap.CyberSecurity.Cryptography.Helpers;

namespace Fiap.CyberSecurity.Cryptography
{
//     private static BigInteger largePrime(int bitLength, int certainty, Random rnd) {
//         BigInteger p;
//         p = new BigInteger(bitLength, rnd).setBit(bitLength-1);
//         p.mag[p.mag.length-1] &= 0xfffffffe;

//         // Use a sieve length likely to contain the next prime number
//         int searchLen = getPrimeSearchLen(bitLength);
//         BitSieve searchSieve = new BitSieve(p, searchLen);
//         BigInteger candidate = searchSieve.retrieve(p, certainty, rnd);

//         while ((candidate == null) || (candidate.bitLength() != bitLength)) {
//             p = p.add(BigInteger.valueOf(2*searchLen));
//             if (p.bitLength() != bitLength)
//                 p = new BigInteger(bitLength, rnd).setBit(bitLength-1);
//             p.mag[p.mag.length-1] &= 0xfffffffe;
//             searchSieve = new BitSieve(p, searchLen);
//             candidate = searchSieve.retrieve(p, certainty, rnd);
//         }
//         return candidate;
//     }

    public class AFLN2
    {
        private 
        BigInteger p = PrimeHelper.GetNextRandom();
        BigInteger q = PrimeHelper.GetNextRandom();
        BigInteger n = p * q;

    }
}
