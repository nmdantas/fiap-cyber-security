using System;
using System.Collections.Generic;
using System.Configuration;
using System.Numerics;
using Wolfram.Alpha;
using Wolfram.Alpha.Models;

namespace Fiap.CyberSecurity.Cryptography.Helpers
{
    public static class MathHelper
    {
        private const int ByteSize = 8;
        private const string WolframAlphaAppKey = "WolframAlphaAppKey"; 
        private const string WolframAlphaPrimeQuery = "NextPrime[{0}]";
        private const string WolframAlphaResultTitle = "Result";

        public static byte[] RandomByteArray(int bitLength)
        {
            Random random = new Random();
            byte[] byteArray = new byte[bitLength / MathHelper.ByteSize];

            random.NextBytes(byteArray);

            return byteArray;
        }

        public static BigInteger RandomBigInteger(int bitLength)
        {
            return BigInteger.Abs(new BigInteger(RandomByteArray(bitLength)));
        }

        public static BigInteger RandomPrime(int bitLength)
        {
            BigInteger prime = BigInteger.Zero;
            BigInteger randomBigInteger = BigInteger.Abs(new BigInteger(RandomByteArray(bitLength)));
            string query = String.Format(MathHelper.WolframAlphaPrimeQuery, randomBigInteger);

            WolframAlphaService service = new WolframAlphaService(ConfigurationManager.AppSettings.Get(MathHelper.WolframAlphaAppKey));
            WolframAlphaRequest request = new WolframAlphaRequest(query);
            WolframAlphaResult result;

            request.Formats = new List<string>() { "plaintext" };

            result = service.Compute(request).GetAwaiter().GetResult();
            
            for (int i = 0; result.QueryResult.Success && i < result.QueryResult.Pods.Count; i++)
            {
                Pod pod = result.QueryResult.Pods[i];

                if (pod.SubPods != null && pod.Title == MathHelper.WolframAlphaResultTitle)
                {
                    for (int j = 0; j < pod.SubPods.Count; j++)
                    {
                        SubPod subPod = pod.SubPods[j];

                        prime = BigInteger.Parse(subPod.Plaintext);
                    }
                }
            }

            return prime;
        }

        public static BigInteger ModInverse(BigInteger a, BigInteger m)
        {
            // https://www.geeksforgeeks.org/multiplicative-inverse-under-modulo-m/
            BigInteger m0 = new BigInteger(m.ToByteArray());
            BigInteger mAux = new BigInteger(m.ToByteArray());
            BigInteger aAux = new BigInteger(a.ToByteArray());
            BigInteger y = BigInteger.Zero;
            BigInteger x = BigInteger.One;

            if (mAux == 1)
                return 0;

            while (aAux > BigInteger.One)
            {
                // q is quotient 
                BigInteger q = aAux / mAux;
                BigInteger t = mAux;

                // m is remainder now, process same as 
                // Euclid's algo 
                mAux = aAux % mAux;
                aAux = t;
                t = y;

                // Update y and x 
                y = x - q * y;
                x = t;
            }

            // Make x positive 
            if (x < 0)
                x += m0;

            return x;
        }
    }
}
