using Fiap.CyberSecurity.Cryptography.Helpers;
using Fiap.CyberSecurity.Cryptography.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;

namespace Fiap.CyberSecurity.Cryptography
{
    public class AFLN2
    {
        public int KeyLength { get; private set; }

        public BigInteger P { get; private set; }

        public BigInteger Q { get; private set; }

        public BigInteger M { get; private set; }

        public BigInteger N { get; private set; }

        public BigInteger E { get; private set; }

        public BigInteger D { get; private set; }

        public AFLN2(int keyLength)
        {
            this.KeyLength = keyLength;
        }

        private AFLN2Prefix ComposePrefix(List<Tuple<int, int>> paddingIndexes)
        {
            List<string> tuples = new List<string>();

            for (int i = 0; i < paddingIndexes.Count; i++)
            {
                string tuple = String.Format("{0}{1}{2}{3}{4}", AFLN2Prefix.TupleBegin, paddingIndexes[i].Item1, AFLN2Prefix.IndexesSeparator, paddingIndexes[i].Item2, AFLN2Prefix.TupleEnd);

                tuples.Add(tuple);
            }

            string prefix = string.Format("{0}{1}{2}", AFLN2Prefix.PrefixBeginFormat, string.Join(AFLN2Prefix.IndexesSeparator, tuples), AFLN2Prefix.PrefixEndFormat);

            return new AFLN2Prefix(prefix);
        }

        private AFLN2Prefix DecomposePrefix(byte[] data)
        {
            AFLN2Prefix prefixObject = new AFLN2Prefix();
            List<Tuple<int, int>> paddingIndexes = new List<Tuple<int, int>>();

            string prefix = null;
            string dataString = Encoding.UTF8.GetString(data);
            int prefixEndIndex = dataString.IndexOf(AFLN2Prefix.PrefixEndFormat) + 1;

            prefix = dataString.Substring(0, prefixEndIndex);
            prefixObject.Content = prefix;

            prefix = prefix.Replace(AFLN2Prefix.PrefixBeginFormat, "");
            prefix = prefix.Replace(AFLN2Prefix.PrefixEndFormat, "");            

            if (prefix.Length > 0)
            {
                prefix = prefix.Substring(1);
                prefix = prefix.Substring(0, prefix.Length - 1);

                string[] splittedPrefix = prefix.Split(new string[]{ String.Format("{0}{1}{2}", AFLN2Prefix.TupleEnd, AFLN2Prefix.IndexesSeparator, AFLN2Prefix.TupleBegin) }, StringSplitOptions.None);

                for (int i = 0; i < splittedPrefix.Length; i++)
                {
                    int[] items = splittedPrefix[i].Split(new string[]{ AFLN2Prefix.IndexesSeparator }, StringSplitOptions.None).Select(x => Convert.ToInt32(x)).ToArray();

                    paddingIndexes.Add(Tuple.Create(items[0], items[1]));
                }
            }

            prefixObject.PaddingIndexes = paddingIndexes;

            return prefixObject;
        }

        public void GenerateKeys()
        {
            this.P = MathHelper.RandomPrime(this.KeyLength);
            this.Q = MathHelper.RandomPrime(this.KeyLength);

            this.N = this.P * this.Q;
            this.M = (this.P - BigInteger.One) * (this.Q - BigInteger.One);

            this.E = MathHelper.RandomBigInteger(this.KeyLength / 2);
            BigInteger addFactor = new BigInteger(1);

            while (BigInteger.GreatestCommonDivisor(this.M, this.E) > BigInteger.One)
            {
                this.E += addFactor;
            }

            this.D = MathHelper.ModInverse(this.E, this.M);
        }

        public string Encrypt(string data)
        {
            /*
            this.P = BigInteger.Parse("3065147332865436226845733806984742774486286183510595911252874198701142418062876105354920831104366963586718819500830256561066136146659532625901446983363183");
            this.Q = BigInteger.Parse("320380930730751791514052764511514641545375310927179698945904946293608448794199033054993597207468285029621422295536303487492650639121393745548889454038173");
            this.M = BigInteger.Parse("982014755330309927958465308472587917794252989520680587967625071958470215411781285584030742331101813297607099272389612934847362825926946006452552013874984904234575883152105972757071513925466449186815983153710995426265034393796650129427141264860028746224824684049762887680619967519226530000664085931567383304");
            this.N = BigInteger.Parse("982014755330309927958465308472587917794252989520680587967625071958470215411781285584030742331101813297607099272389612934847362825926946006452552013874988289762839479340124332543643010182882480848310420929321194205410029144663507204565551179288340581473441024291559254240668526306012310927035536268004784659");
            this.E = BigInteger.Parse("10304422426817155075");
            this.D = BigInteger.Parse("964880743223018012130606124874476225832430737099726718688221981628596255453737161562804635320848589491705058525389686861967963888548300202655167028390068858282035260346667531369139561409415660139426996015160451353933198373907226308038361408892606782318172675466074992593724719045334913439770424466004204171");
            
            this.P = BigInteger.Parse("2389920303438982555651291743644592745446809921430808601218271522024402501242793878743354714353371977352266535187247362907638683614330469844082619306859363");
            this.Q = BigInteger.Parse("5871994423373021208477438292389079385924758262745091896316100714117591373035395654091757353345935542136830613645235540664697711962036245086610583662909459");
            this.M = BigInteger.Parse("14033598694099664247332247547246864650003757753722747287013267383790791545509208799930971171668351565089396489704672282864962465452398052773018609935174947217336645954770001179685094242657285643731472883240172677283480113729893028775172157487156656200233563473728888388056030525072917135988913758521345645796");
            this.N = BigInteger.Parse("14033598694099664247332247547246864650003757753722747287013267383790791545509208799930971171668351565089396489704672282864962465452398052773018609935174955479251372766773765308415130276329417015299657059140670211655716255723767306964704992599224355507753052570877720870959602861468493502703844451724315414617");
            this.E = BigInteger.Parse("51624344051494834981092513588531596417623491415283889654958596465039271763669");
            this.D = BigInteger.Parse("3760890187174774672872795054738906285547807131517931269687996055233341578218142848493517481849957759769564049571139073881946270539101212907127060736228216021865563549084209439286694017723031249525864737770228750625999356223498124984989782521978374633558836100009876893737752901661488086002614291996028946261");
            */
            byte[] dataBytes = Encoding.UTF8.GetBytes(data);
            List<byte> encryptedData = new List<byte>();
            List<Tuple<int, int>> paddingIndexes = new List<Tuple<int, int>>();

            for (int i = 0; i < dataBytes.Length; i++)
            {
                byte[] buffer = new byte[this.KeyLength / 4];
                byte[] encryptedBytes = BigInteger.ModPow(new BigInteger(dataBytes[i]), this.E, this.N).ToByteArray();

                int offset = buffer.Length - encryptedBytes.Length;

                if (offset > 0)
                {
                    paddingIndexes.Add(Tuple.Create(i, offset));
                }

                Buffer.BlockCopy(encryptedBytes, 0, buffer, offset, encryptedBytes.Length);

                encryptedData.AddRange(buffer);
            }

            encryptedData.InsertRange(0, ComposePrefix(paddingIndexes).AsByteArray);

            return Convert.ToBase64String(encryptedData.ToArray());
        }

        public string Decrypt(string data)
        {
            byte[] dataBytes = null;
            byte[] dataBytesAux = Convert.FromBase64String(data);
            List<byte> decryptedData = new List<byte>();
            AFLN2Prefix prefix = DecomposePrefix(dataBytesAux);
            
            dataBytes = new byte[dataBytesAux.Length - prefix.BytesLength];

            Buffer.BlockCopy(dataBytesAux, prefix.BytesLength, dataBytes, 0, dataBytes.Length);

            for (int i = 0, j = 0; i < dataBytes.Length; i+= (this.KeyLength / 4), j++)
            {
                int offset = 0;
                byte[] buffer = new byte[this.KeyLength / 4];
                Tuple<int, int> indexOffsetTuple = prefix.PaddingIndexes.Where(x => x.Item1 == j).FirstOrDefault();

                if (indexOffsetTuple != null)
                {
                    offset = indexOffsetTuple.Item2;
                }

                Buffer.BlockCopy(dataBytes, i, buffer, 0, buffer.Length);
                
                BigInteger decryptedByte = BigInteger.ModPow(new BigInteger(buffer.Skip(offset).ToArray()), this.D, this.N);

                decryptedData.AddRange(decryptedByte.ToByteArray());
            }

            return Encoding.UTF8.GetString(decryptedData.ToArray());
        }
    }
}
