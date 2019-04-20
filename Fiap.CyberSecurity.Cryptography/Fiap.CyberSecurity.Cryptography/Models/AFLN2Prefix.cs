using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Fiap.CyberSecurity.Cryptography.Models
{
    internal class AFLN2Prefix
    {
        internal static readonly string PrefixBeginFormat = "AFLN2{";

        internal static readonly string PrefixEndFormat = "}";

        internal static readonly string IndexesSeparator = ",";

        internal static readonly string TupleBegin = "[";

        internal static readonly string TupleEnd = "]";

        internal AFLN2Prefix() : base()
        {
            this.PaddingIndexes = new List<Tuple<int, int>>();
        }

        internal AFLN2Prefix(string content) : this()
        {
            this.content = content;
        }

        internal AFLN2Prefix(string content, List<Tuple<int, int>> paddingIndexes) : this(content)
        {
            this.PaddingIndexes = paddingIndexes;
        }

        private string content;

        public string Content
        {
            get { return content; }
            set { content = value; }
        }


        private byte[] data;

        public byte[] AsByteArray
        {
            get
            {
                if (data == null)
                {
                    data = Encoding.UTF8.GetBytes(content);
                }

                return data;
            }
        }

        internal int BytesLength
        {
            get
            {
                if (data != null)
                {
                    return data.Length;
                }
                else if (AsByteArray != null)
                {
                    return AsByteArray.Length;
                }

                return -1;
            }
        }

        internal List<Tuple<int, int>> PaddingIndexes { get; set; }
    }
}
