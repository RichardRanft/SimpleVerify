using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using SimpleVerify;

namespace VerifyDriver
{
    class Program
    {
        static void Main(string[] args)
        {
            String path = @"E:\Temp\QVNW003A\";
            if (args.Length > 0 && (File.Exists(args[0]) || Directory.Exists(args[0])))
                path = args[0];
            CHashTool.Dump = true;
            CHashTool.Expand = false;
            CHashTool.SortByFilename = true;
            CHashTool.LowercaseDigest = true;
            CHashTool.SortDigest = false;
            CHashTool.UseFileHashKeys = true;
            CHashTool.RelativePath = true;
            CHashTool.SortOrdinal = true;
            CHashTool.Encode64Bit = false;
            CHashTool.Format = EDigestFormat.InlinePairFirst;
            DateTime start = DateTime.Now;
            Console.WriteLine("{0} - Beginning hash of {1}", start.ToString(),  path);
            if (CHashTool.GetHash(path))
            {
                Console.WriteLine("Hash of {0}:", path);
                Console.WriteLine(CHashTool.Hash);
                Console.WriteLine("{0}{1} - Hash took {2}", Environment.NewLine, DateTime.Now.ToString(), (DateTime.Now - start).ToString());
            }
            else
                Console.WriteLine("Unable to hash folder {0}", path);
        }

        private static String digestToString(byte[] digest)
        {
            var sb = new StringBuilder(digest.Length * 2);

            foreach (byte b in digest)
            {
                // can be "x2" if you want lowercase
                sb.Append(b.ToString("x2"));
            }
            return sb.ToString();
        }
    }
}
