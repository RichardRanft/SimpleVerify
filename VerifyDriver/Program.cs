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
        private static CCmdParser m_parser;

        static void Main(string[] args)
        {
            Dictionary<String, KeyValuePair<EArgType, bool>> argList = new Dictionary<String, KeyValuePair<EArgType, bool>>();
            argList.Add("-path", new KeyValuePair<EArgType, bool>(EArgType.VALUE, false));
            argList.Add("-dt", new KeyValuePair<EArgType, bool>(EArgType.VALUE, false));
            argList.Add("-sfn", new KeyValuePair<EArgType, bool>(EArgType.FLAG, false));
            argList.Add("-fhk", new KeyValuePair<EArgType, bool>(EArgType.FLAG, false));
            argList.Add("-rp", new KeyValuePair<EArgType, bool>(EArgType.FLAG, false));
            argList.Add("-so", new KeyValuePair<EArgType, bool>(EArgType.FLAG, false));
            argList.Add("-x64", new KeyValuePair<EArgType, bool>(EArgType.FLAG, false));
            m_parser = new CCmdParser(argList);
            if (!m_parser.Parse(args))
            {
                return;
            }
            String path = @"E:\Temp\QVNW003A\";
            if (!String.IsNullOrEmpty(m_parser.Options["-path"]))
                path = m_parser.Options["-path"];
            loadSettings();
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

        private static void loadSettings()
        {
            CHashTool.Dump = true;
            CHashTool.Expand = false;
            CHashTool.LowercaseDigest = false;
            CHashTool.SortDigest = false;
            CHashTool.SortByFilename = !String.IsNullOrEmpty(m_parser.Options["-sfn"]);
            CHashTool.UseFileHashKeys = !String.IsNullOrEmpty(m_parser.Options["-fhk"]);
            CHashTool.RelativePath = !String.IsNullOrEmpty(m_parser.Options["-rp"]);
            CHashTool.SortOrdinal = !String.IsNullOrEmpty(m_parser.Options["-so"]);
            CHashTool.Encode64Bit = !String.IsNullOrEmpty(m_parser.Options["-x64"]);
            if (!String.IsNullOrEmpty(m_parser.Options["-dt"]))
            {
                switch (m_parser.Options["-dt"].ToLower())
                {
                    case "ff":
                        CHashTool.Format = EDigestFormat.FilesFirst;
                        break;
                    case "fl":
                        CHashTool.Format = EDigestFormat.FilesLast;
                        break;
                    case "iff":
                        CHashTool.Format = EDigestFormat.InlineFilesFirst;
                        break;
                    case "ifl":
                        CHashTool.Format = EDigestFormat.InlineFilesLast;
                        break;
                    case "ipf":
                        CHashTool.Format = EDigestFormat.InlinePairFirst;
                        break;
                    case "ipl":
                        CHashTool.Format = EDigestFormat.InlinePairLast;
                        break;
                }
            }
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
