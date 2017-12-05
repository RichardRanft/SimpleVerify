using System;
using System.Collections;
using System.Collections.Specialized;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Security.Cryptography;

namespace SimpleVerify
{
    public class CHashTool
    {
        public static Exception LastException = null;
        public static String Delimiter = "";
        public static bool Dump = false;
        public static bool Expand = false;
        public static bool SortByFilename = false;
        public static bool LowercaseDigest = false;
        public static bool SortDigest = false;
        public static bool UseFileHashKeys = false;
        public static bool RelativePath = false;
        public static bool SortOrdinal = true;
        public static EDigestFormat Format = EDigestFormat.FilesFirst;

        private static bool m_error = false;
        private static byte[] m_hash;

        public static String Hash
        {
            get
            {
                return getHashAsString();
            }
            private set { }
        }

        public static bool GetHash(String path)
        {
            if (String.IsNullOrEmpty(path))
            {
                Console.WriteLine("Must provide a file or folder path");
                return false;
            }
            if (Directory.Exists(path))
            {
                Hash = getHash(path);
                if (m_error)
                    return false;
                return true;
            }
            if (File.Exists(path))
            {
                Hash = getFileHash(path);
                if (m_error)
                    return false;
                return true;
            }
            Console.WriteLine("Argument must be a file or a folder");
            return false;
        }

        private static String getHash(String path)
        {
            List<String> files = GetTree(path);
            if (m_error)
                return "";
            if (SortOrdinal)
                files.Sort(StringComparer.Ordinal);
            else
                files.Sort();
            List<CFileEntry> filekey = new List<CFileEntry>();
            StringBuilder digest = new StringBuilder();
            foreach (String file in files)
            {
                if (!File.Exists(file))
                    continue;
                CFileEntry entry = new CFileEntry();
                entry.Hash = getFileHash(file).ToUpper();
                entry.Path = getRelativePath(path, file);
                entry.Filename = Path.GetFileName(path);
                if (RelativePath)
                    entry.PathHash = getHashAsString(entry.Path).ToString();
                else
                    entry.PathHash = getHashAsString(entry.Filename).ToString();
                if (LowercaseDigest)
                {
                    entry.Hash = entry.Hash.ToLower();
                    entry.PathHash = entry.PathHash.ToLower();
                }
                filekey.Add(entry);
                if (m_error)
                    return "";
            }
            if (UseFileHashKeys)
            {
                if (SortByFilename)
                {
                    if (SortDigest)
                        filekey.Sort(new CFileSortPathHash());
                    appendToDigest(filekey, digest);
                }
                else
                {
                    if (SortDigest)
                        filekey.Sort(new CFileSortHash());
                    appendToDigest(filekey, digest);
                }
            }
            else
            {
                if (SortByFilename)
                {
                    if (SortDigest)
                        if (SortOrdinal)
                            filekey.Sort(new CFileSortFilenameOrdinal());
                        else
                            filekey.Sort(new CFileSortFilename());
                    appendToDigest(filekey, digest);
                }
                else
                {
                    if (SortDigest)
                        if (SortOrdinal)
                            filekey.Sort(new CFileSortPathOrdinal());
                        else
                            filekey.Sort(new CFileSortPath());
                    appendToDigest(filekey, digest);
                }
            }
            String hashdigest = digest.ToString();
            int index = hashdigest.LastIndexOf(Delimiter);
            if (index > 0)
                hashdigest = hashdigest.Remove(index);
            m_hash = getStringHash(hashdigest);
            if (Dump && filekey.Count > 0)
            {
                try
                {
                    String dumpfile = "hashdump";
                    //sortDigest, sortByFilename, lowercaseDigest, useFileHashKeys, relpath));
                    dumpfile += "_" + SortDigest.ToString();
                    dumpfile += "_" + SortByFilename.ToString();
                    dumpfile += "_" + LowercaseDigest.ToString();
                    dumpfile += "_" + UseFileHashKeys.ToString();
                    dumpfile += "_" + RelativePath.ToString();
                    dumpfile += "_" + Format.ToString();
                    dumpfile += ".txt";
                    using (StreamWriter sw = new StreamWriter(dumpfile))
                    {
                        foreach (CFileEntry entry in filekey)
                            sw.WriteLine(entry.Path + " " + entry.Hash);
                        sw.WriteLine();
                        sw.WriteLine("Overall SHA-1 = " + Hash);
                        sw.WriteLine();
                        sw.WriteLine("Digest:");
                        sw.WriteLine("-------");
                        sw.Write(hashdigest);
                    }
                }
                catch { }
            }
            return Hash;
        }

        private static void appendToDigest(List<CFileEntry> filekey, StringBuilder digest)
        {
            switch (Format)
            {
                case EDigestFormat.FilesFirst:
                    foreach (CFileEntry entry in filekey)
                    {
                        if (UseFileHashKeys)
                            digest.Append(entry.PathHash + Environment.NewLine);
                        else
                            digest.Append(entry.Path + Environment.NewLine);
                    }
                    foreach (CFileEntry entry in filekey)
                    {
                        digest.Append(entry.Hash + Environment.NewLine);
                    }
                    break;
                case EDigestFormat.FilesLast:
                    foreach (CFileEntry entry in filekey)
                    {
                        digest.Append(entry.Hash + Environment.NewLine);
                    }
                    foreach (CFileEntry entry in filekey)
                    {
                        if (UseFileHashKeys)
                            digest.Append(entry.PathHash + Environment.NewLine);
                        else
                            digest.Append(entry.Path + Environment.NewLine);
                    }
                    break;
                case EDigestFormat.InlineFilesFirst:
                    foreach (CFileEntry entry in filekey)
                    {
                        if (UseFileHashKeys)
                            digest.Append(entry.PathHash + Delimiter);
                        else
                            digest.Append(entry.Path + Delimiter);
                    }
                    foreach (CFileEntry entry in filekey)
                    {
                        digest.Append(entry.Hash + Delimiter);
                    }
                    break;
                case EDigestFormat.InlineFilesLast:
                    foreach (CFileEntry entry in filekey)
                    {
                        digest.Append(entry.Hash + Delimiter);
                    }
                    foreach (CFileEntry entry in filekey)
                    {
                        if (UseFileHashKeys)
                            digest.Append(entry.PathHash + Delimiter);
                        else
                            digest.Append(entry.Path + Delimiter);
                    }
                    break;
                case EDigestFormat.InlinePairFirst:
                    foreach (CFileEntry entry in filekey)
                    {
                        if (UseFileHashKeys)
                            digest.Append(entry.PathHash + Delimiter + entry.Hash + Delimiter);
                        else
                            digest.Append(entry.Path + Delimiter + entry.Hash + Delimiter);
                    }
                    break;
                case EDigestFormat.InlinePairLast:
                    foreach (CFileEntry entry in filekey)
                    {
                        if (UseFileHashKeys)
                            digest.Append(entry.Hash + Delimiter + entry.PathHash + Delimiter);
                        else
                            digest.Append(entry.Hash + Delimiter + entry.Path + Delimiter);
                    }
                    break;
            }
        }

        private static String getRelativePath(String root, String path)
        {
            String relpath = path.Replace(root, "");
            if (relpath.StartsWith("\\"))
                relpath = relpath.Remove(0, 1);
            if (relpath.EndsWith("\\"))
                relpath.Remove(relpath.LastIndexOf('\\'));
            return relpath;
        }

        private static String getFileHash(String filename)
        {
            SHA1 sha1 = new SHA1CryptoServiceProvider();
            try
            {
                using (FileStream fs = new FileStream(filename, FileMode.Open, FileAccess.Read, FileShare.Read))
                {
                    sha1.ComputeHash(fs);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("An exception has occurred.");
                Console.WriteLine(ex.Message);
                if (ex.InnerException != null)
                    Console.WriteLine(ex.InnerException.Message);
                m_error = true;
                LastException = ex;
                return "";
            }
            var hash = sha1.Hash;

            var sb = new StringBuilder(hash.Length * 2);

            foreach (byte b in hash)
            {
                // can be "x2" if you want lowercase
                sb.Append(b.ToString("X2"));
            }
            return sb.ToString();
        }

        private static byte[] getStringHash(String data)
        {
            SHA1 sha1 = new SHA1CryptoServiceProvider();
            byte[] dat = Encoding.ASCII.GetBytes(data);
            sha1.ComputeHash(dat);
            var hash = sha1.Hash;
            return hash;
        }

        private static String getHashAsString(String data)
        {
            var hash = getStringHash(data);
            var sb = new StringBuilder(hash.Length * 2);

            foreach (byte b in hash)
            {
                // can be "x2" if you want lowercase
                sb.Append(b.ToString("X2"));
            }
            return sb.ToString();
        }

        private static String getHashAsString()
        {
            var sb = new StringBuilder(m_hash.Length * 2);

            int count = 0;
            foreach (byte b in m_hash)
            {
                // can be "x2" if you want lowercase
                sb.Append(b.ToString("X2"));
                if (Expand && ++count % 4 == 0)
                    sb.Append(" ");
            }
            return sb.ToString();
        }

        private static List<String> GetTree(string root)
        {
            // Data structure to hold names of subfolders to be
            // examined for files.
            Stack<string> dirs = new Stack<string>(20);
            List<String> foundfiles = new List<string>();

            if (!System.IO.Directory.Exists(root))
            {
                throw new ArgumentException();
            }
            dirs.Push(root);

            while (dirs.Count > 0)
            {
                string currentDir = dirs.Pop();
                string[] subDirs;
                try
                {
                    subDirs = System.IO.Directory.GetDirectories(currentDir);
                }
                // An UnauthorizedAccessException exception will be thrown if we do not have
                // discovery permission on a folder or file. It may or may not be acceptable 
                // to ignore the exception and continue enumerating the remaining files and 
                // folders. It is also possible (but unlikely) that a DirectoryNotFound exception 
                // will be raised. This will happen if currentDir has been deleted by
                // another application or thread after our call to Directory.Exists. The 
                // choice of which exceptions to catch depends entirely on the specific task 
                // you are intending to perform and also on how much you know with certainty 
                // about the systems on which this code will run.
                catch (UnauthorizedAccessException e)
                {
                    Console.WriteLine(e.Message);
                    m_error = true;
                    LastException = e;
                    continue;
                }
                catch (System.IO.DirectoryNotFoundException e)
                {
                    Console.WriteLine(e.Message);
                    m_error = true;
                    LastException = e;
                    continue;
                }

                string[] files = null;
                try
                {
                    files = System.IO.Directory.GetFiles(currentDir);
                }

                catch (UnauthorizedAccessException e)
                {

                    Console.WriteLine(e.Message);
                    m_error = true;
                    LastException = e;
                    continue;
                }

                catch (System.IO.DirectoryNotFoundException e)
                {
                    Console.WriteLine(e.Message);
                    m_error = true;
                    LastException = e;
                    continue;
                }
                // work block...
                foreach (string file in files)
                {
                    if (Path.GetExtension(file).ToLower() == ".lnk")
                        continue;
                    try
                    {
                        // collect file names if they don't contain anything from the ignore list
                        System.IO.FileInfo fi = new System.IO.FileInfo(file);
                        foundfiles.Add(fi.FullName);
                    }
                    catch (System.IO.FileNotFoundException e)
                    {
                        // If file was deleted by a separate application
                        //  or thread since the call to TraverseTree()
                        // then just continue.
                        Console.WriteLine(e.Message);
                        m_error = true;
                        LastException = e;
                        continue;
                    }
                }

                // Push the subdirectories onto the stack for traversal.
                // Don't keep anything that contains 
                foreach (string str in subDirs)
                {
                    dirs.Push(str);
                }
            }
            return foundfiles;
        }
    }

    public class CFileEntry
    {
        public String Filename = "";
        public String Path = "";
        public String Hash = "";
        public String PathHash = "";
    }

    public class CFileSortFilename : IComparer<CFileEntry>
    {
        public int Compare(CFileEntry a, CFileEntry b)
        {
            return a.Filename.CompareTo(b.Filename);
        }
    }

    public class CFileSortPath : IComparer<CFileEntry>
    {
        public int Compare(CFileEntry a, CFileEntry b)
        {
            return a.Path.CompareTo(b.Path);
        }
    }

    public class CFileSortFilenameOrdinal : IComparer<CFileEntry>
    {
        public int Compare(CFileEntry a, CFileEntry b)
        {
            return StringComparer.Ordinal.Compare(a.Filename, b.Filename);
        }
    }

    public class CFileSortPathOrdinal : IComparer<CFileEntry>
    {
        public int Compare(CFileEntry a, CFileEntry b)
        {
            return StringComparer.Ordinal.Compare(a.Path, b.Path);
        }
    }

    public class CFileSortHash : IComparer<CFileEntry>
    {
        public int Compare(CFileEntry a, CFileEntry b)
        {
            return a.Hash.CompareTo(b.Hash);
        }
    }

    public class CFileSortPathHash : IComparer<CFileEntry>
    {
        public int Compare(CFileEntry a, CFileEntry b)
        {
            return a.PathHash.CompareTo(b.PathHash);
        }
    }

    public enum EDigestFormat
    {
        FilesFirst,
        FilesLast,
        InlineFilesFirst,
        InlineFilesLast,
        InlinePairFirst,
        InlinePairLast
    }
}
