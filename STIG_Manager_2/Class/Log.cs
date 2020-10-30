using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;

namespace STIG_Manager_2.Class
{
    public static class Log
    {
        public static string dir = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        public static string filename = dir + "/SMv2/Data/logs.txt";
        public static string GEN =  "  GENERAL   ";
        public static string WARN = "--WARNING-- ";
        public static string ERR =  "!  ERROR   !";
        public static string CRIT = "!!CRITICAL!!";
        public enum Level
        {
            GEN,
            WARN,
            ERR,
            CRIT
        }
        public static string[] Levels = new string[] { GEN, WARN, ERR, CRIT };

        public static StreamWriter Writer { get; set; }

        public static void Add(string message, Level level = Level.GEN)
        {
            try
            {
                if (!File.Exists(filename))
                    Directory.CreateDirectory(Path.GetDirectoryName(filename));
                                
                Writer = new StreamWriter(filename, true);

                Writer.WriteLine(string.Format("{0} : {1} : {2}", DateTime.Now, Levels[(int)level], message));
                Writer.Flush();
            }
            catch (Exception e)
            {
                BaseClass.EShow("ERROR WRITING LOG: " + e.Message);
                throw;
            }
            finally
            {
                Writer.Close();
                Writer.Dispose();
            }
        }

        public static void Clear_Log()
        {
            FileInfo fi = new FileInfo(filename);
            if(fi.Length > 500000)
            {
                var lines = File.ReadAllLines(filename);
                File.WriteAllLines(filename, lines.Skip(lines.Length/2).ToArray());
            }
        }
    }
}
