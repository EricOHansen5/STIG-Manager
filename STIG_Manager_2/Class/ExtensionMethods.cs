using System;
using System.IO;
using System.IO.Compression;

namespace STIG_Manager_2.Class
{
	public static class ExtensionMethods
    {
		public static bool IsFileInUse(this string file)
		{
			Log.Add("IsFileInUse", Log.Level.GEN);

			TextReader textReader = null;

			try
			{
				textReader = File.OpenText(file);
			}
			catch (FileNotFoundException fileNotFoundException)
			{
				Console.WriteLine("FileNotFound: " + fileNotFoundException.Message);
				return false;
			}
			catch (IOException ioException)
			{
				Console.WriteLine("FileInUse: " + ioException.Message);
				return true;
			}
			finally
			{
				if (textReader != null) { textReader.Close(); }
			}
			return false;
		}

		public static string GetFilenameFromZIP(this string filename)
		{
			Log.Add("GetFilenameFromZIP", Log.Level.GEN);

			string extractPath = Path.Combine(Path.GetDirectoryName(filename), Path.GetFileNameWithoutExtension(filename));
			string newFilename = Path.Combine(extractPath, Path.GetFileNameWithoutExtension(filename) + ".xml");
			if (Directory.Exists(extractPath) && File.Exists(newFilename))
				return newFilename;

			using (ZipArchive archive = ZipFile.Open(filename, ZipArchiveMode.Update))
			{
				//archive.CreateEntryFromFile(newFilename, Path.GetFileNameWithoutExtension(filename) + ".xml");
				archive.ExtractToDirectory(extractPath);
			}
			return newFilename;
		}
	}
}
