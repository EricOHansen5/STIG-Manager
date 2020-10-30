using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;

namespace STIG_Manager_2.Class
{
    public class InstanceHandler
    {
		public static string file = "Data/numb_instances.txt";

		public static int GetNumberOfInstances()
		{
			Log.Add("GetNumberOfInstances()");

			try
			{
				string[] splitArray = new string[] { "\n", "\r" };

				FileStream fs;
				StreamReader sr;

				string username = Environment.UserName;

				if (File.Exists(file))
				{
					fs = new FileStream(file, FileMode.Open, FileAccess.Read);
					sr = new StreamReader(fs);

					string entireDoc = sr.ReadToEnd();
					string[] instances = entireDoc.Split(splitArray, StringSplitOptions.RemoveEmptyEntries);

					sr.Close();
					fs.Close();

					return instances.Length;
				}
				else
				{
					return 0;
				}

			}
			catch (Exception e)
			{
				Console.WriteLine("Problem getting number of instances.");
				MessageBox.Show("Error: " + e.Message);
				throw;
			}
		}

		public static void UpdateNumberOfInstances()
		{
			Log.Add("UpdateNumberOfInstances", Log.Level.GEN);

			try
			{
				FileStream fs;
				StreamWriter sw;

				string username = Environment.UserName;

				if (File.Exists(file))
				{
					fs = new FileStream(file, FileMode.Append, FileAccess.Write);
				}
				else
				{
					fs = new FileStream(file, FileMode.Create, FileAccess.Write);
				}

				sw = new StreamWriter(fs);
				sw.WriteLine($"{username} :: Opened at {DateTime.Now.ToString("yyyy-MM-dd hh:mm")}");
				sw.Flush();

				sw.Close();
				fs.Close();
			}
			catch (Exception e)
			{
				Console.WriteLine("Problem updating number of instances.");
				MessageBox.Show("Error: " + e.Message);
				throw;
			}
		}

		public static string[] GetOtherInstances()
		{
			Log.Add("GetOtherInstances", Log.Level.GEN);

			try
			{

				string[] splitArray = new string[] { "\n", "\r" };

				FileStream fs;
				StreamReader sr;

				string username = Environment.UserName;

				if (File.Exists(file))
				{
					fs = new FileStream(file, FileMode.Open, FileAccess.Read);
					sr = new StreamReader(fs);

					string entireDoc = sr.ReadToEnd();
					string[] instances = entireDoc.Split(splitArray, StringSplitOptions.RemoveEmptyEntries);
					string[] instWithUsername = instances.Select(x => !x.Contains(username) ? x : "").ToArray();
					string[] finalInstances = string.Join("\n", instWithUsername)
						.Split(splitArray, StringSplitOptions.RemoveEmptyEntries).ToArray();

					sr.Close();
					fs.Close();

					return finalInstances;
				}
				else
				{
					return null;
				}

			}
			catch (Exception e)
			{
				Console.WriteLine("Problem getting other instances.");
				MessageBox.Show("Error: " + e.Message);
				throw;
			}
		}

		public static void RemoveInstance()
		{
			Log.Add("RemoveInstance", Log.Level.GEN);

			try
			{
				string username = Environment.UserName;

				string[] instances = GetOtherInstances();
				if (instances != null && instances.Length <= 1)
				{
					File.Delete(file);
				}
				else
				{
					FileStream fs;
					StreamWriter sw;

					fs = new FileStream(file, FileMode.Truncate, FileAccess.Write);
					sw = new StreamWriter(fs);

					foreach (string instance in instances)
					{
						if (!instance.Contains(username))
						{
							sw.WriteLine(instance);
						}
						else
							continue;
					}

					sw.Flush();
					sw.Close();
					fs.Close();
				}
			}
			catch (Exception e)
			{
				Console.WriteLine("Problem removing instance.");
				MessageBox.Show("Error: " + e.Message);
				throw;
			}
		}
	}
}
