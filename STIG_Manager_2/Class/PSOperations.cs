using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Linq;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using System.Windows;

namespace STIG_Manager_2.Class
{
    public static class PSOperations
    {
		/// <summary>
		/// Run Powershell script function
		/// </summary>
		/// <param name="script">This parameter is the text representation of the powershell script</param>
		/// <param name="functions">This parameter is the text representation of the functions needed for the script text</param>
		/// <returns>This function returns the results of the powershell script run</returns>
		public static string Run(string script, string functions)
		{
            //Log.Add("Run", Log.Level.GEN);
			// creating the runspace for the powershell to be contained in
            Runspace rs = RunspaceFactory.CreateRunspace();

			try
			{
				// open the runspace to start running powershell scripts
				rs.Open();
				// create the pipeline to pass scripts to in order to run in the runspace
				Pipeline pipeline = rs.CreatePipeline();

				//string functions = ds.Get_HeaderFunctions();
				// add the functions to the runspace so that function calls will be recognized
				pipeline.Commands.AddScript(functions);
				// add the scripts to the runspace
				pipeline.Commands.AddScript(script);
				// add the out-string commandlet so the results are in a string format
				pipeline.Commands.Add("Out-String");

				// invoking the commands in the runspace and storing the results into a powershell object
				Collection<PSObject> results = pipeline.Invoke();
				

				// taking the results of the run and concating into a single string to return
				StringBuilder sb = new StringBuilder();
				foreach (PSObject item in results)
				{
					sb.AppendLine(item.ToString());
				}

				// return string
				return sb.ToString();
			}
			catch (Exception e)
			{
				// IF EVER RECEIVE THE ERROR THAT "GET-PROCESSMITIGATION" IS UNRECOGNIZED
				// DISABLE "PREFER-32BIT" IN PROJECT PROPERTIES.
				Log.Add("PS-ERROR: " + e.Message, Log.Level.ERR);
				return "Error in script.\n\r" + e.Message + "\n";
			}
			finally
			{
				// closing the runspace
				rs.Close();
			}

		}


		public static Dictionary<string, string> Run_All(Dictionary<string, string> vulns, string functions)
		{

			try
			{
				Stopwatch sw = new Stopwatch();
				sw.Start();
				Dictionary<string, string> vulns_results = new Dictionary<string, string>();
				foreach (KeyValuePair<string, string> item in vulns)
				{
					vulns_results.Add(item.Key, Run(item.Value, functions));
				}
				sw.Stop();
				TimeSpan ts = new TimeSpan(sw.ElapsedTicks);
				BaseClass.Show("Finished in " + ts.ToString("c"));
				return vulns_results;
			}
			catch (Exception e)
			{
				BaseClass.EShow("PS-Error: " + e.Message);
				return null;
			}

		}

		public static string Run_Remote(string computer, string script, string functions)
		{
			//Log.Add("RunRemoteScript", Log.Level.GEN);
			WSManConnectionInfo connectionInfo = new WSManConnectionInfo(new Uri("http://" + computer + ":5985"));
			Runspace rs = RunspaceFactory.CreateRunspace(connectionInfo);

			try
			{
				rs.Open();

				PowerShell powershell = PowerShell.Create();
				powershell.Runspace = rs;

				Pipeline pipeline = rs.CreatePipeline();

				pipeline.Commands.AddScript(functions);
				pipeline.Commands.AddScript(script);
				pipeline.Commands.Add("Out-String");

				Collection<PSObject> results = pipeline.Invoke();

				StringBuilder sb = new StringBuilder();
				foreach (PSObject item in results)
				{
					sb.AppendLine(item.ToString());
				}

				return sb.ToString();
			}
			catch (Exception e)
			{
				Log.Add("PS-REMOTE-ERROR: " + e.Message, Log.Level.ERR);
				return null;
			}
			finally
			{
				rs.Close();
			}
		}

		public static Dictionary<string, string> Run_All_Remote(string computer, Dictionary<string, string> scripts, string functions)
		{
			Log.Add("RunRemoteScript", Log.Level.GEN);

			try 
			{ 
				Dictionary<string, string> vulns_results = new Dictionary<string, string>();
				foreach (KeyValuePair<string, string> item in scripts)
				{
					vulns_results.Add(item.Key, Run_Remote(computer, item.Value, functions));
				}

				return vulns_results;
			}
			catch (Exception e)
			{
				Log.Add("PS-REMOTE-ERROR: " + e.Message, Log.Level.ERR);
				return null;
			}
		}

		public static string TestConnection(string computername)
		{
			//Log.Add("TestConnection", Log.Level.GEN);

			Runspace rs;
			try
			{
				//connectioninfo = new WSManConnectionInfo(new Uri("http://" + computername + ":5985"));
				rs = RunspaceFactory.CreateRunspace();

				rs.Open();
				Pipeline pipeline = rs.CreatePipeline();

				pipeline.Commands.AddScript($"Test-Connection {computername} -Count 1 -Quiet");
				pipeline.Commands.Add("Out-String");
				Collection<PSObject> results = pipeline.Invoke();

				StringBuilder sb = new StringBuilder();
				foreach (PSObject item in results)
				{
					sb.AppendLine(item.ToString());
				}

				return sb.ToString();
			}
			catch (Exception e)
			{
				Log.Add("PS-ERROR: " + e.Message, Log.Level.ERR);
				return "Error running PS-Script: " + e.Message;
			}
		}

		public static bool Check_Internet_Connection()
		{
			try
			{
				using (var client = new WebClient())
					using (client.OpenRead("http://google.com/generate_204"))
						return true;
			}
			catch{

				return false;
			}
		}
	}
}
