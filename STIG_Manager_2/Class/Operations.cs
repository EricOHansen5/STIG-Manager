using Microsoft.Win32;
using Newtonsoft.Json;
using STIG_Manager_2.View;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows;

namespace STIG_Manager_2.Class
{
    public static class Operations
    {

		// Method to Parse PS Script and Add to Datastore
		public static Dictionary<string, string> Parse_Script(string filename)
		{
			Log.Add("Parse_Script", Log.Level.GEN);

			if (!File.Exists(filename))
				return null;

			string HeaderFunctions;
			string ElevatePermissions;

			StreamReader r;

			try
			{
				// Open StreamReader
				r = new StreamReader(filename);

				// reads all lines of the document (powershell script)
				List<string> doc = new List<string>(r.ReadToEnd().Split(new char[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries));
				r.Close();

				// Specifically looking for this string in order to find next start point
				int ixHeader = doc.IndexOf("#================== End Functions =============================");
				int ixAdmin = doc.IndexOf("#Create logfile");
				int ixChecks = doc.IndexOf("#Begin STIG Checks");
				if(ixHeader > 0)
					// Seperate header functions
					HeaderFunctions = string.Join("\n", doc.GetRange(0, ixHeader));
				if(ixAdmin > 0)
					// Parse the elevate permissions section
					ElevatePermissions = string.Join("\n", doc.GetRange(ixHeader + 1, ixAdmin - ixHeader));
				// Parse logfile initilization section
				//Logfile = string.Join("\n", doc.GetRange(ixAdmin, ixChecks - ixAdmin));

				// Create Dictionary to Store PowerShell Scripts
				Dictionary<string, string> DictFinal = new Dictionary<string, string>();

				if (ixChecks < 0)
					ixChecks = 0;

				// Parse all Vuln powershell script sections
				List<int> ixVulns = new List<int>();
				for (int i = ixChecks; i < doc.Count; i++)
				{
					// PowerShell format "# Vuln ID V-######" or "#V-######"
					if (doc[i].ToLower().StartsWith("# vuln id v-") || doc[i].ToLower().StartsWith("#v-"))
						ixVulns.Add(i);
				}

				// Iterates through powershell
				for (int i = 0; i < ixVulns.Count; i++)
				{
					int start = ixVulns[i];
					string id = "";

					int end = 0;

					if (i + 1 >= ixVulns.Count){
						end = doc.Count - 1;
					}else{
						end = ixVulns[i + 1];
					}

					if (doc[start].StartsWith("# Vuln ID V-"))
					{
						id = doc[start].Substring("# Vuln ID ".Length).Split(new char[] { ' ', ',' }, StringSplitOptions.RemoveEmptyEntries)[0];
					}
					else if (doc[start].StartsWith("#V-"))
					{
						id = "V-" + doc[start].Substring("#V-".Length).Split(new char[] { ' ', ',' }, StringSplitOptions.RemoveEmptyEntries)[0];
					}
					string val = string.Join("\n", doc.GetRange(start, end - start));

					string clean_val = Remove_Outfile(val);//Regex.Replace(val, "| Out-File $logName -Append", "", RegexOptions.IgnoreCase);

					if (DictFinal.ContainsKey(id))
					{
						DictFinal[id] += "\n" + clean_val;
					}else{
						DictFinal.Add(id, clean_val);
					}
				}
				return DictFinal;
			}
			catch (IOException io)
			{
				Log.Add("Input/Output Error: " + io.Message, Log.Level.ERR);
				return null;
			}
			catch (Exception e)
			{
				Log.Add("Exception Error: " + e.Message, Log.Level.ERR);
				return null;
			}
		}
		public static string ReplaceCaseInsensitive(string input, string search, string replacement)
		{
			string result = Regex.Replace(
				input,
				Regex.Escape(search),
				replacement.Replace("$", "$$"),
				RegexOptions.IgnoreCase
			);
			return result;
		}


		// Method to Parse PS Script Header Functions
		public static Dictionary<string, PSHeaderFunction> Parse_Header_Functions(string filename)
		{
			Log.Add("Parse_Header_Functions", Log.Level.GEN);
			if (!File.Exists(filename))
				return null;

			StreamReader r;

			try
			{
				// Open StreamReader
				r = new StreamReader(filename);

				// reads all lines of the document (powershell script)
				List<string> doc = new List<string>(r.ReadToEnd().Split(new char[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries));
				r.Close();

				// Specifically looking for this string in order to find next start point
				int ixHeader = doc.IndexOf("#================== End Functions =============================");

				// Seperate header functions
				string sfunctions = string.Join("\n", doc.GetRange(0, ixHeader));

				Dictionary<string, PSHeaderFunction> Function_Dictionary = new Dictionary<string, PSHeaderFunction>();

				string[] func = sfunctions.Split(new string[] { "Function", "function" }, StringSplitOptions.RemoveEmptyEntries);
				foreach (string f in func)
				{
					// parse function name
					// user function name as key
					// function text as value
					int ixBracket = f.IndexOf('{');
					if (ixBracket == -1)
						continue;
					string name = f.Substring(1, ixBracket - 2);
					string newF = "Function" + f;

					if (!Function_Dictionary.ContainsKey(name))
					{
						PSHeaderFunction curFunc = new PSHeaderFunction();
						curFunc.Title = name;
						string clean_func = Remove_Outfile(newF);
						string valid_func = Validate_Function(clean_func);
						curFunc.Add_Function(valid_func);

						Function_Dictionary.Add(name, curFunc);
					}
				}

				return Function_Dictionary;
			}
			catch (IOException io)
			{
				Log.Add("Input/Output Error: " + io.Message, Log.Level.ERR);
				return null;
			}
			catch (Exception e)
			{
				Log.Add("Exception Error: " + e.Message, Log.Level.ERR);
				return null;
			}
		}

		public static string Remove_Outfile(string script)
        {
			StringBuilder sb = new StringBuilder();

			string[] lines = script.Split(new char[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
            foreach (string item in lines)
            {
				int ixS = 0;
				ixS = item.ToLower().IndexOf("| out-file");
				if (ixS <= 0)
					sb.AppendLine(item);
				else
					sb.AppendLine(item.Substring(0, ixS));
            }
			return sb.ToString();
        }

		public static void Load_Scripts(OpenFileDialog ofd, Datastore datastore)
		{
			Log.Add("Load_Script", Log.Level.GEN);

			StreamReader sr = new StreamReader(ofd.FileName);
			string file = sr.ReadToEnd();
			Dictionary<string, string> vuln_dict = new Dictionary<string, string>();

			if (Path.GetExtension(ofd.FileName).ToLower().Equals(".json")){
				vuln_dict = JsonConvert.DeserializeObject<Dictionary<string, string>>(file);
			}else{
				if (Path.GetExtension(ofd.FileName).ToLower().Equals(".ps1"))
					vuln_dict = Parse_Script(ofd.FileName);
				else
					BaseClass.EShow("This file doesn't seem to be in the correct format. Please try a .json or .ps1 file.");
			}

			if (vuln_dict != null)
			{
				int count = 0;
				foreach (KeyValuePair<string, string> item in vuln_dict)
				{
					if (datastore.Vuln_DB.ContainsKey(item.Key))
					{
						if (item.Value.Length <= 45) continue;
						
						datastore.Vuln_DB[item.Key].Add_Script(item.Value);
						count++;
					}
					else
					{
						if (item.Value.Length <= 45) continue;
						Vuln vuln = new Vuln();
						vuln.ID = item.Key;
						vuln.Scripts.Add(vuln.Scripts.Count, item.Value);
						vuln.Status = Vuln.NotReviewed;

						datastore.Vuln_DB.Add(vuln.ID, vuln);
						count++;
					}
				}
				BaseClass.Show("Number of scripts imported: " + count);
				datastore.Merge();
			}
		}

		private static string UsernameDir = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
		private static string CmdletFilename = Path.Combine(UsernameDir, "SMv2\\Data\\Cmdlets.txt");
		private static string CurDir = Environment.CurrentDirectory;

		public static string[] Parse_AutoComplete_Cmdlets()
		{
			Log.Add("Parse_AutoComplete_Cmdlets", Log.Level.GEN);

			string file = Path.Combine(UsernameDir, CmdletFilename);

			if (!File.Exists(file) && File.Exists(Path.Combine(CurDir, "Data\\Cmdlets.txt")))
			{
				Log.Add("Copying Cmdlet file");
				File.Copy(Path.Combine(CurDir, "Data\\Cmdlets.txt"), file);
				Log.Add("Copy Complete Cmdlet file");
			}

			StreamReader r;
			try
			{
				// This will check to see if the cmdlets file exists
				// if the cmdlets file doesn't exist then this function will
				// return an empty array.
                if (!File.Exists(file))
                {
					BaseClass.EShow("There was a problem opening the PowerShell Cmdlets file.\n\rFile doesn't exist: " + file);

					return Array.Empty<string>();
                }
                r = new StreamReader(file);
				string doc = r.ReadToEnd();
				r.Close();
				string[] lines = doc.Split(new char[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);

				for (int i = 0; i < lines.Length; i++)
					lines[i] = lines[i].Trim();

				return lines;

			}
            catch (Exception e)
			{
				Log.Add("Unable to read cmdlets.txt file." + e.Message, Log.Level.ERR);
				return Array.Empty<string>();
			}
		}

		public static string Run = "Run";
		public static string Execute = "Execute the following command";
		public static string Substitute = "substituting [";
		public static string Enter = "Enter";
		public static string Try_Parse_PowerShell(string parse_me)
		{
			Log.Add("Try_Parse_PowerShell()");
			if (parse_me == null || string.IsNullOrWhiteSpace(parse_me))
            {
				Log.Add("PowerShell Parse: parse_me is null or whitespace");
				return "";
            }				
			// If parse_me contains registry entries continue to be parsed by registry parser
			if (parse_me.Contains("HKEY_LOCAL_MACHINE"))
				return "";

			// enter "ps_value" ____:
			// "ps_value+"
			// If the "value_name" ____ is greater than / is less than / is equal too "value" ___ ____, this is a finding / this is not a finding

			// CHECK
			// is greater than	= -gt
			// is less than		= -lt
			// is equal too		= -eq
			// is more than		= -gt
			// is not found		= -eq $null

			// RESULT
			// this is a finding
			// this is not a finding
			// this is not applicable

			// The following results should be displayed:

			// Enter 'Net User [account name] | Find /i "Password Last Set"',
			// If the "value_name" ____ is greater than / is less than / is equal too "value" ___ ____, this is a finding / this is not a finding

			Log.Add("Section 1");
			// Split parse_me into lines
			string[] lines = parse_me.Split(new char[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries);
			if (lines == null || lines.Length <= 0)
			{
				Log.Add("Lines null or less than 0");
				return "";
			}

			// Final return script
			StringBuilder script = new StringBuilder();

			// debugging / testings
			List<string> values = new List<string>();

			Log.Add("Section 2");
			foreach (string item in lines)
			{
				string[] qsplit = item.Split(new char[] { '\'', '\"' }, StringSplitOptions.RemoveEmptyEntries);
				if (qsplit == null || qsplit.Length <= 0)
				{
					Log.Add("PowerShell Parse: qsplit null or less than 0");
					return "";
				}

				string thisLine = "if(";
				for (int i = 1; i < qsplit.Length; i++)
				{
					if (i % 2 != 0)
						thisLine += $"'{qsplit[i]}'";
					else
						if (qsplit[i].Contains("is not"))
						thisLine += " -eq ";
					else if (qsplit[i].Contains("this is a finding"))
						thisLine += $"){{ \t\"PASS - value is {qsplit[i-1]}\" \n}}else{{ \n\t\"FAIL - value is not {qsplit[i-1]}\" \n}}";
				}
				if (thisLine != "if(" && thisLine.EndsWith("\n}"))
					values.Add(thisLine);
			}

			Log.Add("Section 3");
			bool addNextLine = false;
			for (int i = 0; i < lines.Length; i++)
			{
				Log.Add("Section 3.1");
				if (addNextLine)
				{
					addNextLine = false;
					continue;
				}

				Log.Add("Section 3.2");
				string lower = lines[i].ToLower();
				// Parses the powershell / cmd from line
				if (lower.StartsWith("enter") && lower.EndsWith(":"))
				{
					Log.Add("Section 3.2.1");
					addNextLine = true;
					string variable = "$result = " + lines[i + 1].Trim('\"');
					script.Append(variable);
					// Determine Logic
					continue;

					// Parse the entire powershell / cmd from line and continue
				}
				else if (lower.StartsWith("enter") && lower.EndsWith("\"."))
				{
					Log.Add("Section 3.2.2");
					string stripped = lines[i].Split(new char[] { '\'', '\"' }, StringSplitOptions.RemoveEmptyEntries)[1];
					string variable = "$result = " + stripped;
					script.Append(variable);
					// Determine Logic
					continue;
				}
				else if(lower.Contains("powershell window and enter."))
                {
					Log.Add("Section 3.2.3");
					StringBuilder tempScript = new StringBuilder();
					int ixStart = i + 1;
					int ixEnd = ixStart + 1;
					if (lines[ixStart].StartsWith("\""))
					{
						Log.Add("Section 3.2.3.1");
						// Find ixEnd
						while (ixEnd <= lines.Length)
						{
							if (lines[ixEnd].EndsWith("\""))
								break;
							ixEnd++;
						}
					}
					else
					{
						Log.Add("Section 3.2.3.2");
						// Find ixStart
						while (ixStart <= lines.Length)
                        {
							if (lines[ixStart].StartsWith("\""))
								break;
							ixStart++;
                        }
						ixEnd = ixStart;
						// Find ixEnd
						while (ixEnd <= lines.Length)
						{
							if (lines[ixEnd].EndsWith("\""))
								break;
							ixEnd++;
						}
					}
					Log.Add("Section 3.2.4");
					for (int j = ixStart; j <= ixEnd; j++)
                    {
						tempScript.AppendLine(lines[j].Trim('\"'));
                    }

					script.Append("$result = " + tempScript);
				
				// Parse the powershell and replace the substitute variable
				}
				else if(lower.StartsWith("enter") && lower.Contains('[') && lower.Contains(']'))
				{
					Log.Add("Section 3.2.5");
					continue;
					int temp1 = lines[i].IndexOf('\"');
					Log.Add("temp1: " + temp1.ToString());
					if(temp1 == null || temp1 <= 0)
					{
						Log.Add("Powershell parse: temp1 is null or less than 0");
						continue;
					}

					string ps = lines[i].Substring(temp1).Substring(0, temp1);
					Log.Add("ps: " + ps);
					if (ps == null || ps.Length <= 0)
                    {
						Log.Add("Powershell parse: ps is null");
						continue;
                    }

					string v = ps.Substring(ps.IndexOf('[')).Substring(0, ps.IndexOf(']'));
					if (v == null || v.Length <= 0)
					{
						Log.Add("Powershell parse: v is null");
						continue;
					}
					string value = $"$value_name = \'{v}\'";
					script.Append(value);
					ps = "$result = " + ps.Replace($"[{v}]", "$value_name");
					script.Append(ps);
				}
				else if(lines[i].Contains("Execute the following command"))
                {
					Log.Add("Section 3.2.6");
					if (lines[i + 1].Length > 1)
						script.Append("$result = " + lines[i + 1]);

                }
			}
			Log.Add("Section 4");

			return script.ToString();
		}

		public readonly static string[] FindingTypes = new string[]
		{
			"If the following",
			"If one of the following",
			"If the registry",
			"If it exists",

			"value exists", //4
            "values exists",

			"does not exist",//6
            "do not exist",

			"requirement is NA",    //8
            "this is a finding",
			"this is not a finding.",

			"with a value of"
		};
		public static string[] RegistryParseKeys = new string[]
		{
			"Registry Hive: ",
			"Registry Path:",
			"Value Name:",
			"Type:",
			"Value:"
		};

		public static string Try_Parse_Registry(string parse_me)
		{
			Log.Add("Try_Parse_Registry()");

			if (parse_me == null || string.IsNullOrWhiteSpace(parse_me))
			{
				Log.Add("Registry Parse: parse_me is null or empty");
				return "";
			}

			bool Exists = false;
			bool Finding = false;
			bool NA = false;

			List<string> SpecificValue = new List<string>();

			StringBuilder sb = new StringBuilder();

			// Parse the check content
			// Find all Finding Types
			// Find all Hives
			// Find all Paths
			// Find all Value Names
			// Find all Values

			List<string> debugList = new List<string>();

			string[] lines = parse_me.Split(new char[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries);
			if (lines == null)
			{
				Log.Add("Registry Parse: lines is null");
				return "";
			}

			List<string> regStack = new List<string>();
			List<string> regFindingType = new List<string>();

			string last_hive = "";
			string last_path = "";
			string last_value_name = "";
			string last_type = "";
			string last_value = "";
			int count = 0;

			#region Build PS Script
			foreach (string item in lines)
			{
				// Store Descriptive Line
				if (item.Contains(FindingTypes[0]) ||
					item.Contains(FindingTypes[1]) ||
					item.Contains(FindingTypes[2]) ||
					item.Contains(FindingTypes[3]) ||
					item.Contains(FindingTypes[4]))
				{
					regFindingType.Add($"#{item}");
					continue;
				}

				#region Gather Values to get Registry
				// Hive Set Last Hive
				if (item.StartsWith(RegistryParseKeys[0]))
					last_hive = item.Replace("\\\\*\\", "").Split(new char[]{' '}, StringSplitOptions.RemoveEmptyEntries)[2];
				// Check for hive path and store
				if (item.StartsWith(RegistryParseKeys[1]))
					last_path = item.Replace("\\\\*\\", "").Split(new char[]{' '}, StringSplitOptions.RemoveEmptyEntries)[2];
				// Check for value name and store
				if (item.StartsWith(RegistryParseKeys[2]))
					last_value_name = item.Replace("\\\\*\\", "").Split(new char[]{' '}, StringSplitOptions.RemoveEmptyEntries)[2];
				// Check for registry type and store
				if (item.StartsWith(RegistryParseKeys[3]))
					last_type = item.Replace("\\\\*\\", "").Split(new char[]{' '}, StringSplitOptions.RemoveEmptyEntries)[1];
                #endregion

                // Check for value and store it
                if (item.StartsWith(RegistryParseKeys[4]))
				{
					// Use regex to parse out multiple values of registry
					Regex regex = new Regex("[0-9]{1,}");
					// Parses all digits out of item
					string[] matches = regex.Matches(item).Cast<Match>().Select(m => m.Value).ToArray();
					if (matches == null)
					{
						Log.Add("Registry Parse: matches is null");
						return "";
					}

					// Parses all words out of the item
					string[] val = item.Split(new char[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
					if (val == null)
                    {
                        Log.Add("Registry Parse: Val is null");
						return "";
                    }

					// If registry is going to be a text value set true
					bool isTextValue = false;

					// if the value length is greater than one and
					// a digit value was able to be parsed then store value
					if(val.Length > 1 && matches.Length > 0)
						last_value = val[1].Replace(",", "");
					else
					{
						// else if
						if(val.Length == 1)
						{
							isTextValue = true;
							last_value = "'" + string.Join("\n", lines.Skip(count + 2).Take(lines.Length - count - 1).ToArray()) + "'";
						}
						else
						{
							isTextValue = true;
							last_value = "'" + item.Replace("Value: ", "") + "'";
							
							//BaseClass.Show("Error Registry Parse:\n" + string.Format("[Items:{0}]Matches:{1}]", item, string.Join(",", matches)));
						}
					}
					debugList.Add(item);
					
					string pass = $"\t\"PASS - {last_value_name} value equals {last_value}\"";
					string fail = $"\t\"FAIL - {last_value_name} value equals $(${last_value_name})\"";

					foreach (string ftype in regFindingType)
					{
						// This sections sets the true/false logic to determine pass fail conditions
						if (ftype.Contains(FindingTypes[4]) || ftype.Contains(FindingTypes[5]) || ftype.Contains(FindingTypes[3]))
							Exists = true;
						if (ftype.Contains(FindingTypes[8]))
							NA = true;
						else if (ftype.Contains(FindingTypes[9]))
							Finding = true;
						// This section finds specific value in line
						if (ftype.Contains(FindingTypes[11]))
						{
							string tempVal = "";
							var ms = regex.Matches(ftype);
							foreach (var m in ms)
							{
								tempVal += m.ToString();
							}
							last_value = tempVal;
						}

						string hive = "HKLM:";
						if (last_hive.ToLower().Contains("current_user"))
							hive = "HKCU:";
						else if (last_hive.ToLower().Contains("classes_root"))
							hive = "HKCR:";
						else if (last_hive.ToLower().Contains("users"))
							hive = "HKU:";
						else if (last_hive.ToLower().Contains("config"))
							hive = "HKCC:";

						// Build the script using the registry values
						string script = $"{ftype}\n#[[{last_value_name}]]\n${last_value_name} = (Get-ItemProperty -Path {hive}{last_path}).{last_value_name}\n";
						// setting the value to match gives a higher chance of pass then an exact match for text.
						//if(isTextValue)
						//	script += $"If(${last_value_name} -match {last_value})" +
						//	"{\n";
						//else
							script += $"If(${last_value_name} -eq {last_value})" +
							"{\n";

						// Logic Table for Pass or Fail
						//          NF  F   NA
						//  VE      P   F   NA
						//  VDNE    P   F   NA
						if (SpecificValue.Capacity >= 1)
						{

							if ((Exists && !Finding) || (!Exists && Finding) || (Exists && NA) || (!Exists && NA))
							{
								script += pass;
								script += "\n}else{\n";
								script += fail;
							}
							else
							{
								script += fail;
								script += "\n}else{\n";
								script += pass;
							}
						}
						else
						{
							if (Exists && Finding)
							{
								script += fail;
								script += "\n}else{\n";
								script += pass;
							}
							else
							{
								script += pass;
								script += "\n}else{\n";
								script += fail;
							}
						}
						script += "\n}";

						// Store the sript in the registry object list of powershell scripts
						sb.AppendLine(script + "\n");
						
					}
					// Reset the value object
					last_value_name = "";
					last_type = "";
					last_value = "";
					regFindingType.Clear();
					
				}

				count++;
			}
			#endregion
			string results = sb.ToString();
			
			return results;
		}

		public static string Validate_Function(string func)
		{
			int leftBrackets = func.Count(x => x == '{');
			int rightBrackets = func.Count(x => x == '}');

			if (leftBrackets == rightBrackets)
				return func;
			else
				return func + "\n\r}";
		}

		public static string Add_User_Initials(string FindingDetails)
		{
			if (FindingDetails == null || FindingDetails.Length <= 0)
				return FindingDetails;

			// Adds users initials to findings.
			string[] initials = Environment.UserName.Split(new char[] { '.' }, StringSplitOptions.RemoveEmptyEntries);
			string inits = "";
			foreach (string item in initials)
				inits += item[0];
			if (!FindingDetails.Contains("Run by: " + inits.ToUpper()) && FindingDetails != "")
				FindingDetails += $"Run by: {inits.ToUpper()} on {DateTime.Now.ToString("HH:mm dd-MM-yyyy")}";

			return FindingDetails;
		}
	}
}
