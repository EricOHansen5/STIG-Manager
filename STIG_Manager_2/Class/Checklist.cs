using System;
using System.Collections.Generic;
using System.IO;
using System.Xml;
using System.Xml.Schema;
using System.Linq;
using System.Windows;
using System.Xml.Linq;

namespace STIG_Manager_2.Class
{
    public class Checklist : BaseClass
    {
		#region Properties

        private Dictionary<string, Vuln> _Vulns = new Dictionary<string, Vuln>();
        public Dictionary<string, Vuln> Vulns
        {
            get { return _Vulns; }
            set { if (value != _Vulns) _Vulns = value; OnPropertyChanged(); }
        }

		public Info info = new Info();

		public bool Loaded = false;
		#endregion

		public bool Load_Checklist(string filename)
		{
			Log.Add("Load_Checklist()", Log.Level.GEN);

			if (File.Exists(filename))
			{
				// Reset the Dictionary
				Vulns = new Dictionary<string, Vuln>();
				info.CustomName = filename;
				Log.Add("Checklist info customName = " + filename);
				// Get Schema Settings
				XmlReaderSettings xmlReaderSettings = GenererateXmlReaderSettings();

				try
				{
					using (XmlReader reader = XmlReader.Create(filename, xmlReaderSettings))
					{
						while (reader.Read())
						{
							if (reader.IsStartElement())
							{
								Log.Add("XML Parse 'Reader Name': " + reader.Name);
								switch (reader.Name)
								{
									case "ASSET":
										{
											//ObtainSystemInformation(reader);
											break;
										}
									case "STIG_INFO":
										{
											ObtainStigInfo(reader);
											break;
										}
									case "VULN":
										{
											ParseStigDataNodes(reader);
											break;
										}
									default: { break; }
								}
							}
						}
					}
					Loaded = true;
					Log.Add("Load_Checklist() Complete");
					return true;
				}
				catch (Exception e)
				{
					EShow("Load_Checklist - Error: " + e.Message);
					Loaded = false;
					return false;
				}
			}else{
				EShow("Load_Checklist - Error: File Doesn't Exist");
				Loaded = false;
				return false;
			}
		}

		public bool Copy_Checklist(string filename, bool showMessage = false)
		{
			Log.Add("Copy_Checklist", Log.Level.GEN);

			if (File.Exists(info.CustomName))
			{
				string dir = Path.GetDirectoryName(filename);

				if (Directory.Exists(dir))
					// create directory
					Directory.CreateDirectory(Path.GetDirectoryName(filename));

				// check if the new filename is the current checklist file
				if (info.CustomName == filename)
				{
					// if current checklist is the same
					Log.Add("Filename is the same.");
				}
				else
				{
					// overwrite
					File.Copy(info.CustomName, filename, true);

					if (File.Exists(filename))
					{
						Log.Add("Copy File Success");
						if (showMessage)
							MessageBox.Show("Checkfile Created!", "File Created", MessageBoxButton.OK, MessageBoxImage.Information);
					}
					else
					{
						Log.Add("Copy File Failed", Log.Level.ERR);
						if (showMessage)
							MessageBox.Show("Error: Checkfile NOT Created.", "File Created", MessageBoxButton.OK, MessageBoxImage.Error);
					}
				}
				return true;
			}
			else
			{
				MessageBox.Show($"Unable to create new copy of checkfile. {info.CustomName} doesn't exist.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
				return false;
			}
		}

		public static bool Update_Checklist(string filename, Dictionary<string, Vuln> TempVulns, bool showMessage = false)
		{
			Log.Add("Update_Checklist()", Log.Level.GEN);

			try
			{
				if (File.Exists(filename))
					Log.Add($"Update Checklist - {filename} Exists");
				else
					Log.Add($"Update Checklist - {filename} NOT Exists");

				// Loads xml document
				XDocument checkfile = XDocument.Load(filename, LoadOptions.PreserveWhitespace);
				Log.Add("Encoding: " + checkfile.Declaration.Encoding);
				checkfile.Declaration = new XDeclaration("1.0", "utf-8", null);
				Log.Add("Encoding: " + checkfile.Declaration.Encoding);

				// parse the stig node
				var stgs = checkfile.Root.Element("STIGS");

				// parse the vuln nodes
				var vulns = stgs.Element("iSTIG").Elements("VULN");

				foreach (Vuln item in TempVulns.Values)
				{
					string id = item.ID;
					//var select = vulns.FirstOrDefault(x => x.Element("STIG_DATA").Element("ATTRIBUTE_DATA").Value == "V-63319");
					var select = vulns.FirstOrDefault(x => x.Element("STIG_DATA").Element("ATTRIBUTE_DATA").Value == id);
					if (select != null)
					{
						//select.SetElementValue("FINDING_DETAILS", "somecoolfindingnotexpected");
						select.SetElementValue("STATUS", item.Status);
						select.SetElementValue("FINDING_DETAILS", item.FindingDetails);
						select.SetElementValue("COMMENTS", item.Comments);
						//select.SetElementValue("SEVERITY_OVERRIDE", item.SeverityOverride);
						select.SetElementValue("SEVERITY_JUSTIFICATION", item.SeverityJustification);
					}
					else
					{
						Log.Add("Unable to update " + id, Log.Level.ERR);
						Console.WriteLine("Unable to update " + id);
					}
				}
				checkfile.Save(filename, SaveOptions.DisableFormatting);
				if (showMessage)
					MessageBox.Show("Update Complete!", "Update Checkfile", MessageBoxButton.OK, MessageBoxImage.Information);
				return true;
			}
			catch (IOException ioe)
			{
				Log.Add("Update Check - IOERROR: " + ioe.Message, Log.Level.ERR);
				MessageBox.Show("Update Error!\n\r\n\r" + ioe.Message, "Update Checkfile", MessageBoxButton.OK, MessageBoxImage.Error);
				return false;
			}
			catch (Exception e)
			{
				Log.Add("Update Check - ERROR: " + e.Message, Log.Level.ERR);
				MessageBox.Show("Update Error!\n\r\n\r" + e.Message, "Update Checkfile", MessageBoxButton.OK, MessageBoxImage.Error);
				return false;
			}
		}

		public static string Generate_Filename(string filename, string computer)
		{
			string dir = Path.GetDirectoryName(filename);
			string name = Path.GetFileNameWithoutExtension(filename);
			string ext = Path.GetExtension(filename);
			// Combine path of directory of checkfile with computername
			if(computer == "")
			{
				return Path.Combine(dir, $"{name}{ext}");
			}
			return Path.Combine(dir, $"{name}_{computer.Replace('.', '_')}{ext}");
		}

		#region XML Parsing
		private static XmlReaderSettings GenererateXmlReaderSettings()
		{
			try
			{

				XmlReaderSettings xmlReaderSettings = new XmlReaderSettings
				{

					//xmlReaderSettings.IgnoreWhitespace = true;
					//xmlReaderSettings.IgnoreComments = true;
					
					ValidationType = ValidationType.Schema
				};
				xmlReaderSettings.ValidationFlags |= XmlSchemaValidationFlags.ProcessInlineSchema;
				xmlReaderSettings.ValidationFlags |= XmlSchemaValidationFlags.ProcessSchemaLocation;
				xmlReaderSettings.ValidationEventHandler += new ValidationEventHandler(ValidationCallBack);
				return xmlReaderSettings;
			}
			catch (Exception exception)
			{
				Console.Write("Unable to generate XmlReaderSettings.");
				throw exception;
			}
		}
		// Display any warnings or errors.
		private static void ValidationCallBack(object sender, ValidationEventArgs args)
		{
			if (args.Severity == XmlSeverityType.Warning)
				Console.WriteLine("\tWarning: Matching schema not found.  No validation occurred." + args.Message);
			else
				Console.WriteLine("\tValidation error: " + args.Message);

		}

/*		private void ObtainSystemInformation(XmlReader xmlReader)
		{
			try
			{
				while (xmlReader.Read())
				{
					if (xmlReader.IsStartElement())
					{
						switch (xmlReader.Name)
						{
							case "ROLE":
								{
									asset._Role = ObtainCurrentNodeValue(xmlReader);
									break;
								}
							case "ASSET_TYPE":
								{
									asset._Type = ObtainCurrentNodeValue(xmlReader);
									break;
								}
							case "HOST_NAME":
								{
									asset._Host_Name = ObtainCurrentNodeValue(xmlReader);
									break;
								}
							case "HOST_IP":
								{
									asset._Host_IP = ObtainCurrentNodeValue(xmlReader);
									break;
								}
							case "HOST_MAC":
								{
									asset._Host_MAC = ObtainCurrentNodeValue(xmlReader);
									break;
								}
							case "HOST_FQDN":
								{
									asset._Host_FQDN = ObtainCurrentNodeValue(xmlReader);
									break;
								}
							case "TECH_AREA":
								{
									asset._Tech_Area = ObtainCurrentNodeValue(xmlReader);
									break;
								}
							case "TARGET_KEY":
								{
									asset._Target_Key = ObtainCurrentNodeValue(xmlReader);
									break;
								}
							case "WEB_OR_DATABASE":
								{
									asset._Web_or_Database = ObtainCurrentNodeValue(xmlReader);
									break;
								}
							case "WEB_DB_SITE":
								{
									asset._Web_DB_Site = ObtainCurrentNodeValue(xmlReader);
									break;
								}
							case "WEB_DB_INSTANCE":
								{
									asset._Web_DB_Instance = ObtainCurrentNodeValue(xmlReader);
									break;
								}
							default:
								{ break; }
						}
					}
					else if (xmlReader.NodeType == XmlNodeType.EndElement && xmlReader.Name.Equals("ASSET"))
					{ break; }
				}
			}
			catch (Exception exception)
			{
				Console.WriteLine("Unable to obtain host system information.");
				throw exception;
			}
		}
*/
		private void ObtainStigInfo(XmlReader xmlReader)
		{
			try
			{
				xmlReader.Read();
				while (xmlReader.Read())
				{
					if (xmlReader.IsStartElement() && xmlReader.Name.Equals("SID_NAME"))
					{
						xmlReader.Read();
						switch (xmlReader.Value)
						{
							case "version":
								{
									info.Version = ObtainStigInfoSubNodeValue(xmlReader);
									break;
								}
							case "classification":
								{
									info.Classification = ObtainStigInfoSubNodeValue(xmlReader);
									break;
								}
							case "stigid":
								{
									info.StigID = ObtainStigInfoSubNodeValue(xmlReader);
									break;
								}
							case "description":
								{
									info.Description = ObtainStigInfoSubNodeValue(xmlReader);
									break;
								}
							case "filename":
								{
									info.FileName = ObtainStigInfoSubNodeValue(xmlReader);
									break;
								}
							case "releaseinfo":
								{
									info.ReleaseInfo = ObtainStigInfoSubNodeValue(xmlReader);
									break;
								}
							case "title":
								{
									info.Title = ObtainStigInfoSubNodeValue(xmlReader);
									break;
								}
							case "uuid":
								{
									info.UUID = ObtainStigInfoSubNodeValue(xmlReader);
									break;
								}
							case "notice":
								{
									info.Notice = ObtainStigInfoSubNodeValue(xmlReader);
									break;
								}
							default:
								{ break; }
						}
					}
					else if (xmlReader.NodeType == XmlNodeType.EndElement && xmlReader.Name.Equals("STIG_INFO"))
					{ break; }
				}
			}

			catch (Exception exception)
			{
				Console.WriteLine("Unable to obtain STIG information.");
				throw exception;
			}
		}

		private string ObtainStigInfoSubNodeValue(XmlReader xmlReader)
		{
			try
			{
				string stigInfoPortion = xmlReader.Value;
				string stigInfoValue = string.Empty;
				while (xmlReader.Read())
				{
					if (xmlReader.IsStartElement() && xmlReader.Name.Equals("SID_DATA"))
					{
						xmlReader.Read();
						stigInfoValue = xmlReader.Value;
						if (stigInfoPortion.Equals("version"))
						{
							if (!string.IsNullOrWhiteSpace(stigInfoValue))
							{ stigInfoValue = "V-" + stigInfoValue; }
							else
							{ stigInfoValue = "V?"; }
						}
						if (stigInfoPortion.Equals("releaseinfo"))
						{
							if (!string.IsNullOrWhiteSpace(stigInfoValue))
							{ stigInfoValue = "R-" + stigInfoValue.Split(':')[1].Split(' ')[1] + " (" + stigInfoValue.Split(':')[2] + " )"; }
							//{ stigInfoValue = "R" + stigInfoValue.Split(' ')[1].Split(' ')[0].Trim(); }
							else
							{ stigInfoValue = "R?"; }
						}
						return stigInfoValue;
					}
					else if (xmlReader.NodeType == XmlNodeType.EndElement && xmlReader.Name.Equals("SI_DATA"))
					{
						if (string.IsNullOrWhiteSpace(stigInfoValue))
						{
							switch (stigInfoPortion)
							{
								case "version":
									{ return "V?"; }
								case "releaseinfo":
									{ return "R?"; }
								default:
									{ return string.Empty; }
							}
						}
						return stigInfoValue;
					}
					else
					{ continue; }
				}
				return "Read too far!";
			}
			catch (Exception exception)
			{
				Console.WriteLine("Unable to obtain the value from the STIG Info sub-node");
				throw exception;
			}
		}

		private string ObtainAttributeDataNodeValue(XmlReader xmlReader)
		{
			try
			{
				while (!xmlReader.Name.Equals("ATTRIBUTE_DATA"))
				{ xmlReader.Read(); }
				xmlReader.Read();
				string value = xmlReader.Value;
				value = value.Replace("&gt", ">");
				value = value.Replace("&lt", "<");
				xmlReader.Read();
				xmlReader.Read();
				return value;
			}
			catch (Exception exception)
			{
				Console.WriteLine("Unable to obtain Attribute Data node value.");
				throw exception;
			}
		}

		private string ObtainCurrentNodeValue(XmlReader xmlReader)
		{
			try
			{
				xmlReader.Read();
				string value = xmlReader.Value;
				value = value.Replace("&gt", ">");
				value = value.Replace("&lt", "<");
				return value;
			}
			catch (Exception exception)
			{
				Console.WriteLine("Unable to obtain currently accessed node value.");
				throw exception;
			}
		}

		private void ParseStigDataNodes(XmlReader xmlReader)
		{
			try
			{
				while (xmlReader.Read())
				{

					Vuln vuln = new Vuln();

					while (xmlReader.Read())
					{
						if (xmlReader.Name.Equals("STIG_DATA") || xmlReader.Name.Equals(""))
						{
							xmlReader.Read();
							if (xmlReader.Value.Contains("\n") && xmlReader.Value.Contains("\t"))
								xmlReader.Read();
						}
						if (xmlReader.Name.Equals("VULN_ATTRIBUTE"))
						{
							xmlReader.Read();
							switch (xmlReader.Value)
							{
								case "Vuln_Num":
									{
										vuln.ID = ObtainAttributeDataNodeValue(xmlReader);
										break;
									}
								case "Severity":
									{
										vuln.Severity = ObtainAttributeDataNodeValue(xmlReader);
										break;
									}
								case "Group_Title":
									{
										vuln.GroupTitle = ObtainAttributeDataNodeValue(xmlReader);
										break;
									}
								case "Rule_ID":
									{
										vuln.RuleID = ObtainAttributeDataNodeValue(xmlReader);
										break;
									}
								case "Rule_Ver":
									{
										vuln.RuleVersion = ObtainAttributeDataNodeValue(xmlReader);
										break;
									}
								case "Rule_Title":
									{
										vuln.RuleTitle = ObtainAttributeDataNodeValue(xmlReader);
										break;
									}
								case "Vuln_Discuss":
									{
										vuln.Discussion = ObtainAttributeDataNodeValue(xmlReader);
										break;
									}
								case "IA_Controls":
									{
										//vuln.IAControls = ObtainAttributeDataNodeValue(xmlReader);
										break;
									}
								case "Check_Content":
									{
										vuln.CheckContent = ObtainAttributeDataNodeValue(xmlReader);
										break;
									}
								case "Fix_Text":
									{
										vuln.FixText = ObtainAttributeDataNodeValue(xmlReader);
										break;
									}
								case "False_Positives":
									{
										//vuln.FalsePositive = ObtainAttributeDataNodeValue(xmlReader);
										break;
									}
								case "False_Negatives":
									{
										//vuln.FalseNegatives = ObtainAttributeDataNodeValue(xmlReader);
										break;
									}
								case "Documentable":
									{
										//vuln.Documentable = ObtainAttributeDataNodeValue(xmlReader);
										break;
									}
								case "Mitigations":
									{
										//vuln.Mitigations = ObtainAttributeDataNodeValue(xmlReader);
										break;
									}
								case "Potential_Impact":
									{
										//vuln.PotentialImpact = ObtainAttributeDataNodeValue(xmlReader);
										break;
									}
								case "Third_Party_Tools":
									{
										//vuln.ThirdPartyTools = ObtainAttributeDataNodeValue(xmlReader);
										break;
									}
								case "Mitigation_Control":
									{
										//vuln.MitigationControl = ObtainAttributeDataNodeValue(xmlReader);
										break;
									}
								case "Responsibility":
									{
										//vuln.Responsibility = ObtainAttributeDataNodeValue(xmlReader);
										break;
									}
								case "Security_Override_Guidance":
									{
										//vuln.SecurityOverrideGuidance = ObtainAttributeDataNodeValue(xmlReader);
										break;
									}
								case "Check_Content_Ref":
									{
										//vuln.CheckContentRef = ObtainAttributeDataNodeValue(xmlReader);
										break;
									}
								case "Weight":
									{
										//vuln.Weight = ObtainAttributeDataNodeValue(xmlReader);
										break;
									}
								case "Class":
									{
										//vuln.Class = ObtainAttributeDataNodeValue(xmlReader);
										break;
									}
								case "STIGRef":
									{
										//vuln.STIGRef = ObtainAttributeDataNodeValue(xmlReader);
										break;
									}
								case "TargetKey":
									{
										//vuln.TargetKey = ObtainAttributeDataNodeValue(xmlReader);
										break;
									}
								case "CCI_REF":
									{
										//vuln.CCIRef = ObtainAttributeDataNodeValue(xmlReader);
										break;
									}

								default: { break; }
							}
						}
						else if (xmlReader.IsStartElement() && xmlReader.Name.Equals("STATUS"))
						{
							xmlReader.Read();
							vuln.Status = xmlReader.Value;
							xmlReader.Read();
						}
						else if (xmlReader.IsStartElement() && xmlReader.Name.Equals("FINDING_DETAILS"))
						{
							xmlReader.Read();
							vuln.FindingDetails = xmlReader.Value;
							xmlReader.Read();
						}
						else if (xmlReader.IsStartElement() && xmlReader.Name.Equals("COMMENTS"))
						{
							xmlReader.Read();
							vuln.Comments = xmlReader.Value;
							xmlReader.Read();
						}
						else if (xmlReader.IsStartElement() && xmlReader.Name.Equals("SEVERITY_OVERRIDE"))
						{
							xmlReader.Read();
							//vuln.SeverityOverride = xmlReader.Value;
							xmlReader.Read();
						}
						else if (xmlReader.IsStartElement() && xmlReader.Name.Equals("SEVERITY_JUSTIFICATION"))
						{
							xmlReader.Read();
							vuln.SeverityJustification = xmlReader.Value;
							xmlReader.Read();
							break;
						}
					}

					// After parsing all vuln data check to make sure vuln data is valid
					// then check dictionary of vulns to see if key exists
					// if the key doesn't exist then add vuln to the dictionary using its vuln number
					// else if it already exists then update that vuln with the new data.
					if (!string.IsNullOrEmpty(vuln.ID))
					{
						// Hidden(true) will not allow item to be displayed when this checkfile is in use.
						vuln.IsHidden = false;
						Vulns.Add(vuln.ID, vuln);
					}
				}
			}
			catch (Exception exception)
			{
				Log.Add("Checklist Load Error: Unable to parse STIG data node", Log.Level.ERR);
			}
		}

		#endregion
	}
}
