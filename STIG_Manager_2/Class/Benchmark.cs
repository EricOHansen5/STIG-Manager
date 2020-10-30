using System;
using System.Collections.Generic;
using System.IO;
using System.Net.NetworkInformation;
using System.Text;
using System.Xml;
using System.Xml.Schema;

namespace STIG_Manager_2.Class
{
    public class Benchmark : BaseClass
    {

		#region Properties

		private string _Title = "";
		public string Title
		{
			get { return _Title; }
			set { 
				if (value != _Title) 
					_Title = value;
				if (value == null)
					return;
				Short_Title = value.Replace("Microsoft ", "");
				OnPropertyChanged(); }
		}

		private string _Short_Title = "";
		public string Short_Title
		{
			get {
				if (_Short_Title == null)
					return "";
				return _Short_Title; }
			set { if (value != _Short_Title) _Short_Title = value; OnPropertyChanged(); }
		}

        private string _Source = "";
        public string Source
        {
            get { return _Source; }
            set { if (value != _Source) _Source = value; OnPropertyChanged(); }
        }

        private string _Release = "";
        public string Release
        {
            get { return _Release; }
            set { if (value != _Release) _Release = value; OnPropertyChanged(); }
        }

		private DateTime _ReleaseDate;
		public DateTime ReleaseDate
		{
			get { return _ReleaseDate; }
			set { 
				if (value != _ReleaseDate) 
					_ReleaseDate = value;
				Date_String = value.ToString("dd MMM yyyy");
				OnPropertyChanged(); }
		}

		private string _Date_String = "";
		public string Date_String
		{
			get { return _Date_String; }
			set { if (value != _Date_String) _Date_String = value; OnPropertyChanged(); }
		}

        private string _Version = "";
        public string Version
        {
            get { return _Version; }
            set { if (value != _Version) _Version = value; OnPropertyChanged(); }
        }

        private Dictionary<string, int> _SelectedVulns = new Dictionary<string, int>();
        public Dictionary<string, int> SelectedVulns
        {
            get { return _SelectedVulns; }
            set { if (value != _SelectedVulns) _SelectedVulns = value; OnPropertyChanged(); }
        }

		public bool Loaded = false;
		#endregion


		public bool Load_Benchmark(string fileName)
		{
			Log.Add("ReadXccdfFile", Log.Level.GEN);

			try
			{
				if (fileName.IsFileInUse())
				{
					Log.Add(fileName + " is in use; please close any open instances and try again.", Log.Level.WARN);
					Show(fileName + " is in use; please close any open instances and try again.");
					Loaded = false;
					return false;
				}
				if (Path.GetExtension(fileName).ToLower().Contains(".zip"))
					fileName = fileName.GetFilenameFromZIP();

				ParseXccdfWithXmlReader(fileName);
				Loaded = true;
				return true;
			}
			catch (Exception e)
			{
				Log.Add("Unable to process XCCDF file." + e.Message, Log.Level.ERR);
				Loaded = false;
				return false;
			}
		}

		private void ParseXccdfWithXmlReader(string fileName)
		{
			try
			{
				//XmlReaderSettings xmlReaderSettings = GenerateXmlReaderSettings();

				using (XmlReader xmlReader = XmlReader.Create(fileName))
				{
					while (xmlReader.Read())
					{
						if (xmlReader.IsStartElement())
						{
							if (xmlReader.Prefix == "xccdf")
							{
								ParseXccdfFromScc(xmlReader);
							}
							else
							{
								if (xmlReader.Name == "title")
								{
									Title = xmlReader.ReadInnerXml();
								}
								continue;
							}
						}
						else
							continue;
					}
				}
			}
			catch (Exception exception)
			{
				Console.WriteLine("Unable to parse XCCDF using XML reader.");
				throw exception;
			}
		}

		#region Parse XCCDF File From SCC

		private void ParseXccdfFromScc(XmlReader xmlReader)
		{
			try
			{
				while (xmlReader.Read())
				{
					if (xmlReader.IsStartElement())
					{
						switch (xmlReader.Name)
						{
							case "xccdf:title":
								{
									Source = GetSccXccdfTitle(xmlReader);
									break;
								}
							case "xccdf:plain-text":
								{
									Release = GetSccXccdfRelease(xmlReader);
									break;
								}
							case "xccdf:version":
								{
									Version = GetSccXccdfVersion(xmlReader);
									break;
								}
							case "xccdf:Profile":
								{
									string vuln_name = GetSccXccdfProfile(xmlReader);
									while (xmlReader.Name != "xccdf:select")
										xmlReader.Read();

									while (xmlReader.Name == "xccdf:select")
									{
										string vuln_id = GetSccXccdfSelect(xmlReader);
										if (SelectedVulns.ContainsKey(vuln_id))
											SelectedVulns[vuln_id]++;
										else
											SelectedVulns.Add(vuln_id, 0);
										xmlReader.Read();
										xmlReader.Read();
									}

									break;
								}
							case "xccdf:Value":
								{
									/*sValue val = new sValue
									{
										ID = GetSccXccdfAttribute(xmlReader, "id"),
										Type = GetSccXccdfAttribute(xmlReader, "type"),
										Oper = GetSccXccdfAttribute(xmlReader, "operator")
									};*/

									xmlReader.Read();
									xmlReader.Read();
									if (xmlReader.Name == "xccdf:title")
									{
										xmlReader.Read();
										//val.Title = xmlReader.Value;
									}

									xmlReader.Read();
									xmlReader.Read();
									xmlReader.Read();
									if (xmlReader.Name == "xccdf:description")
									{
										xmlReader.Read();
										//val.Description = xmlReader.Value;
									}

									xmlReader.Read();
									xmlReader.Read();
									xmlReader.Read();
									if (xmlReader.Name == "xccdf:value" && string.IsNullOrWhiteSpace(xmlReader.GetAttribute("selector")))
									{
										xmlReader.Read();
										//val.Value = xmlReader.Value;
									}

									xmlReader.Read();
									xmlReader.Read();
									xmlReader.Read();
									while (xmlReader.Name == "xccdf:value")
									{
										xmlReader.Read();
										//val.Selectors.Add(xmlReader.Value);
										xmlReader.Read();
										xmlReader.Read();
										xmlReader.Read();
									}
									//Benchmark.Values.Add(val);*/
									break;
								}
							case "xccdf:Group":
								{
									GetSccXccdfVulnerabilityInformation(xmlReader);
									break;
								}
							case "xccdf:TestResult":
								{
									//ParseSccXccdfTestResult(xmlReader);
									break;
								}
							default: { break; }
						}
					}
				}
			}
			catch (Exception exception)
			{
				Console.WriteLine("Unable to parse SCC XCCDF.");
				throw exception;
			}
		}

		private static string GetSccXccdfTitle(XmlReader xmlReader)
		{
			try
			{
				xmlReader.Read();
				string xccdfTitle = xmlReader.Value + " Benchmark";
				return xccdfTitle;
			}
			catch (Exception exception)
			{
				Console.WriteLine("Unable to get XCCDF title.");
				throw exception;
			}
		}

		private string GetSccXccdfRelease(XmlReader xmlReader)
		{
			try
			{
				if (!string.IsNullOrWhiteSpace(xmlReader.GetAttribute("id")) && xmlReader.GetAttribute("id").Equals("release-info"))
				{
					xmlReader.Read();
					string date = xmlReader.Value.Split(new string[] { "Date: " }, StringSplitOptions.RemoveEmptyEntries)[1];
					string releaseInfo = "R-" + xmlReader.Value.Split(' ')[1] + " ( " + date + " )";
					ReleaseDate = DateTime.Parse(date);
					return releaseInfo;
				}
				return "Unable to get XCCDF release.";
			}
			catch (Exception exception)
			{
				Console.WriteLine("Unable to get XCCDF release.");
				throw exception;
			}
		}

		private string GetSccXccdfProfile(XmlReader xmlReader)
		{
			try
			{
				if (!string.IsNullOrWhiteSpace(xmlReader.GetAttribute("id")))
				{
					//xmlReader.Read();
					string profileID = xmlReader.GetAttribute("id").Split(new string[] { "stig_profile_" }, StringSplitOptions.None)[1].Replace('_', ' ');
					return profileID;
				}
				return "Unable to get XCCDF Profile.";
			}
			catch (Exception exception)
			{
				Console.WriteLine("Unable to get XCCDF Profile.");
				throw exception;
			}
		}

		private string GetSccXccdfSelect(XmlReader xmlReader)
		{
			try
			{

				if (!string.IsNullOrWhiteSpace(xmlReader.GetAttribute("idref")) && xmlReader.GetAttribute("selected").Equals("true"))
				{
					return xmlReader.GetAttribute("idref").Split(new string[] { "stig_group_" }, StringSplitOptions.None)[1];
				}
				return "Unable to get XCCDF Select.";
			}
			catch (Exception exception)
			{
				Console.WriteLine("Unable to get XCCDF Select.");
				throw exception;
			}
		}

		private string GetSccXccdfAttribute(XmlReader xmlReader, string attribute)
		{
			try
			{

				if (!string.IsNullOrWhiteSpace(xmlReader.GetAttribute(attribute)))
				{

					return xmlReader.GetAttribute(attribute);
				}
				return "Unable to get XCCDF Attribute.";
			}
			catch (Exception exception)
			{
				Console.WriteLine("Unable to get XCCDF Attribute.");
				throw exception;
			}
		}

		private string GetSccXccdfVersion(XmlReader xmlReader)
		{
			try
			{
				xmlReader.Read();
				string versionInfo = "V-" + xmlReader.Value;
				return versionInfo;
			}
			catch (Exception exception)
			{
				Console.WriteLine("Unable to get XCCDF version.");
				throw exception;
			}
		}

		private void GetSccXccdfVulnerabilityInformation(XmlReader xmlReader)
		{
			try
			{
				//sGroup group = new sGroup
				//{
				//	ID = xmlReader.GetAttribute("id")
				//};

				while (xmlReader.Read())
				{
					if (xmlReader.IsStartElement() && xmlReader.Name.Equals("xccdf:Rule"))
					{
						//group.Rule = xmlReader.GetAttribute("id");
						//group.Risk = ConvertSeverityToRawRisk(xmlReader.GetAttribute("severity"));
						//group.Impact = ConvertSeverityToImpact(xmlReader.GetAttribute("severity"));

						while (xmlReader.Read())
						{
							if (xmlReader.IsStartElement())
							{
								switch (xmlReader.Name)
								{
									case "xccdf:title":
										{
											xmlReader.Read();
											//group.Title = xmlReader.Value;
											break;
										}
									case "xccdf:description":
										{
											xmlReader.Read();
											//group.Description = xmlReader.Value;

											//group.Description.Replace("&lt;", "<");
											//group.Description.Replace("&gt;", ">");
											break;
										}
									case "xccdf:ident":
										{
											if (xmlReader.GetAttribute("system").Equals(@"http://iase.disa.mil/cci"))
											{
												xmlReader.Read();
												//group.System = xmlReader.Value;
											}
											break;
										}
									case "xccdf:fixtext":
										{
											xmlReader.Read();
											//group.FixText = xmlReader.Value.Replace("&gt;", ">");
											break;
										}
									default: { break; }
								}
							}
						}
						//Benchmark.Groups.Add(group);
					}
				}
			}
			catch (Exception exception)
			{
				Console.WriteLine("Unable to get XCCDF vulnerability information.");
				throw exception;
			}
		}

        //private void ParseSccXccdfTestResult(XmlReader xmlReader) {
        //	try {
        //		while(xmlReader.Read()) {
        //			if(xmlReader.IsStartElement()) {
        //				switch(xmlReader.Name) {
        //					case "cdf:target-facts": {
        //							SetAffectedAssetInformationFromSccFile(xmlReader);
        //							break;
        //						}
        //					case "cdf:rule-result": {
        //							SetXccdfScanResultFromSccFile(xmlReader);
        //							break;
        //						}
        //					case "cdf:score": {
        //							SetXccdfScoreFromSccFile(xmlReader);
        //							break;
        //						}
        //					default: { break; }
        //				}
        //			}
        //		}
        //	} catch(Exception exception) {
        //		Console.WriteLine("Unable to parse XCCDF test results.");
        //		throw exception;
        //	}
        //}

        //private void SetAffectedAssetInformationFromSccFile(XmlReader xmlReader) {
        //	try {
        //		while(xmlReader.Read()) {
        //			if(xmlReader.IsStartElement() && xmlReader.Name.Equals("cdf:fact")) {
        //				switch(xmlReader.GetAttribute("name")) {
        //					case "urn:scap:fact:asset:identifier:host_name": {
        //							xmlReader.Read();
        //							"HostName", xmlReader.Value;
        //							break;
        //						}
        //					case "urn:scap:fact:asset:identifier:ipv4": {
        //							xmlReader.Read();
        //							"IpAddress", xmlReader.Value;
        //							break;
        //						}
        //					default: { break; }
        //				}
        //			} else if(xmlReader.NodeType == XmlNodeType.EndElement && xmlReader.Name.Equals("cdf:target-facts")) {

        //				return;
        //			}
        //		}
        //	} catch(Exception exception) {
        //		Console.WriteLine("Unable to set affected asset information.");
        //		throw exception;
        //	}
        //}

        //private void SetXccdfScanResultFromSccFile(XmlReader xmlReader) {
        //	try {
        //		"RuleId" xmlReader.GetAttribute("idref");
        //		while(xmlReader.Read()) {
        //			if(xmlReader.IsStartElement() && xmlReader.Name.Equals("cdf:result")) {
        //				xmlReader.Read();
        //				"Status", ConvertXccdfResultToStatus(xmlReader.Value);
        //				break;
        //			} else if(xmlReader.NodeType == XmlNodeType.EndElement && xmlReader.Name.Equals("cdf:rule-result")) { return; }
        //		}
        //	} catch(Exception exception) {
        //		Console.WriteLine("Unable to set XCCDF scan result.");
        //		throw exception;
        //	}
        //}

        //private void SetXccdfScoreFromSccFile(XmlReader xmlReader) {
        //	while(!xmlReader.Name.Equals("cdf:TestResult")) {
        //		if(!string.IsNullOrWhiteSpace(xmlReader.GetAttribute("system")) && xmlReader.GetAttribute("system").Equals("urn:xccdf:scoring:default")) {
        //			xmlReader.Read();
        //			"ScapScore", xmlReader.Value;
        //		} else { xmlReader.Read(); }
        //	}
        //}

        #endregion


        #region Parse XCCDF File From ACAS

        //private void ParseXccdfFromAcas(XmlReader xmlReader) {
        //	try {
        //		while(xmlReader.Read()) {
        //			if(xmlReader.IsStartElement()) {
        //				switch(xmlReader.Name) {
        //					case "xccdf:benchmark": {
        //							GetAcasXccdfTitle(xmlReader)));
        //							break;
        //						}
        //					case "xccdf:target-facts": {
        //							GetAcasXccdfTargetInfo(xmlReader);
        //							break;
        //						}
        //					case "xccdf:rule-result": {
        //							ParseAcasXccdfTestResult(xmlReader);
        //							break;
        //						}
        //					case "xccdf:score": {
        //							xmlReader.Read();
        //							 xmlReader.Value));
        //							break;
        //						}
        //					default: { break; }
        //				}
        //			}
        //		}
        //	} catch(Exception exception) {
        //		Console.WriteLine("Unable to parse ACAS XCCDF.");
        //		throw exception;
        //	}
        //}

        //private string GetAcasXccdfTitle(XmlReader xmlReader) {
        //	try {

        //		xccdfTitle = xmlReader.GetAttribute("href");
        //		xccdfTitle = xccdfTitle.Split(new string[] { "_SCAP" }, StringSplitOptions.None)[0].Replace('_', ' ');
        //		if(Regex.IsMatch(xccdfTitle, @"\bU \b")) { xccdfTitle = Regex.Replace(xccdfTitle, @"\bU \b", ""); }
        //		Match match = Regex.Match(xccdfTitle, @"V\dR\d{1,10}");
        //		if(match.Success) {
        //			versionInfo = match.Value.Split('R')[0];
        //			releaseInfo = "R" + match.Value.Split('R')[1];
        //		}
        //		xccdfTitle = xccdfTitle.Replace(match.Value + " ", "") + " Benchmark";
        //		return xccdfTitle;
        //	} catch(Exception exception) {
        //		Console.WriteLine("Unable to obtain XCCDF title.");
        //		throw exception;
        //	}
        //}

        //private void GetAcasXccdfTargetInfo(XmlReader xmlReader) {
        //	try {
        //		while(xmlReader.Read()) {
        //			if(xmlReader.IsStartElement()) {
        //				switch(xmlReader.GetAttribute("name")) {
        //					case "urn:xccdf:fact:asset:identifier:host_name": {
        //							xmlReader.Read();
        //							xmlReader.Value);
        //							break;
        //						}
        //					case "urn:xccdf:fact:asset:identifier:ipv4": {
        //							xmlReader.Read();
        //							xmlReader.Value;
        //							break;
        //						}
        //					default: { break; }
        //				}
        //			} else if(xmlReader.NodeType == XmlNodeType.EndElement && xmlReader.Name.Equals("xccdf:target-facts")) { return; }
        //		}
        //	} catch(Exception exception) {
        //		Console.WriteLine("Unable to obtain XCCDF target information.");
        //		throw exception;
        //	}
        //}

        //private void ParseAcasXccdfTestResult(XmlReader xmlReader) {
        //	try {
        //			"VulnId", xmlReader.GetAttribute("idref").Replace("_rule", "");

        //			"RuleId", xmlReader.GetAttribute("idref").Replace("_rule", "");

        //			"RawRisk", xmlReader.GetAttribute("severity");

        //			"Impact", xmlReader.GetAttribute("severity");

        //			"Description", "XCCDF Result was generated via ACAS; description is not available."));

        //			"VulnTitle", "XCCDF Result was generated via ACAS; title is not available."));

        //		while(xmlReader.Read()) {
        //			if(xmlReader.IsStartElement()) {
        //				switch(xmlReader.Name) {
        //					case "xccdf:result": {
        //							xmlReader.Read();
        //							sqliteCommand.Parameters.Add(new SQLiteParameter(
        //								"Status", ConvertXccdfResultToStatus(xmlReader.Value)));
        //							break;
        //						}
        //					case "xccdf:ident": {
        //							if(xmlReader.GetAttribute("system").Equals(@"http://iase.disa.mil/cci")) {
        //								xmlReader.Read();
        //								string cciRef = xmlReader.Value;
        //								if(!string.IsNullOrWhiteSpace(cciRef)) {
        //									foreach(CciToNist cciToNist in MainWindowViewModel.cciToNistList.Where(x => x.CciNumber.Equals(cciRef))) {
        //										if(!sqliteCommand.Parameters.Contains("NistControl")) {
        //											if(RevisionThreeSelected && cciToNist.Revision.Contains("Rev. 3")) { sqliteCommand.Parameters.Add(new SQLiteParameter("NistControl", cciToNist.NistControl)); }
        //											if(RevisionFourSelected && cciToNist.Revision.Contains("Rev. 4")) { sqliteCommand.Parameters.Add(new SQLiteParameter("NistControl", cciToNist.NistControl)); }
        //											if(AppendixASelected && cciToNist.Revision.Contains("53A")) { sqliteCommand.Parameters.Add(new SQLiteParameter("NistControl", cciToNist.NistControl)); }
        //										} else {
        //											if(RevisionThreeSelected && cciToNist.Revision.Contains("Rev. 3") &&
        //												!sqliteCommand.Parameters["NistControl"].Value.ToString().Contains(cciToNist.NistControl)) {
        //												sqliteCommand.Parameters["NistControl"].Value =
        //												  sqliteCommand.Parameters["NistControl"].Value + Environment.NewLine + cciToNist.NistControl;
        //											}
        //											if(RevisionFourSelected && cciToNist.Revision.Contains("Rev. 4") &&
        //												!sqliteCommand.Parameters["NistControl"].Value.ToString().Contains(cciToNist.NistControl)) {
        //												sqliteCommand.Parameters["NistControl"].Value =
        //												  sqliteCommand.Parameters["NistControl"].Value + Environment.NewLine + cciToNist.NistControl;
        //											}
        //											if(AppendixASelected && cciToNist.Revision.Contains("53A") &&
        //												!sqliteCommand.Parameters["NistControl"].Value.ToString().Contains(cciToNist.NistControl)) {
        //												sqliteCommand.Parameters["NistControl"].Value =
        //												  sqliteCommand.Parameters["NistControl"].Value + Environment.NewLine + cciToNist.NistControl;
        //											}
        //										}
        //									}
        //									sqliteCommand.Parameters.Add(new SQLiteParameter("CciNumber", cciRef));
        //								}
        //							}
        //							break;
        //						}
        //					default: { break; }
        //				}
        //			} else if(xmlReader.NodeType == XmlNodeType.EndElement && xmlReader.Name.Equals("xccdf:rule-result")) { return; }
        //		}
        //	} catch(Exception exception) {
        //		Console.WriteLine("Unable to parse XCCDF test results.");
        //		throw exception;
        //	}
        //}


        #endregion

        #region Parse XCCDF FIle From Benchmark File
        private XmlReaderSettings GenerateXmlReaderSettings()
		{
			try
			{
				XmlReaderSettings xmlReaderSettings = new XmlReaderSettings
				{
					IgnoreWhitespace = true,
					IgnoreComments = true,
					ValidationType = ValidationType.Schema
				};
				if (NetworkInterface.GetIsNetworkAvailable())
				{
					xmlReaderSettings.ValidationFlags = XmlSchemaValidationFlags.ProcessInlineSchema;
					xmlReaderSettings.ValidationFlags = XmlSchemaValidationFlags.ProcessSchemaLocation;
				}
				return xmlReaderSettings;
			}
			catch (Exception exception)
			{
				Console.WriteLine("Unable to generate XmlReaderSettings.");
				throw exception;
			}
		}

		private Stream GenerateStreamFromString(string streamString)
		{
			try
			{
				MemoryStream memoryStream = new MemoryStream();
				StreamWriter streamWriter = new StreamWriter(memoryStream);
				streamWriter.Write(streamString);
				streamWriter.Flush();
				memoryStream.Position = 0;
				return memoryStream;
			}
			catch (Exception exception)
			{
				Console.WriteLine("Unable to generate a Stream from the provided string.");
				throw exception;
			}
		}

		private string ConvertSeverityToRawRisk(string severity)
		{
			try
			{
				switch (severity)
				{
					case "high": { return "I"; }
					case "medium": { return "II"; }
					case "low": { return "III"; }
					case "unknown": { return "Unknown"; }
					default: { return "Unknown"; }
				}
			}
			catch (Exception exception)
			{
				Console.WriteLine("Unable to convert severity to raw risk.");
				throw exception;
			}
		}

		private string ConvertSeverityToImpact(string severity)
		{
			try
			{
				switch (severity)
				{
					case "high": { return "High"; }
					case "medium": { return "Medium"; }
					case "low": { return "Low"; }
					case "unknown": { return "Unknown"; }
					default: { return "Unknown"; }
				}
			}
			catch (Exception exception)
			{
				Console.WriteLine("Unable to convert severity to impact.");
				throw exception;
			}
		}

		private string ConvertXccdfResultToStatus(string xccdfResult)
		{
			try
			{
				switch (xccdfResult)
				{
					case "pass":
						return "Completed";
					case "fail":
						return "Ongoing";
					case "error":
						return "Error";
					case "unknown":
						return "Not Reviewed";
					case "notapplicable":
						return "Not Applicable";
					case "notchecked":
						return "Not Reviewed";
					case "notselected":
						return "Not Reviewed";
					case "informational":
						return "Informational";
					case "fixed":
						return "Completed";
					default:
						return "Not Reviewed";
				}
			}
			catch (Exception exception)
			{
				Console.WriteLine("Unable to convert XCCDF test result to status.");
				throw exception;
			}
		}

		private string GetDescriptionAndIacFromSccFile(string description)
		{
			try
			{
				description.Replace("&lt;", "<");
				description.Replace("&gt;", ">");
				description = description.Insert(0, "<root>");
				description = description.Insert(description.Length, "</root>");
				if (description.Contains(@"<link>")) { description = description.Replace(@"<link>", "\"link\""); }
				if (description.Contains(@"<link"))
				{
					int falseStartElementIndex = description.IndexOf("<link");
					int falseEndElementIndex = description.IndexOf(">", falseStartElementIndex);
					StringBuilder stringBuilder = new StringBuilder(description);
					stringBuilder[falseEndElementIndex] = '\"';
					description = stringBuilder.ToString();
					description = description.Replace(@"<link", "\"link");
				}
				XmlReaderSettings xmlReaderSettings = new XmlReaderSettings
				{
					IgnoreWhitespace = true,
					IgnoreComments = true
				};

				using (Stream stream = GenerateStreamFromString(description))
				{
					using (XmlReader descriptionXmlReader = XmlReader.Create(stream, xmlReaderSettings))
					{
						while (descriptionXmlReader.Read())
						{
							if (descriptionXmlReader.IsStartElement() && descriptionXmlReader.Name.Equals("VulnDiscussion"))
							{
								descriptionXmlReader.Read();
								return descriptionXmlReader.Value;
							}
							else if (descriptionXmlReader.IsStartElement() && descriptionXmlReader.Name.Equals("IaControl"))
							{
								descriptionXmlReader.Read();
								if (descriptionXmlReader.NodeType == XmlNodeType.Text)
								{
									return descriptionXmlReader.Value;
								}

							}
						}
					}
				}
				return "Unable to retrieve description and/or IAC.";
			}
			catch (Exception exception)
			{
				Console.WriteLine("Unable to retrieve description and/or IAC.");
				throw exception;
			}
		}
        #endregion
    }
}
