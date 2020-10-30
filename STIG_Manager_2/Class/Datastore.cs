using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Data;

namespace STIG_Manager_2.Class
{
    public class Datastore : BaseClass
    {
        #region Properties
        public Dictionary<string, PSHeaderFunction> HeaderFunctions = new Dictionary<string, PSHeaderFunction>();

        private Checklist _ChecklistObj = new Checklist();
        public Checklist ChecklistObj
        {
            get { return _ChecklistObj; }
            set { if (value != _ChecklistObj) _ChecklistObj = value; OnPropertyChanged(); }
        }
        private Benchmark _BenchmarkObj = new Benchmark();
        public Benchmark BenchmarkObj
        {
            get { return _BenchmarkObj; }
            set { if (value != _BenchmarkObj) _BenchmarkObj = value; OnPropertyChanged(); }
        }
        public static string dir = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        public static string dbfile = dir + "/SMv2/Data/vuln_database.json";
        public static string dbfileBAK = dir + "/SMv2/Data/vuln_database_BAK.json";
        public static string last_checklist = dir + "/SMv2/Data/last_checklist.json";
        public static string last_benchmark = dir + "/SMv2/Data/last_benchmark.json";
        public static string last_headerfunctions = dir + "/SMv2/Data/last_headerfunctions.json";

        public FileInfo DBInfo
        {
            get {
                OnPropertyChanged();
                return new FileInfo(dbfile);
            }
        }
        public FileInfo DBInfoBAK
        {
            get
            {
                OnPropertyChanged();
                return new FileInfo(dbfileBAK); 
            }
        }

        public bool IsTimeToCreateBackup {
            get
            {
                
                if (DBInfo.Exists) {
                    TimeSpan span = DBInfo.LastWriteTime - DBInfoBAK.LastWriteTime;
                    //long dif = DBInfo.Length - dbfileBAK.Length;
                    if(span.Hours >= 1)
                        return true;
                    return false;
                }
                return false;
            }
        }

        #endregion

        #region Vuln_DB
        private Dictionary<string, Vuln> _Vuln_DB = new Dictionary<string, Vuln>();
        public Dictionary<string, Vuln> Vuln_DB
        {
            get { return _Vuln_DB; }
            set { if (value != _Vuln_DB) _Vuln_DB = value; OnPropertyChanged(); }
        }

        // Add to DB
        public bool Add_Vuln(Vuln vuln)
        {
            // Remove this logger when enclave is working properly.
            //Log.Add("Add_Vuln:" + vuln.ID);
            if (Vuln_DB.ContainsKey(vuln.ID) || Vuln_DB == null)
            {
                return false;
            }
            else
            {
                Vuln_DB.Add(vuln.ID, vuln);
                //Log.Add("Add Vuln " + vuln.ID, Log.Level.GEN);
                return true;
            }
        }

        // Update vuln in DB
        public bool Update_Vuln(Vuln vuln)
        {
            // Remove this logger when enclave is working properly.
            Log.Add("Update_Vuln:" + vuln.ID);

            if (Vuln_DB.ContainsKey(vuln.ID))
            {
                Vuln_DB[vuln.ID] = vuln;
                Log.Add("Update Vuln " + vuln.ID, Log.Level.GEN);
                return true;
            }
            else
            {
                return false;
            }
        }
        #endregion

        #region DB File Operations
        // Create DB File
        public bool Create_DB_File(bool UseBackupOfDBFile = false)
        {
            Log.Add("Create_DB_File()", Log.Level.GEN);
            try
            {
                if (DBInfo.Exists)
                {
                    Log.Add("DB File Already Exists.", Log.Level.GEN);
                    return true;
                }
                else
                {
                    Log.Add("DB File Doesn't Exist, Creating Now.", Log.Level.GEN);

                    if (!Directory.Exists(Path.GetDirectoryName(dbfile)))
                    {
                        Directory.CreateDirectory(Path.GetDirectoryName(dbfile));
                    }

                    // Check if user wants to restore from backup
                    if (DBInfoBAK.Exists && !UseBackupOfDBFile)
                        UseBackupOfDBFile = RShow("A backup of the Vulnerability Database Exists.\n\nDo you want to restore from the backup?");

                    if (UseBackupOfDBFile)
                    {
                        Log.Add("Backup DB File Exist, User Opted to Restore.", Log.Level.GEN);
                        // Copies the Backup file to the original dbfile location
                        File.Copy(dbfileBAK, dbfile);
                        return true;
                    }
                    else
                    {
                        Log.Add("DB File Created.", Log.Level.GEN);
                        // Create / Write Empty Dictionary or Current Dictionary to DB File
                        using (FileStream fs = File.OpenWrite(dbfile))
                        {
                            byte[] info = new UTF8Encoding(true).GetBytes(JsonConvert.SerializeObject(Vuln_DB));
                            fs.Write(info, 0, info.Length);
                        }
                        return true;
                    }
                }
            }
            catch (IOException ioe)
            {
                EShow("IOERROR:" + ioe.Message);
                return false;
            }
            catch (Exception e)
            {
                EShow("ERROR:" + e.Message);
                return false;
            }
            
        }
        
        // Copy DB File
        public bool Copy_DB_File(bool Force = false)
        {
            Log.Add("Copy_DB_File()", Log.Level.GEN);
            try
            {
                if (DBInfo.Exists)
                {
                    Log.Add("DB File Exist, Checking if time to backup.", Log.Level.GEN);
                    // Check to see if the backup file is older than a day
                    if (IsTimeToCreateBackup || Force)
                    {
                        Log.Add("Time To Create Backup or Forced.", Log.Level.GEN);
                        // Create a copy of the dbfile 
                        File.Copy(dbfile, dbfileBAK, true);
                        return true;
                    }
                    else
                    {
                        Log.Add("Not Time To Backup.", Log.Level.GEN);
                        // Backup not needed, too recent to create a backup
                        return false;
                    }
                }
                else
                {
                    if (Create_DB_File())
                    {
                        // If Backup exists copy will fail.
                        if (DBInfoBAK.Exists && DBInfoBAK.Length > DBInfo.Length)
                        {
                            Log.Add("Backup DB File Exist, but DB File Did not or Backup is larger than Original. Not Creating Backup!", Log.Level.WARN);
                            // DO NOT OVERWRITE BACKUP IF ORIGINAL DOESN'T EXIST
                            return false;
                        }
                        else
                        {
                            Log.Add("Copying DB File.", Log.Level.GEN);
                            File.Copy(dbfile, dbfileBAK);
                            return true;
                        }
                    }
                    else
                    {
                        Log.Add("Unable to create DB File. No Backup Created.", Log.Level.WARN);
                        return false;
                    }
                }
            }
            catch (IOException ioe)
            {
                EShow("IOERROR:" + ioe.Message);
                return false;
            }
            catch (Exception e)
            {
                EShow("ERROR:" + e.Message);
                return false;
            }
        }

        // Load DB File
        public bool Load_DB_File()
        {
            Log.Add("Load_DB_File()", Log.Level.GEN);

            try
            {
                // Check if DB File Exists
                if (DBInfo.Exists)
                {
                    Log.Add("DB File Exist.", Log.Level.GEN);

                    // Read File Content
                    using (StreamReader sr = File.OpenText(dbfile))
                    {
                        string dbstr = sr.ReadToEnd();

                        // Deserialize DB File
                        Vuln_DB = JsonConvert.DeserializeObject<Dictionary<string, Vuln>>(dbstr);

                        // Initialize if null
                        if (Vuln_DB == null)
                            Vuln_DB = new Dictionary<string, Vuln>();
                    }
                    Log.Add("DB File Loaded Successfully.", Log.Level.GEN);

                    Validate_DB();

                    return true;
                }
                else
                {
                    Log.Add("DB File Doesn't Exist, attempting to create.", Log.Level.WARN);

                    // Create and Copy File
                    // Current Vuln_DB is loaded.
                    Copy_DB_File();
                    Log.Add("DB File Load Failure.", Log.Level.GEN);

                    // Add Baseline Scripts to Vulns
                    Validate_DB();

                    return false;
                }
            }
            catch (IOException ioe)
            {
                EShow("IOERROR:" + ioe.Message);
                return false;
            }
            catch (Exception e)
            {
                EShow("ERROR:" + e.Message);
                return false;
            }
        }
        
        // Update DB File
        public bool Update_DB_File()
        {
            Log.Add("Update_DB_File()", Log.Level.GEN);
            try
            {
                if (_Vulns != null)
                {
                    // Update Vuln_DB with Currently Displayed Vulns
                    foreach (object item in _Vulns.SourceCollection.Cast<Vuln>().ToList())
                    {
                        if (item.GetType().Equals(typeof(Vuln)))
                        {
                            if (Vuln_DB.ContainsKey((item as Vuln).ID))
                            {
                                Update_Vuln((item as Vuln));
                            }
                        }
                    }
                }

                // Check if DB File Exists
                if (DBInfo.Exists)
                {
                    Log.Add("DB File Exist, Writing Vuln_DB.", Log.Level.GEN);
                    // Create Copy of DB File if needed.
                    Copy_DB_File();

                    // Create / Overwrite Existing DB File
                    using (FileStream fs = File.Create(dbfile))
                    {
                        // Writes the current dictionary to the DB File
                        byte[] info = new UTF8Encoding(true).GetBytes(JsonConvert.SerializeObject(Vuln_DB));
                        fs.Write(info, 0, info.Length);
                    }
                    Log.Add("DB File Updated Successfully.", Log.Level.GEN);
                    return true;
                }
                else
                {
                    Log.Add("DB File Updated Successfully.", Log.Level.GEN);
                    // Create and Copy File
                    // Current Vuln_DB is loaded.
                    return Copy_DB_File();
                }
            }
            catch (IOException ioe)
            {
                EShow("IOERROR:" + ioe.Message);
                return false;
            }
            catch (Exception e)
            {
                EShow("ERROR:" + e.Message);
                return false;
            }
        }

        private bool Validate_DB()
        {
            Log.Add("Validate_DB()", Log.Level.GEN);

            // If Vuln_DB Empty, Load Scripts
            if (Vuln_DB.Count == 0)
            {
                Log.Add("Vuln_DB Count Equals 0");

                // Check Script File Exists
                string filename = "Data/Windows10STIGManualChecks_v1.2.ps1";
                if (File.Exists(filename))
                {

                    // Parse Script File
                    Dictionary<string, string> dict_scripts = Operations.Parse_Script(filename);

                    foreach (KeyValuePair<string, string> kv in dict_scripts)
                    {
                        // Add Vuln ID and Script to Vuln_DB
                        Vuln vuln = new Vuln();
                        vuln.ID = kv.Key;
                        vuln.Scripts.Add(vuln.Scripts.Count, kv.Value);
                        vuln.Status = Vuln.NotReviewed;
                        Vuln_DB.Add(vuln.ID, vuln);
                    }
                }
                return false;
            }
            else
            {
                return true;
            }
        }
        #endregion

        #region Checklist / Benchmark / HeaderFunction File Operations
        public bool Save_Checklist()
        {
            Log.Add("Save_Checklist()", Log.Level.GEN);

            try
            {
                // Create / Overwrite the last_checklist file
                using (FileStream fs = File.Create(last_checklist))
                {
                    byte[] info = new UTF8Encoding(true).GetBytes(JsonConvert.SerializeObject(ChecklistObj));
                    fs.Write(info, 0, info.Length);
                }

                Log.Add("Checklist Saved Successfully.", Log.Level.GEN);
                return true;
            }
            catch (IOException ioe)
            {
                EShow("IOERROR:" + ioe.Message);
                return false;
            }
            catch (Exception e)
            {
                EShow("ERROR:" + e.Message);
                return false;
            }
        }

        public bool Save_Benchmark()
        {
            Log.Add("Save_Benchmark()", Log.Level.GEN);

            try
            {
                // Create / Overwrite the last_benchmark file
                using (FileStream fs = File.Create(last_benchmark))
                {
                    byte[] info = new UTF8Encoding(true).GetBytes(JsonConvert.SerializeObject(BenchmarkObj));
                    fs.Write(info, 0, info.Length);
                }

                Log.Add("Benchmark Saved Successfully.", Log.Level.GEN);
                return true;
            }
            catch (IOException ioe)
            {
                EShow("IOERROR:" + ioe.Message);
                return false;
            }
            catch (Exception e)
            {
                EShow("ERROR:" + e.Message);
                return false;
            }
        }

        public bool Save_HeaderFunctions()
        {
            Log.Add("Save_HeaderFunctions()", Log.Level.GEN);

            try
            {
                // Create / Overwrite the last_headerfunctions file
                using (FileStream fs = File.Create(last_headerfunctions))
                {
                    byte[] info = new UTF8Encoding(true).GetBytes(JsonConvert.SerializeObject(HeaderFunctions));
                    fs.Write(info, 0, info.Length);
                }

                Log.Add("HeaderFunctions Saved Successfully.", Log.Level.GEN);
                return true;
            }
            catch (IOException ioe)
            {
                EShow("IOERROR:" + ioe.Message);
                return false;
            }
            catch (Exception e)
            {
                EShow("ERROR:" + e.Message);
                return false;
            }
        }

        public bool Restore_Benchmark()
        {
            Log.Add("Restore_Benchmark()", Log.Level.GEN);

            try
            {
                if (File.Exists(last_benchmark)) { 
                    // read the last_benchmark file
                    using (StreamReader sr = File.OpenText(last_benchmark))
                    {
                        string file = sr.ReadToEnd();
                        BenchmarkObj = JsonConvert.DeserializeObject<Benchmark>(file);
                    }

                    Log.Add("Benchmark Restored Successfully.", Log.Level.GEN);
                    return true;
                }
                    else
                {
                    Log.Add("Last Benchmark File Doesn't Exist.", Log.Level.GEN);
                    return false;
                }
            }
            catch (IOException ioe)
            {
                EShow("IOERROR:" + ioe.Message);
                return false;
            }
            catch (Exception e)
            {
                EShow("ERROR:" + e.Message);
                return false;
            }
        }

        public bool Restore_Checklist()
        {
            Log.Add("Restore_Checklist()", Log.Level.GEN);

            try
            {
                if (File.Exists(last_checklist)) { 
                    // read the last_checklist file
                    using (StreamReader sr = File.OpenText(last_checklist))
                    {
                        string file = sr.ReadToEnd();
                        ChecklistObj = JsonConvert.DeserializeObject<Checklist>(file);
                    }

                    Log.Add("Checklist Restored Successfully.", Log.Level.GEN);
                    return true;
                }
                    else
                {
                    Log.Add("Last Checklist File Doesn't Exist.", Log.Level.GEN);
                    return false;
                }
            }
            catch (IOException ioe)
            {
                EShow("IOERROR:" + ioe.Message);
                return false;
            }
            catch (Exception e)
            {
                EShow("ERROR:" + e.Message);
                return false;
            }
        }

        public bool Restore_HeaderFunctions()
        {
            Log.Add("Restore_HeaderFunctions", Log.Level.GEN);

            try
            {
                if (File.Exists(last_headerfunctions))
                {
                    // read the last_headerfunctions file
                    using (StreamReader sr = File.OpenText(last_headerfunctions))
                    {
                        string file = sr.ReadToEnd();
                        if(string.IsNullOrEmpty(file) || file.Length <= 4)
                        {
                            Log.Add("Last HeaderFunctions File is too small.");
                            return false;
                        }
                        HeaderFunctions = JsonConvert.DeserializeObject<Dictionary<string, PSHeaderFunction>>(file);
                    }

                    Log.Add("HeaderFunctions Restored Successfully.", Log.Level.GEN);
                    return true;
                }
                else
                {
                    Log.Add("Last HeaderFunctions File Doesn't Exist.", Log.Level.GEN);
                    return false;
                }
            }
            catch (IOException ioe)
            {
                EShow("IOERROR:" + ioe.Message);
                return false;
            }
            catch (Exception e)
            {
                EShow("ERROR:" + e.Message);
                return false;
            }
        }
        #endregion

        #region HeaderFunction Operations
        
        public bool Add_HeaderFunction(PSHeaderFunction function)
        {
            if (HeaderFunctions.ContainsKey(function.Title))
            {
                return false;
            }
            else
            {
                HeaderFunctions.Add(function.Title, function);
                return true;
            }
        }

        public bool Update_HeaderFunction(PSHeaderFunction function)
        {
            if (HeaderFunctions.ContainsKey(function.Title))
            {
                HeaderFunctions[function.Title] = function;
                return true;
            }
            else
            {
                return false;
            }
        }

        public string Get_HeaderFunctions()
        {
            StringBuilder sb = new StringBuilder();
            foreach (PSHeaderFunction item in HeaderFunctions.Values)
            {
                sb.AppendLine(item.LastFunction);
            }
            return sb.ToString();
        }

        #endregion

        #region Vuln_DB Operations

        private ListCollectionView _Vulns;
        public ICollectionView Vulns
        {
            get
            {
                return _Vulns;
            }
        }

        public bool Merge()
        {
            Log.Add("Merge()");
 
            try
            {
                CompareFileVersions();

                try
                {


                    List<Vuln> disp_list = new List<Vuln>();

                    // Loop through Checklist Vulns and add to Vuln_DB
                    foreach (KeyValuePair<string, Vuln> kv in ChecklistObj.Vulns)
                    {
                        // Remove this logger when enclave is working properly.
                        //Log.Add("1st Foreach:" + kv.Key);

                        if (Vuln_DB.ContainsKey(kv.Key))
                        {

                            // Keeps the FindingDetails
                            // This line needs to come before the Status otherwise FindingDetails will 
                            // Try and change the status depending on the content in findingdetails.
                            kv.Value.FindingDetails = Vuln_DB[kv.Key].FindingDetails;
                            // Keeps the scripts, ismanualonly, and comments
                            kv.Value.Status = Vuln_DB[kv.Key].Status;
                            

                            kv.Value.Scripts = Vuln_DB[kv.Key].Scripts;
                            kv.Value.IsManualOnly = Vuln_DB[kv.Key].IsManualOnly;
                            kv.Value.Comments = Vuln_DB[kv.Key].Comments;

                            if (kv.Value.Scripts.Count > 1)
                            {
                                // Remove this logger when enclave is working properly.
                                Log.Add("If scripts.count>1:" + kv.Key);
                                kv.Value.Current_Version = kv.Value.Scripts.Count - 1;
                            }
                            else
                            {
                                // Remove this logger when enclave is working properly.
                                Log.Add("If scripts.count<=1:" + kv.Key);
                            }

                            // Updates the current value in the VUln_DB
                            Update_Vuln(kv.Value);
                        }
                        else
                        {
                            // Adds the new value to the Vuln_DB
                            Add_Vuln(kv.Value);
                        }
                    }

                    // Loop through Vuln_DB hide the benchmarked vulns
                    foreach (KeyValuePair<string, Vuln> kv in Vuln_DB)
                    {
                        // Remove this logger when enclave is working properly.
                        //Log.Add("2nd Foreach:" + kv.Key);

                        // Hides Vulns not in Checklist Object
                        if (!ChecklistObj.Vulns.ContainsKey(kv.Key))
                            kv.Value.IsHidden = true;
                        else
                            kv.Value.IsHidden = false;

                        // Hides Vulns that are in Benchmark object
                        if (BenchmarkObj.SelectedVulns.ContainsKey(kv.Key))
                            kv.Value.IsBenchmark = true;
                        else
                            kv.Value.IsBenchmark = false;

                        // Try to parse registry / powershell from checkcontent
                        if (string.IsNullOrEmpty(kv.Value.Last_Script))
                        {
                            // Remove this logger when enclave is working properly.
                            Log.Add("Last_script empty:" + kv.Key);
                            string ps = Operations.Try_Parse_PowerShell(kv.Value.CheckContent);
                            string reg = Operations.Try_Parse_Registry(kv.Value.CheckContent);
                            kv.Value.Last_Script = ps != "" ? ps : reg;
                        }

                        // Create a display list to make changes to
                        if (!kv.Value.IsHidden)
                            disp_list.Add(kv.Value);


                    }


                    // Remove this logger when enclave is working properly.
                    Log.Add("Disp_list OrderBy");
                    // Sort the list before creating the display object
                    disp_list = disp_list.OrderBy(o => o.ID).ToList();


                    // Remove this logger when enclave is working properly.
                    Log.Add("Disp_list ListCollectionView");
                    _Vulns = new ListCollectionView(disp_list);
                    OnPropertyChanged("Vulns");
                    Refresh();
                    Log.Add("Merge() Successful");
                }
                catch (Exception e)
                {
                    Log.Add(e.Message, Log.Level.ERR);
                    string errstr = "";
                    foreach (var item in e.Data)
                    {
                        errstr += item.ToString();
                    }
                    Log.Add(errstr, Log.Level.ERR);
                }
                return true;
            }
            catch (Exception e)
            {
                EShow("MERGE ERROR: " + e.Message);
                Log.Add("ERROR DATA: " + e.Data.ToString(), Log.Level.ERR);
                return false;
            }
        }

        public bool CompareFileVersions()
        {
            try
            {
                Log.Add("CompareFileVersions()");

                if (ChecklistObj != null &&
                    ChecklistObj.info != null &&
                    !string.IsNullOrWhiteSpace(ChecklistObj.info.Short_Title) &&
                    !string.IsNullOrWhiteSpace(ChecklistObj.info.Date_String) &&
                    BenchmarkObj != null &&
                    !string.IsNullOrWhiteSpace(BenchmarkObj.Short_Title) &&
                    !string.IsNullOrWhiteSpace(BenchmarkObj.Date_String))
                {
                    // Checks the Checklist File Title/Date to the
                    // Benchmark File Title/Date
                    string ctitle = ChecklistObj.info.Short_Title;
                    string btitle = BenchmarkObj.Short_Title;

                    Log.Add("Benchmark Obj date: " + BenchmarkObj.ReleaseDate.ToString());
                    Log.Add("Checklist Obj date: " + ChecklistObj.info.Date_String);
                    bool date_same = BenchmarkObj.ReleaseDate.Equals(DateTime.Parse(ChecklistObj.info.Date_String));
                    if (ctitle != null && !ctitle.Equals(btitle))
                        Show("The checklist file title doesn't match the benchmark file title, please double check that you chose the correct files.");
                    else if (!date_same)
                        Show("The checklist file and the benchmark file have different dates, please double check that you chose the correct files.");
                    else
                        return true;
                }
                return false;
            }catch(Exception e)
            {
                Log.Add("CompareFileVersion Exception: " + e.Message);
                return false;
            }
        }

        public void Refresh(bool showAll = false)
        {
            if (!showAll)
                Vulns.Filter = GetFilter();
            else
                Vulns.Filter = RemoveFilter();
            OnPropertyChanged("Vulns");
        }

        public void Search(string text)
        {
            Vulns.Filter = SearchFilter(text);
            OnPropertyChanged("Vulns");
        }

        public Predicate<object> GetFilter()
        {
            //if(ChecklistObj.Loaded)
                return new Predicate<object>(o => ((Vuln)o).IsHidden == false && ((Vuln)o).IsBenchmark == false || (o as Vuln).Status == Vuln.Open);
            // Display all vulns if checklist not loaded
            //return new Predicate<object>(o => ((Vuln)o).IsBenchmark == false);
        }

        public Predicate<object> RemoveFilter()
        {

            return new Predicate<object>(o => ((Vuln)o) != null);
        }

        public Predicate<object> SearchFilter(string text)
        {
            text = text.ToLower();
            return new Predicate<object>(o => 
            ((Vuln)o).ID.ToLower().Contains(text) || 
            ((Vuln)o).Status.ToLower().Contains(text) || 
            ((Vuln)o).Last_Script.ToLower().Contains(text) ||
            ((Vuln)o).RuleTitle.ToLower().Contains(text));
        }
        #endregion
    }
}
