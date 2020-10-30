using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;

namespace STIG_Manager_2.Class
{
    public class Computer : BaseClass
    {

        private bool _IsSelected = false;
        public bool IsSelected
        {
            get { return _IsSelected; }
            set { if (value != _IsSelected) _IsSelected = value; OnPropertyChanged(); }
        }

        private string _Name = "ComputerName";
        public string Name
        {
            get { return _Name; }
            set { if (value != _Name) _Name = value; OnPropertyChanged(); }
        }

        private bool _IsRunning = false;
        public bool IsRunning
        {
            get { return _IsRunning; }
            set { if (value != _IsRunning) _IsRunning = value; OnPropertyChanged(); }
        }


        private int _TotalScripts = 0;
        public int TotalScripts
        {
            get { return _TotalScripts; }
            set { if (value != _TotalScripts) _TotalScripts = value; OnPropertyChanged(); }
        }

        public double Offset {
            get
            {
                return 100.0 / TotalScripts;
            }
        }

        private int _Completed = 0;
        public int Completed
        {
            get { return _Completed; }
            set { if (value != _Completed) _Completed = value; OnPropertyChanged(); }
        }


        private string _FinishText = "Not Run";
        public string FinishText
        {
            get { return _FinishText; }
            set { if (value != _FinishText) _FinishText = value; OnPropertyChanged(); }
        }

        private bool _Online;
        public bool Online
        {
            get { return _Online; }
            set { if (value != _Online) _Online = value; OnPropertyChanged(); }
        }

        public BackgroundWorker bgw = new BackgroundWorker()
        {
            WorkerReportsProgress = true,
            WorkerSupportsCancellation = true
        };
        
        private Dictionary<string, string> _Run_Results;
        public Dictionary<string, string> Run_Results
        {
            get { return _Run_Results; }
            set { if (value != _Run_Results) _Run_Results = value; OnPropertyChanged(); }
        }
        public static string error = "Errors(check logs)";
        public static string cancel = "Cancelled";
        public void Run(Datastore ds)
        {
            Completed = 0;

            bgw.DoWork += (_, args) =>
            {
                try
                {
                    Dictionary<string, string> vulns = new Dictionary<string, string>();
                    // Add script to vulns dicitonary
                    foreach (var item in ds.Vulns.SourceCollection)
                    {
                        if (item.GetType().Equals(typeof(Vuln)) &&
                            !(item as Vuln).IsManualOnly &&
                            !(item as Vuln).IsHidden &&
                            !(item as Vuln).IsBenchmark)
                        {
                            //(item as Vuln).FindingDetails = Operations.Add_User_Initials(Run((item as Vuln).Last_Script, ds));
                            vulns.Add((item as Vuln).ID, (item as Vuln).Last_Script);
                        }
                    }

                    string functions = ds.Get_HeaderFunctions();

                    Dictionary<string, string> vulns_results = new Dictionary<string, string>();
                    TotalScripts = vulns.Count;
                    int count = 0;
                    foreach (KeyValuePair<string, string> item in vulns)
                    {
                        if (bgw.CancellationPending)
                        {
                            args.Cancel = true;
                            return;
                        }
                        string value = PSOperations.Run_Remote(Name, item.Value, functions);
                        if (value == null)
                        {
                            args.Result = error;
                            return;
                        }
                        count++;
                        vulns_results.Add(item.Key, value);
                        bgw.ReportProgress((int)(count * Offset));
                    }
                    if (count > 0)
                        args.Result = vulns_results;
                    else
                        args.Result = error;
                }
                catch (Exception e)
                {
                    EShow("ASYNC-ERROR: " + e.Message);
                    args.Result = error;
                }
                
            };
            bgw.ProgressChanged += (_, args) =>
            {
                Completed = args.ProgressPercentage;
                IsRunning = true;
                FinishText = "Running..";
            };
            bgw.RunWorkerCompleted += (_, args) =>
            {
                if (args.Error != null)
                {
                    FinishText = error;
                    IsSelected = false;
                }
                else if (args.Cancelled)
                {
                    FinishText = cancel;
                }
                else
                {
                    if (args.Result.GetType() == typeof(string))
                    {
                        FinishText = args.Result as string;
                        IsSelected = false;
                        Show("There was an error while trying to run the powershell.\n\rRestart the application as an Admin.");
                    }
                    else
                    {
                        Completed = 100;
                        FinishText = "Completed";
                        if (args.Result.GetType() == typeof(Dictionary<string, string>))
                        {
                            Run_Results = args.Result as Dictionary<string, string>;
                            Create_Checklist_File(ds);
                        }
                    }
                }

                IsRunning = false;
                
            };

            bgw.RunWorkerAsync();
        }

        public bool Create_Checklist_File(Datastore ds)
        {
            Log.Add("Create_Checklist_File()");

            Dictionary<string, Vuln> TempVulns = new Dictionary<string, Vuln>(ds.ChecklistObj.Vulns);

            string filename = Checklist.Generate_Filename(ds.ChecklistObj.info.CustomName, Name);
            if (ds.ChecklistObj.Copy_Checklist(filename, false))
            {
                int count = 0;
                foreach (KeyValuePair<string, string> item in Run_Results)
                {
                    if (TempVulns.ContainsKey(item.Key) && item.Value != null)
                    {
                        TempVulns[item.Key].FindingDetails = Operations.Add_User_Initials(item.Value);
                        count++;
                    }
                        
                }
                if (count > 0)
                {
                    return Checklist.Update_Checklist(filename, TempVulns, false);
                }
                else
                {
                    EShow($"There was an error in running these scripts remotely.\n\rName: {Name}");
                    return false;
                }
            }
            else
            {
                if (File.Exists(filename))
                {
                    Show("File Already Exists. " + Name);
                    return false;
                }
                return false;
            }
            
        }


        private bool _IsChecking;
        public bool IsChecking
        {
            get { return _IsChecking; }
            set { if (value != _IsChecking) _IsChecking = value; OnPropertyChanged(); }
        }
        public async void IsOnline()
        {
            try
            {
                IsChecking = true;
                bool del(){
                    if (PSOperations.TestConnection(Name).ToLower().Contains("true"))
                    {
                        Online = true;
                        return true;
                    }
                    else
                    {
                        Online = false;
                        return false;
                    }
                };

                await Task.Run(del);
                IsChecking = false;
            }
            catch (Exception)
            {
                FinishText = error;
                IsChecking = false;
            }
            
        }
    }
}
