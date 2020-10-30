using System.Collections.Generic;
using System.Linq;

namespace STIG_Manager_2.Class
{
    public class Vuln : BaseClass
    {
        #region Properties
        #region Standard Properties
        private string _ID = "";
        public string ID
        {
            get { return _ID; }
            set { if (value != _ID) _ID = value; OnPropertyChanged(); }
        }
      
        private string _Status = "";
        public string Status
        {
            get { return _Status; }
            set { 
                if (value != _Status) 
                    _Status = value; 
                OnPropertyChanged(); 
                OnPropertyChanged("DispStatus"); 
            }
        }
        
        public const string NotReviewed = "Not Reviewed";
        public const string Open = "Open";
        public const string NotAFinding = "Not A Finding";
        public const string NotApplicable = "Not Applicable";
        public const string NA = "N/A";
        public static string[] Statuses = new string[] { NotReviewed, Open, NotAFinding, NotApplicable };

        public string DispStatus
        {
            get
            {
                switch (Status)
                {
                    case ("Not_Reviewed"):
                        return NotReviewed;
                    case ("Open"):
                        return Open;
                    case ("NotAFinding"):
                        return NotAFinding;
                    case ("NotApplicable"):
                        return NotApplicable;
                    default:
                        return NotReviewed;
                }
            }
            set
            {
                switch (value)
                {
                    case (NotReviewed):
                        Status = "Not_Reviewed";
                        break;
                    case (Open):
                        Status = "Open";
                        break;
                    case (NotAFinding):
                        Status = "NotAFinding";
                        break;
                    case (NotApplicable):
                        Status = "NotApplicable";
                        break;
                    default:
                        Status = "Not_Reviewed";
                        break;
                }
                OnPropertyChanged();
            }
        }
        
        private string _Severity = "";
        public string Severity
        {
            get { return _Severity; }
            set { if (value != _Severity) _Severity = value; OnPropertyChanged(); }
        }
        public const string CATIII = "CAT III";
        public const string CATII = "CAT II";
        public const string CATI = "CAT I";

        private string _Discussion = "";
        public string Discussion
        {
            get { return _Discussion; }
            set { if (value != _Discussion) _Discussion = value; OnPropertyChanged(); }
        }
        private string _FixText = "";
        public string FixText
        {
            get { return _FixText; }
            set { if (value != _FixText) _FixText = value; OnPropertyChanged(); }
        }
        private string _CheckContent = "";
        public string CheckContent
        {
            get { return _CheckContent; }
            set { if (value != _CheckContent) _CheckContent = value; OnPropertyChanged(); }
        }
        private string _SeverityJustification = "";
        public string SeverityJustification
        {
            get { return _SeverityJustification; }
            set { if (value != _SeverityJustification) _SeverityJustification = value; OnPropertyChanged(); }
        }
        private string _Comments = "";
        public string Comments
        {
            get { return _Comments; }
            set { if (value != _Comments) _Comments = value; OnPropertyChanged(); }
        }
        private string _FindingDetails = "";
        public string FindingDetails
        {
            get { return _FindingDetails; }
            set {
                if (value != _FindingDetails && value != null)
                {
                    _FindingDetails = value;
                    Check_Results();
                    OnPropertyChanged();
                }
            }
        }

        private string _RuleID = "";
        public string RuleID
        {
            get { return _RuleID; }
            set { if (value != _RuleID) _RuleID = value; OnPropertyChanged(); }
        }
        private string _RuleTitle = "";
        public string RuleTitle
        {
            get { return _RuleTitle; }
            set { if (value != _RuleTitle) _RuleTitle = value; OnPropertyChanged(); }
        }

        private string _RuleVersion = "";
        public string RuleVersion
        {
            get { return _RuleVersion; }
            set { if (value != _RuleVersion) _RuleVersion = value; OnPropertyChanged(); }
        }

        private string _GroupTitle = "";
        public string GroupTitle
        {
            get { return _GroupTitle; }
            set { if (value != _GroupTitle) _GroupTitle = value; OnPropertyChanged(); }
        }

        #endregion

        #region Extended Properties

        private Dictionary<int, string> _Scripts = new Dictionary<int, string>();
        public Dictionary<int, string> Scripts
        {
            get { return _Scripts; }
            set { if (value != _Scripts) 
                    _Scripts = value; 
                OnPropertyChanged();
                OnPropertyChanged("Last_Script");
                OnPropertyChanged("Versions");
                OnPropertyChanged("Current_Version");
                OnPropertyChanged("Current_Script");
            }
        }
        public void Add_Script(string val)
        {
            if (_Scripts.Count == 0 ||_Scripts[_Scripts.Count - 1] != val)
            {
                _Scripts.Add(_Scripts.Count, val);
                Current_Version = _Scripts.Count - 1;
            }
            OnPropertyChanged("Scripts");
            OnPropertyChanged("Versions");
            OnPropertyChanged("Current_Script");
        }
        
        public string Last_Script
        {
            get
            {
                if(Scripts.Count > 0)
                    return Scripts[Scripts.Count - 1];
                return "";
            }
            set
            {
                Add_Script(value);
                OnPropertyChanged();
            }
        }
        public int[] Versions
        {
            get { return Scripts.Keys.Cast<int>().ToArray(); }
        }

        private int _Current_Version = 0;
        public int Current_Version
        {
            get {
                return _Current_Version;
            }
            set { 
                if (value != _Current_Version) 
                    _Current_Version = value; 
                OnPropertyChanged();
                OnPropertyChanged("Current_Script");
            }
        }
        private string _Current_Script = "";
        public string Current_Script
        {
            get {
                if (Scripts.Count != 0)
                    return Scripts[_Current_Version];
                return _Current_Script; }
            set { 
                if (value != _Current_Script)
                    Add_Script(value);
                OnPropertyChanged();
                OnPropertyChanged("IsContainRegistryValue");
            }
        }

        // Is True when Vuln in DB & CKL & Benchmark
        private bool _IsBenchmark = false;
        public bool IsBenchmark
        {
            get { return _IsBenchmark; }
            set { if (value != _IsBenchmark) _IsBenchmark = value; OnPropertyChanged(); }
        }

        // Is True when Vuln in DB & Not in CKL
        private bool _IsHidden = false;
        public bool IsHidden
        {
            get { return _IsHidden; }
            set { if (value != _IsHidden) _IsHidden = value; OnPropertyChanged(); }
        }

        // Is Set by User
        private bool _IsManualOnly = false;
        public bool IsManualOnly
        {
            get { return _IsManualOnly; }
            set { if (value != _IsManualOnly) _IsManualOnly = value; OnPropertyChanged(); }
        }

        public const string PassWithCondition = "PASS WITH CONDITION";
        public const string Pass = "PASS";
        public const string Fail = "FAIL";
        public const string Error = "ERROR";

        // Is True when Vuln.FindingDetails contains the string "Pass With Condition"
        public bool IsPassWithCondition
        {
            get {
                if (FindingDetails.Contains(PassWithCondition))
                    return true;
                return false;
            }
        }
        public bool IsNotApplicable
        {
            get
            {
                if (FindingDetails.Contains(NA) || FindingDetails.Contains(NotApplicable.ToUpper()))
                    return true;
                return false;
            }
        }
        public bool IsFail
        {
            get
            {
                if (FindingDetails.Contains(Fail) ||
                FindingDetails.Contains(Error))
                    return true;
                return false;
            }
        }
        public bool IsPass
        {
            get
            {
                if (FindingDetails.Contains(Pass))
                    return true;
                return false;
            }
        }

        public bool IsContainRegistryValue
        {
            get {
                if (Current_Script.Contains("[[") && Current_Script.Contains("]]"))
                    return true;
                return false; }
        }

        private int _Completed;
        public int Completed
        {
            get { return _Completed; }
            set { if (value != _Completed) _Completed = value; OnPropertyChanged(); }
        }

        #endregion
        #endregion

        public bool Clean_Up_Scripts()
        {
            try
            {
                Dictionary<int, string> tempDict = new Dictionary<int, string>();

                tempDict.Add(0, Last_Script);
                Current_Version = 0;

                //foreach (var item in Scripts)
                //{
                //    // If dictionary doesn't contain value, add it
                //    if (!tempDict.ContainsValue(item.Value))
                //    {
                //        tempDict.Add(tempDict.Count, item.Value);
                //    }
                //    else
                //    {
                //        // If the dictionary contains the value then determine 
                //        // if it is the latest version, if so add it
                //        for (int i = 0; i < Scripts.Count; i++)
                //        {

                //        }
                //    }
                //}
                Scripts = tempDict;
                return true;
            }
            catch (System.Exception e)
            {
                Log.Add("Error while cleaning up scripts. " + e.Message, Log.Level.ERR);
                return false;
            }
        }

        public void Check_Results()
        {
            // If FindingDetails doesn't have any current status, return with default values
            if (string.IsNullOrWhiteSpace(FindingDetails))
                return;

            // Parse Findings to determine Status
            if (IsPassWithCondition)
            {
                // Set Status to Not a finding
                DispStatus = NotAFinding;
                OnPropertyChanged("IsPassWithCondition");
            }
            else if (IsFail)
            {
                DispStatus = Open;
            }
            else if (IsPass)
            {
                DispStatus = NotAFinding;
            }
            else if (IsNotApplicable)
            {
                DispStatus = NotApplicable;
            }
            else
                DispStatus = NotReviewed;
        }
    }
}
