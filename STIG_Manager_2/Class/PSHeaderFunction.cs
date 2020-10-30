using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace STIG_Manager_2.Class
{
    public class PSHeaderFunction : BaseClass
    {
        // Stores the Modification Number
        public int Version
        {
            get {
                if (Functions == null || Functions.Count == 0)
                    return 0;
                return Functions.Count - 1;
            }
        }

        // Describes the Function Name
        private string _Title = "";
        public string Title
        {
            get { return _Title; }
            set { if (value != _Title) _Title = value; OnPropertyChanged(); }
        }

        public string LastFunction
        {
            get {
                if (Functions.Count == 0)
                    return "";
                return Functions[Version]; 
            }
            set {
                if (value != "" && (Functions.Count == 0 || !value.Equals(Functions[Version])))
                    Functions.Add(Functions.Count, value);
                OnPropertyChanged();
                OnPropertyChanged("Version");
            }
        }

        // Holds all the Function Versions
        private Dictionary<int, string> _Functions = new Dictionary<int, string>();
        public Dictionary<int, string> Functions
        {
            get { return _Functions; }
            set { if (value != _Functions) _Functions = value; OnPropertyChanged(); }
        }

        public void Add_Function(string func)
        {
            Functions.Add(Functions.Count, func);
            OnPropertyChanged("Functions");
            OnPropertyChanged("Version");
        }
    }
}
