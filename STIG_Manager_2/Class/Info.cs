using System;

namespace STIG_Manager_2.Class
{
    public class Info : BaseClass
    {

        private string _Version = "";
        public string Version
        {
            get { return _Version; }
            set { if (value != _Version) _Version = value; OnPropertyChanged(); }
        }

        private string _Classification = "";
        public string Classification
        {
            get { return _Classification; }
            set { if (value != _Classification) _Classification = value; OnPropertyChanged(); }
        }

        private string _CustomName = "";
        public string CustomName
        {
            get { return _CustomName; }
            set { if (value != _CustomName) _CustomName = value; OnPropertyChanged(); }
        }

        private string _StigID = "";
        public string StigID
        {
            get { return _StigID; }
            set { if (value != _StigID) _StigID = value; OnPropertyChanged(); }
        }

        private string _Description = "";
        public string Description
        {
            get { return _Description; }
            set { if (value != _Description) _Description = value; OnPropertyChanged(); }
        }


        private string _FileName = "";
        public string FileName
        {
            get { return _FileName; }
            set { if (value != _FileName) _FileName = value; OnPropertyChanged(); }
        }

        private string _ReleaseInfo = "";
        public string ReleaseInfo
        {
            get { return _ReleaseInfo; }
            set { 
                if (value != _ReleaseInfo)
                    _ReleaseInfo = value;
                if (value == "")
                    return;
                Date_String = value.Split(new char[] { '(' }, StringSplitOptions.RemoveEmptyEntries)[1].Trim(')').Trim(' ');
                OnPropertyChanged(); }
        }

        private string _Date_String = "";
        public string Date_String
        {
            get { return _Date_String; }
            set { if (value != _Date_String) _Date_String = value; OnPropertyChanged(); }
        }

        private string _Title = "";
        public string Title
        {
            get { return _Title; }
            set { 
                if (value != _Title) 
                    _Title = value;
                Short_Title = value.Replace("Security Technical Implementation Guide", "").Trim(' ');
                OnPropertyChanged(); }
        }

        private string _Short_Title = "";
        public string Short_Title
        {
            get
            {
                if (_Short_Title == null)
                    return "";
                return _Short_Title; }
            set { if (value != _Short_Title) _Short_Title = value; OnPropertyChanged(); }
        }

        private string _UUID = "";
        public string UUID
        {
            get { return _UUID; }
            set { if (value != _UUID) _UUID = value; OnPropertyChanged(); }
        }

        private string _Notice = "";
        public string Notice
        {
            get { return _Notice; }
            set { if (value != _Notice) _Notice = value; OnPropertyChanged(); }
        }

        private string _Source = "";
        public string Source
        {
            get { return _Source; }
            set { if (value != _Source) _Source = value; OnPropertyChanged(); }
        }
    }
}
