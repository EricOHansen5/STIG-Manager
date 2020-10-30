using Microsoft.Win32;
using Newtonsoft.Json;
using STIG_Manager_2.Class;
using STIG_Manager_2.View;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;

namespace STIG_Manager_2
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window, INotifyPropertyChanged
    {
        #region Notify Property Changed Members
        /// <summary>
        /// This region is just a notification from the C# classes to the xaml class to update variable information
        /// </summary>
        public event PropertyChangedEventHandler PropertyChanged;
        private void OnPropertyChanged([CallerMemberName] string name = "")
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
        }
        #endregion

        #region ScaleValue Depdency Property
        // This Region is used to scale/zoom in the application as user changes the size up or down.
        // The only method that you should need to edit is the CalculateScale
        // Change the denominator to change the scale value for height or width.

        public static readonly DependencyProperty ScaleValueProperty
            = DependencyProperty.Register("ScaleValue", typeof(double),
                typeof(MainWindow), new UIPropertyMetadata(1.0,
                    new PropertyChangedCallback(OnScaleValueChanged),
                    new CoerceValueCallback(OnCoerceScaleValue)));
        private static object OnCoerceScaleValue(DependencyObject o, object value)
        {
            MainWindow STIG_Manager = o as MainWindow;
            if (STIG_Manager != null)
                return STIG_Manager.OnCoerceScaleValue((double)value);
            else
                return value;
        }
        private static void OnScaleValueChanged(DependencyObject o, DependencyPropertyChangedEventArgs e)
        {
            MainWindow STIG_Manager = o as MainWindow;
            if (STIG_Manager != null)
                STIG_Manager.OnScaleValueChanged((double)e.OldValue, (double)e.NewValue);
        }
        protected virtual double OnCoerceScaleValue(double value)
        {
            if (double.IsNaN(value))
                return 1.0f;

            value = Math.Max(0.1, value);
            return value;
        }
        protected virtual void OnScaleValueChanged(double oldValue, double newValue)
        {
        }
        public double ScaleValue
        {
            get
            {
                return (double)GetValue(ScaleValueProperty);
            }
            set
            {
                SetValue(ScaleValueProperty, value);
            }
        }
        private void MainGrid_SizeChanged(object sender, EventArgs e)
        {
            CalculateScale();
        }

        // Change the yScale/xScale if you are having issues with objects not appearing within the window
        private void CalculateScale()
        {
            double yScale = ActualHeight / 669; //change the denominator up will increase the windows size vertically
            double xScale = ActualWidth / 1192; //change the denominator up will increase the windows size horizontally
            double value = Math.Min(xScale, yScale);
            //value = 1;
            ScaleValue = (double)OnCoerceScaleValue(STIG_Manager, value);
        }
        #endregion

        #region Properties
        // This property is used to help generate powershell scripts
        // It is filled with all the commandlets that PowerShell has as of May 2020
        // To update commandlets open the "Cmdlets.txt" in the data folder and add/remove commandlets as needed.
        public string[] AutoCompleteList;

        /// <summary>
        /// Datastore is the core of this application, it does the reading/writing of the database files
        /// For more information on this Class visit the Datastore class summary.
        /// </summary>
        public Datastore datastore = new Datastore();

        // This is just a pointer to the datastore.ChecklistObj for easier access.
        public Checklist checklist
        {
            get { return datastore.ChecklistObj; }
        }
        
        // This is just a pointer to the datastore.BenchmarkObj for easier access.
        public Benchmark benchmark
        {
            get { return datastore.BenchmarkObj; }
        }
        #endregion

        // NOTE if Automation.dll is having access denied errors:
        // 1. Disable HBSS
        // 2. Install using Nuget Package Manager CLI:
        //    Install-Package System.Management.Automation.dll -Version 10.0.10586
        //    or Nuget package manager and install "Powershell 5.1.reference assemblies"

        /// <summary>
        /// The MainWindow is the initialization method for the GUI
        /// It creates the first log entry, initializeses the datastore class
        /// Fills the AutoCompleteList with commandlets
        /// Initializes all the GUI components
        /// Sets the DataContext of those components to this class.
        /// Sets the Title of the GUI
        /// Sets the Datagrid datacontext to the datastore property
        /// Sets the itemsource for the status combobox
        /// Sets all the checklist object datacontext 
        /// Sets all the benchmark object datacontext
        /// </summary>
        public MainWindow()
        {
            Log.Add("MainWindow()", Log.Level.GEN);
            Log.Clear_Log();
            Thread.Sleep(500);

            InitializeDatastore();

            AutoCompleteList = Operations.Parse_AutoComplete_Cmdlets();
            InitializeComponent();
            DataContext = this;
            this.Title += " (v" + Assembly.GetExecutingAssembly().GetName().Version.ToString() + ")";

            // Everythign below this line sets the binding for each of these GUI objects.
            dataGrid.DataContext = datastore;
            cbStatus.ItemsSource = Vuln.Statuses;

            // Set DataContext for Checklist Object
            txbCName.DataContext = checklist.info;
            txbCVersion.DataContext = checklist.info;
            txbCRelease.DataContext = checklist.info;

            // Set DataContext for Benchmark Object
            txbBName.DataContext = benchmark;
            txbBVersion.DataContext = benchmark;
            txbBRelease.DataContext = benchmark;
        }

        /// <summary>
        /// InitializeDatastore method tries to load the previous existing database file
        /// For more information on these Load/Restore methods refer to the Datastore class
        /// </summary>
        public void InitializeDatastore()
        {
            Log.Add("InitializeDatastore", Log.Level.GEN);

            // Load DB / Scripts
            if (!datastore.Load_DB_File())
            {
                // Load Failure
                // Create Baseline DB File
                datastore.Update_DB_File();

            }

            // Restore HeaderFunctions if they exist
            if (!datastore.Restore_HeaderFunctions())
            {
                // Create Baseline HeaderFunctions File
                datastore.HeaderFunctions = Operations.Parse_Header_Functions("Data/Windows10STIGManualChecks_v1.2.ps1");
                datastore.Save_HeaderFunctions();
            }

            // Load Checklist
            if (!datastore.Restore_Checklist())
            {
                // Restore Failure
                // Create Checklist File
                datastore.Save_Checklist();
            }

            // Load Benchmark
            if (!datastore.Restore_Benchmark())
            {
                // Restore Failure
                // Create Benchmark File
                datastore.Save_Benchmark();
            }

            // Run First Merge
            datastore.Merge();
        }

        #region AutoComplete
        /// <summary>
        /// AutoComplete region contains the methods specifically refering to the PowerShell commandlets
        /// that are used in the PowerShell Textbox.  When the user starts to type a commandlet, a box will
        /// appear with possible suggestions for autocomplete.  If the user wants the first value in the box 
        /// they can just click on the correct commandlet or use the "Tab" key to insert that commandlet into 
        /// the powershell script.
        /// </summary>
        private async void TextBox_KeyUp(object sender, System.Windows.Input.KeyEventArgs e)
        {
            // TODO:
            //      setup undo (ctrl-z)

            int len = (sender as TextBox).Text.Length;
            await Task.Delay(500);
            if (len != (sender as TextBox).Text.Length)
                return;

            #region Get Query
            bool found = false;
            var border = (stkAutoComplete.Parent as ScrollViewer).Parent as Border;
            
            string sub_str = (sender as TextBox).Text.Substring(0, (sender as TextBox).SelectionStart);
            string end_str = (sender as TextBox).Text.Substring((sender as TextBox).SelectionStart);

            // This splits the substring into an array
            string[] words = sub_str.Split(new char[] { ' ', '\n', '\r', '\t' });
            if (e.Key.Equals(Key.Tab))
                words = sub_str.Split(new char[] { ' ', '\n', '\r', '\t' }, StringSplitOptions.RemoveEmptyEntries);

            //string[] words = (sender as TextBox).Text.Split(new char[] { ' ', '\n', '\r', '\t' }, StringSplitOptions.RemoveEmptyEntries);
            int last = words.Length > 0 ? words.Length - 1 : 0;
            string query = words[last];
            #endregion
            
            // Show / Hide popup if query null
            if (query.Length == 0)
            {
                stkAutoComplete.Children.Clear();
                psPopUp.IsOpen = false;
                //border.Visibility = Visibility.Collapsed;
            }
            else
            {
                psPopUp.IsOpen = true;
                //border.Visibility = Visibility.Visible;
            }

            #region Populate AutoComplete Popup
            // Clear children to populate with cmdlets
            stkAutoComplete.Children.Clear();
            foreach(var obj in AutoCompleteList)
            {
                if (obj.ToLower().StartsWith(query.ToLower()))
                {
                    addItem(obj);
                    found = true;
                }
            }
            #endregion

            if (!found)
            {
                stkAutoComplete.Children.Add(new TextBlock() { Text = "No Results." });
                //border.Visibility = Visibility.Collapsed;
                psPopUp.IsOpen = false;
            }

            if (e.Key.Equals(Key.Tab) && !(stkAutoComplete.Children[0] as TextBlock).Text.Contains("No Results."))
            {
                e.Handled = true;
                int ix = txtPowerShell.SelectionStart;
                string b4 = (sender as TextBox).Text.Substring(0, ix).TrimEnd('\t');
                string add = (stkAutoComplete.Children[0] as TextBlock).Text.Substring(query.Length);
                (sender as TextBox).Text = b4 + add + end_str;
                (sender as TextBox).SelectionStart = ix + (stkAutoComplete.Children[0] as TextBlock).Text.Length - 1;

                stkAutoComplete.Children.Clear();
                //border.Visibility = Visibility.Collapsed;
                psPopUp.IsOpen = false;
            }

            if (e.Key.Equals(Key.Escape))
            {
                stkAutoComplete.Children.Clear();
                //border.Visibility = Visibility.Collapsed;
                psPopUp.IsOpen = false;
            }
        }
        /// <summary>
        /// addItem is a sub method to the TextBox_KeyUp handler.  It takes the information that was handed to
        /// it from the handler and adds the commandlets that match to the given text.
        /// </summary>
        /// <param name="text">Substring of commandlet</param>
        private void addItem(string text)
        {
            TextBlock block = new TextBlock();

            // Add the text
            block.Text = text;

            // A little style...
            block.Margin = new Thickness(2, 3, 2, 3);
            block.Cursor = Cursors.Hand;
            
            // Mouse events
            block.MouseLeftButtonUp += (sender, e) =>
            {
                // Gets substring from start of txtPowerShell to where the cursor is.
                string sub_str = txtPowerShell.Text.Substring(0, txtPowerShell.SelectionStart);
                string end_str = txtPowerShell.Text.Substring(txtPowerShell.SelectionStart);
                // This splits the substring into an array
                string[] words = sub_str.Split(new char[] { ' ', '\n', '\r', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                int last = words.Length > 0 ? words.Length - 1 : 0;
                string query = words[last];
                int ix = txtPowerShell.Text.IndexOf(query);
                txtPowerShell.Text = txtPowerShell.Text.Substring(0, ix) + (sender as TextBlock).Text + end_str;
            };

            block.MouseEnter += (sender, e) =>
            {
                TextBlock b = sender as TextBlock;
                b.Background = Brushes.PeachPuff;
            };

            block.MouseLeave += (sender, e) =>
            {
                TextBlock b = sender as TextBlock;
                b.Background = Brushes.Transparent;
            };

            // Add to the panel
            stkAutoComplete.Children.Add(block);
        }
        #endregion

        // string used to ask user if they want to store the findings.
        const string Store_Findings = "\n\rDo you want to store these findings?";

        #region PowerShell Script Operations
        /// <summary>
        /// Click_Run is the handler for the Test Script button.
        /// This handler changes the visibility of the progressbar
        /// creates the delegation function to run asyncronously
        /// queues the delegation to run and stores the results from run into results
        /// displays the results to the user and asks them if they want to update the
        /// current vuln with the results.
        /// Hides the progressbar and returns the test script button back to default
        /// </summary>
        private async void Click_Run(object sender, RoutedEventArgs e)
        {
            Button btn = sender as Button;
            btn.Content = "Running";
            progressBar_Run.Visibility = Visibility.Visible;

            Vuln selectedItem = dataGrid.SelectedItem as Vuln;

            string script = txtPowerShell.Text;
            string functions = datastore.Get_HeaderFunctions();

            string del() { return PSOperations.Run(script, functions); }
            string results = await Task.Run(del);

            Message msgDialog = new Message(results + Store_Findings, true);
            msgDialog.ShowDialog();
            if (msgDialog.DialogResult == true)
            {
                selectedItem.FindingDetails = Operations.Add_User_Initials(results);
            }
            progressBar_Run.Visibility = Visibility.Hidden;
            btn.Content = "Test Script";
        }

        /// <summary>
        /// Click_Run_All is the handler for the Run All button
        /// Updates the content to "Running" of the button and sets the visibility to disabled
        /// Changes the visibility of the progressbar to visible
        /// Creates a new instance of the vulns dictionary and adds all the vulns from the datastore
        /// that are not "IsManualOnly", "IsHidden", and "IsBenchmark".
        /// Creates the delegation object to run asyncronously
        /// Runs the delegation and store the results into the vulns dictionary
        /// Iterates the vulns dictionary and updates the vuln findingdetails from results
        /// Resets the progressbar visibility, button content, and button display.
        /// </summary>
        private async void Click_Run_All(object sender, RoutedEventArgs e)
        {
            // Change Button Information to reflect that t
            Button btn = sender as Button;
            btn.Content = "Running";
            btn.IsEnabled = false;
            progressBar_RunAll.Visibility = Visibility.Visible;

            Dictionary<string, string> vulns = new Dictionary<string, string>();
            // Add script to vulns dicitonary
            foreach (var item in datastore.Vulns.SourceCollection)
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

            string functions = datastore.Get_HeaderFunctions();

            Dictionary<string, string> del() { return PSOperations.Run_All(vulns, functions); }
            vulns = await Task.Run(del);

            // Update vulns with results from run_all
            foreach (var item in datastore.Vulns.SourceCollection)
            {
                if (item.GetType().Equals(typeof(Vuln)) &&
                    !(item as Vuln).IsManualOnly &&
                    !(item as Vuln).IsHidden &&
                    !(item as Vuln).IsBenchmark)
                {
                    (item as Vuln).FindingDetails = Operations.Add_User_Initials(vulns[(item as Vuln).ID]);
                }
            }
            progressBar_RunAll.Visibility = Visibility.Hidden;
            btn.Content = "Run All";
            btn.IsEnabled = true;
        }

        /// <summary>
        /// Click_Run_Remote is the handler for "Run Remote" button
        /// Opens the RunRemoteWindow and displays it to the user.
        /// </summary>
        private void Click_Run_Remote(object sender, RoutedEventArgs e)
        {
            // Open Run Remote Window
            RunRemoteWindow rrw = new RunRemoteWindow(datastore);
            if(rrw.IsOpen)
                rrw.Show();            
        }

        /// <summary>
        /// Click_Functions is the handler for the "Functions" button
        /// This method displays the FunctionsWindow to the user.
        /// </summary>
        private void Click_Functions(object sender, RoutedEventArgs e)
        {
            FunctionsWindow fw = new FunctionsWindow(this);
            fw.Show();
        }
        #endregion

        #region PowerShell Textbox Operations        
        /// <summary>
        /// Click_search_registry() is a method that will search the registry for the value inside
        /// the double brackets inside the powershell textbox
        /// this method is still in the works.
        /// </summary>
        private void Click_Search_Registry(object sender, RoutedEventArgs e)
        {
            int ix1 = (dataGrid.SelectedItem as Vuln).Current_Script.IndexOf("#[[");
            int ix2 = (dataGrid.SelectedItem as Vuln).Current_Script.IndexOf("]]", ix1);

            string val = (dataGrid.SelectedItem as Vuln).Current_Script.Substring(ix1 + 3, ix2 - ix1 - 3);
            if (BaseClass.RShow($"Search Registry for {val}?"))
            {
                BaseClass.Show("This feature coming soon! Keep hanging in there!\nLove Scripts!");
                return;
                RegistryKey OurKey = Registry.LocalMachine;
                OurKey = OurKey.OpenSubKey(val, true);
                if (OurKey == null)
                {
                    BaseClass.Show("Unable to parse key.");
                    return;
                }

                foreach (string Keyname in OurKey.GetSubKeyNames())
                {
                    RegistryKey key = OurKey.OpenSubKey(Keyname);

                    BaseClass.RShow(key.ToString()); 
                }
            }
        }
        /// <summary>
        /// Click_Parse_Script will take the currently selected vulnerability and tries to parse
        /// powershell commandlets or registry values / checks from the check_content of the vulnerability
        /// then prompts the user to see if they want to use the parsed script.
        /// </summary>
        private void Click_Parse_Script(object sender, RoutedEventArgs e)
        {
            string check_content = (dataGrid.SelectedItem as Vuln).CheckContent;
            string ps = Operations.Try_Parse_PowerShell(check_content);
            string reg = Operations.Try_Parse_Registry(check_content);
            string disp_result = ps != "" ? ps : reg;
            if (BaseClass.RShow("Use this script?\n\n" + disp_result))
            {
                (dataGrid.SelectedItem as Vuln).Add_Script(disp_result);
            }
        }
        /// <summary>
        /// Click_Clean_Scripts is the handler for the Clean Up Scripts button
        /// This removes all other versions of the powershell scripts besides the most recently created one.
        /// </summary>
        private void Click_Clean_Scripts(object sender, RoutedEventArgs e)
        {
            if (BaseClass.RShow($"Do you want to remove all previous version?\n\nThis will remove all versions except {(dataGrid.SelectedItem as Vuln).Scripts.Count - 1}"))
            {
                (dataGrid.SelectedItem as Vuln).Clean_Up_Scripts();
            }
        }
        #endregion

        #region Closing / Saving
        /// <summary>
        /// The closing / saving section contains the handlers for the Stig manager 2 
        /// closing events and the button press "save"
        /// </summary>
        private void STIG_Manager_Closing(object sender, CancelEventArgs e)
        {
            Log.Add("Application Close\n\r");
        }
        /// <summary>
        /// Click_Save performs the save event to keep the current state at which the Stig manager is in
        /// and saves the different data models to files / databases
        /// First it tries to update the database files, if successful
        /// it saves the checklist, benchmark, and header functions
        /// then displays the results to the user
        /// if the database is not successful then it displays the results to the user
        /// </summary>
        private void Click_Save(object sender, RoutedEventArgs e)
        {
            if (datastore.Update_DB_File())
            {
                bool save_status = true;
                //save_status = datastore.Update_DB_File() == false ? false : save_status;
                save_status = datastore.Save_Checklist() == false ? false : save_status;
                save_status = datastore.Save_Benchmark() == false ? false : save_status;
                save_status = datastore.Save_HeaderFunctions() == false ? false : save_status;

                if (save_status)
                    BaseClass.Show("Save Successful");
                else
                    BaseClass.Show("Save Failure.");
            }
            else
            {
                BaseClass.EShow("Update Failure.\n\rSave Failure.");
            }
        }
        #endregion

        #region Load Benchmark / Checklist Data
        /// <summary>
        /// The Load Benchmark / Checklist data section is where all the handlers are for manipulating the checklist files
        /// or the benchmark files
        /// 
        /// </summary>
        
        ///Click_Load_Checklist grabs the checklist filename 
        ///checks to see if the name is null or empty string
        ///if the name is not null or empty string it loads the checklist
        ///saves the checklist and then performs the merge to display the 
        ///checklist to the user
        ///if the name is null or empty it displays the error to the user
        private void Click_Load_Checklist(object sender, RoutedEventArgs e)
        {
            Log.Add("Click_Load_Checklist()");

            string filename = Get_Filename_Checklist();

            if (!string.IsNullOrEmpty(filename))
            {
                if (Path.GetExtension(filename) != ".ckl")
                {
                    if (BaseClass.RShow("The file type you have selected isn't supported.\r1. Open STIG Viewer\r2. Create a new checklist from selected STIG\r3. Save as a new file\r4. Open STIG Manager and try uploading the newly created file.\r\rAre you sure you want to continue with this file type?"))
                    {
                        checklist.Load_Checklist(filename);
                        datastore.Save_Checklist();
                        datastore.Merge();
                    }
                    else
                    {
                        BaseClass.EShow("Checklist Not Loaded.");
                    }
                }
                else
                {
                    checklist.Load_Checklist(filename);
                    datastore.Save_Checklist();
                    datastore.Merge();
                }
            }
            else
            {
                BaseClass.EShow("Checklist Not Loaded.\nfile name: " + filename);
            }

            Log.Add("Click_Load_Checklist() Complete");
        }
        /// <summary>
        /// Click_Load_Bechmark is similar to load checklist
        /// It grabs the current / last benchmark file name and does a check to see if it null or empty
        /// if it is NOT null or empty it Loads the benchmark file, saves the benchmark file contents, 
        /// and performs a merge of the contents with the checklist and datastore components
        /// see the datastore.Merge() summary for more details
        /// if it is null or empty it displays to the user the error
        /// </summary>
        private void Click_Load_Benchmark(object sender, RoutedEventArgs e)
        {
            string filename = Get_Filename_Benchmark();
            if (!string.IsNullOrEmpty(filename))
            {
                benchmark.Load_Benchmark(filename);
                datastore.Save_Benchmark();
                datastore.Merge();
                //dataGrid.ItemsSource = datastore.Vulns;
            }
            else
            {
                BaseClass.Show("Benchmark Not Loaded.");
            }
        }
        /// <summary>
        /// Click_Clear_Benchmark is the handler to remove the contents of the benchmark file previously loaded.
        /// It creates a default instance of the Benchmark file
        /// performs a merge of the contents
        /// and then updates the GUI with the current benchmark file contents
        /// (Which should be nothing)
        /// </summary>
        private void Click_Clear_Benchmark(object sender, RoutedEventArgs e)
        {
            datastore.BenchmarkObj = new Benchmark();
            datastore.Merge();

            // Set DataContext for Benchmark Object
            txbBName.DataContext = benchmark;
            txbBVersion.DataContext = benchmark;
            txbBRelease.DataContext = benchmark;
        }

        //These are the search filters for the OpenFileDialog objects created
        public static string BenchmarkFileType = "Zip(*.zip)|*.zip|Extracted Zip(*.xml)|*.xml|All File Types(*.*)|*.*";
        public static string ChecklistFileType = "Checklist(*.ckl)|*.ckl|Extracted Zip(*.xml)|*.xml|All File Types(*.*)|*.*";
        /// <summary>
        /// GetFile returns an OpenFileDialog to a method to display to the user
        /// It creates a generic OpenFIleDialog with the above filter type and a title
        /// </summary>
        /// <param name="filetype">OpenFileDialog file filter</param>
        /// <returns>OpenFileDialog Object</returns>
        private OpenFileDialog GetFile(string filetype)
        {
            OpenFileDialog ofd = new OpenFileDialog()
            {
                CheckFileExists = true,
                Filter = filetype,
                Title = "Open File Dialog"
            };
            return ofd;
        }
        /// <summary>
        /// Get_Filename_Checklist displays a OpenFileDialog to the user in order to upload a checklist file
        /// </summary>
        /// <returns>Filename of checklist file to use a stream reader to open</returns>
        /// Returns null if no filename was selected
        public string Get_Filename_Checklist()
        {
            OpenFileDialog ofd = GetFile(ChecklistFileType);
            if (ofd.ShowDialog().Value)
                return ofd.FileName;
            return null;
        }
        /// <summary>
        /// Get_Filename_Benchmark displays a OpenFileDialog to the user in order to upload a benchmark file
        /// </summary>
        /// <returns>Filename of benchmark file to use a stream reader to open</returns>
        /// Returns null if no filename was selected
        public string Get_Filename_Benchmark()
        {
            OpenFileDialog ofd = GetFile(BenchmarkFileType);
            if (ofd.ShowDialog().Value)
                return ofd.FileName;
            return null;
        }
        /// <summary>
        /// SaveFile creates the SaveFileDialog to be displayed to the user
        /// Sets the checkpathexist to true, inserts the filter, title, and uses the current checklist name
        /// as the initialDirectory and the filename
        /// </summary>
        /// <param name="filetype">File extension filter from above</param>
        /// <returns>Returns a SaveFileDialog to display to user</returns>
        private SaveFileDialog SaveFile(string filetype)
        {
            SaveFileDialog sfd = new SaveFileDialog()
            {
                CheckPathExists = true,
                Filter = filetype,
                Title = "Save File Dialog",
                InitialDirectory = Path.GetDirectoryName(checklist.info.CustomName),
                FileName = Path.GetFileName(checklist.info.CustomName)
            };
            return sfd;
        }
        /// <summary>
        /// Click_Load_Script is the handler to load a powershell script into the database file.
        /// This method will parse the given script and add it to the current database.  If the current database
        /// contains the existing powershell script it will add it to the list of scripts of that vulnerablility.
        /// Gets the OpenFileDialog with given filter, checks to see if the user picked a file
        /// and if the user picked one loads that script into the datastore file to be parsed.
        /// else it displays an error message to the user.
        /// </summary>
        private void Click_Load_Script(object sender, RoutedEventArgs e)
        {
            try
            {
                OpenFileDialog ofd = GetFile("All File Types(*.*)|*.*");
                if (ofd.ShowDialog().Value)
                {
                    Operations.Load_Scripts(ofd, datastore);
                }
            }catch(Exception err)
            {
                BaseClass.EShow("Exception Error: " + err.Message);
            }
        }
        /// <summary>
        /// Click_Save_Checklist creates a copy of the current checklist file and changes the current checklist to the new one.
        /// It grabs the savefiledialog from SaveFile method (see SaveFile method for more details)
        /// It checks to see if the combobox "cbRemoteNames" has a selected item, if it does then it sets the default save filename
        /// as the current checklist file with the selected remote computer name added to the end of it
        /// if the dialog comes back with a valid status (filename was selected and saved)
        /// stores the filename and then clears the savefiledialog
        /// copies the checklist to the new filename, updates the checklist file with the current vulnerability findings, comments, and status
        /// loads the new filename into the program to make sure that it is reading from and writing to the correct file
        /// saves the checklist and updates the database files to point to this as the last loaded checklist
        /// then displays the results of the save file operation
        /// </summary>
        private void Click_Save_Checklist(object sender, RoutedEventArgs e)
        {
            SaveFileDialog sfd = SaveFile(ChecklistFileType);
            
            // Checks to see if the combobox remotenames has a value selected and if so adds the selected name to the saved checklist.
            if(cbRemoteNames.SelectedItem != null && cbRemoteNames.SelectedItem as string != "")
            {
                sfd.FileName = Path.GetFileNameWithoutExtension(sfd.FileName) + $"_{cbRemoteNames.SelectedItem}{Path.GetExtension(sfd.FileName)}";
            }

            if(sfd.ShowDialog().Value)
            {
                // Store filename and clear sfd
                string filename = sfd.FileName;
                sfd = null;

                // Makes sure that each step of the save application passes and displays results.
                bool Save_Successful = true;
                Save_Successful = checklist.Copy_Checklist(filename, true) == false ? false : Save_Successful;
                Save_Successful = Checklist.Update_Checklist(filename, checklist.Vulns) == false ? false : Save_Successful;
                Save_Successful = checklist.Load_Checklist(filename) == false ? false : Save_Successful;
                
                datastore.Save_Checklist();

                if (Save_Successful)
                    BaseClass.Show("Save Successful");
                else
                    BaseClass.Show("Save Failure");
            }
        }
        /// <summary>
        /// Get_Remote_Computers_Names will open the RenRemoteWindow and grab the computer names that 
        /// are used in the datagrid to display the current names in the combobox above the save new button.
        /// as long as the list of names comes back with values it will set the itemssource of the combobox to the names list
        /// 
        /// </summary>
        private void Get_Remote_Computers_Names(object sender, EventArgs e)
        {
            List<string> names = RunRemoteWindow.Get_Computer_Names();
            if (names != null)
            {
                (sender as ComboBox).ItemsSource = names;
            }
        }
        #endregion

        #region Search Textbox
        /// <summary>
        /// txtSearch_TextChanged is the handler for when the textbox to search receives changes
        /// checks the text that are inside the textbox currently and if they are the default values
        /// or empty then it just refreshes the itemssource and returns
        /// if the text is not the default or empty it gets the length and if the length hasn't changed in
        /// a half second it will continue to process the search text.
        /// This await is to create a delay between the user typing and the search results.  If this delay is 
        /// removed the search text gets processed and freezes the application until it finishes the search.
        /// once the search is complete it updates the itemssource of the vulnerabilities
        /// (see Process_Search_Text summaries for more details)
        /// </summary>
        private async void txtSearch_TextChanged(object sender, TextChangedEventArgs e)
        {
            TextBox tb = (sender as TextBox);
            if (tb.Text == "Search..." || tb.Text == "")
            {
                datastore.Refresh();
                return;
            }

            // Set initial length
            int startlength = tb.Text.Length;
            // Wait .5 seconds
            await Task.Delay(500);
            // If current text length is equal to initial length perform search
            if (startlength == tb.Text.Length)
                Process_Search_Text();
        }
        /// <summary>
        /// Process_Search_Text takes the text that was received in the textbox and passes it
        /// to the datastore object's search method to filter the existing vulnerabilities using 
        /// the search text provided.
        /// (see datastore.Search() method for more details)
        /// </summary>
        private void Process_Search_Text()
        {
            // Search Datastore list of vulns for text
            datastore.Search(txtSearch.Text);
        }
        /// <summary>
        /// txtSearch_GotFocus clears the text out of the textbox so the user can type what they are searching for.
        /// stores the previous text into the Tag attribute so that the text can be restored if the textbox loses focus
        /// without a new value in it.
        /// </summary>
        private void txtSearch_GotFocus(object sender, RoutedEventArgs e)
        {
            txtSearch.Tag = txtSearch.Text;
            txtSearch.Text = "";
        }
        /// <summary>
        /// txtSearch_LostFocus checks the current text when the textbox loses focus and if it is empty it resets to the default value
        /// </summary>
        private void txtSearch_LostFocus(object sender, RoutedEventArgs e)
        {
            if (txtSearch.Text == "")
                txtSearch.Text = "Search...";
        }
        /// <summary>
        /// chkbxShowAll_Click is the handler for the checkbox, if the checkbox is checked
        /// it takes the current filter on the vulnerabilities and removes them. 
        /// (see datastore.Refresh() for more details)
        /// </summary>
        private void chkbxShowAll_Click(object sender, RoutedEventArgs e)
        {
            CheckBox chk = (sender as CheckBox);

            if (chk.IsChecked.Value)
            {
                datastore.Refresh(true);
            }
            else
            {
                datastore.Refresh();
            }
        }
        #endregion

    }
}
