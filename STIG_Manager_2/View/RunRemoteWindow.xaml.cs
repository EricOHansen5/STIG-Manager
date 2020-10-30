using Newtonsoft.Json;
using STIG_Manager_2.Class;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;

namespace STIG_Manager_2.View
{
    /// <summary>
    /// Interaction logic for RunRemoteWindow.xaml
    /// </summary>
    public partial class RunRemoteWindow : Window, INotifyPropertyChanged
    {

        #region Notify Property Changed Members
        public event PropertyChangedEventHandler PropertyChanged;
        private void OnPropertyChanged([CallerMemberName] string name = "")
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
        }
        #endregion

        #region Properties
        private BackgroundWorker bg;
        private BackgroundWorker bg_checker;

        private Visibility _IsChecking = Visibility.Hidden;
        public Visibility IsChecking
        {
            get { return _IsChecking; }
            set { if (value != _IsChecking) _IsChecking = value; OnPropertyChanged(); }
        }

        private int _CountDown = 60;
        public int CountDown
        {
            get { return _CountDown; }
            set { if (value != _CountDown) _CountDown = value; OnPropertyChanged(); }
        }

        private bool _IsRunning;
        public bool IsRunning
        {
            get { return _IsRunning; }
            set { 
                if (value != _IsRunning) 
                    _IsRunning = value;
                if (value == false)
                    TaskIsComplete();

                OnPropertyChanged(); }
        }

        private Datastore datastore;

        private List<Computer> _Computers = new List<Computer>();
        public List<Computer> Computers
        {
            get { return _Computers; }
            set { if (value != _Computers) _Computers = value; OnPropertyChanged(); }
        }
        
        private const int Test_Connect_mSecs = 3000;

        public bool IsOpen { get; set; }

        private List<Computer> OG_Computers { get; set; }


        private bool _Saved = true;
        public bool Saved
        {
            get { return _Saved; }
            set { if (value != _Saved) _Saved = value; OnPropertyChanged(); }
        }
        #endregion

        public RunRemoteWindow(Datastore datastore)
        {
            try
            {
                if (!PSOperations.Check_Internet_Connection())
                {
                    BaseClass.Show("Please check your internet connection and try again.\n\rIf this persists then try restarting your computer.");
                    IsOpen = false;
                    Close();
                    return;
                }
                
                Restore_Computers();
                bg = new BackgroundWorker()
                {
                    WorkerReportsProgress = true,
                    WorkerSupportsCancellation = true
                };
                bg_checker = new BackgroundWorker()
                {
                    WorkerReportsProgress = true
                };

                this.datastore = datastore;

                InitializeComponent();
                DataContext = this;

                // Monitors running background workers and updates UI based on status.
                bg.DoWork += (_, args) =>
                {
                    while (!(_ as BackgroundWorker).CancellationPending)
                    {
                        if (bg.CancellationPending)
                            return;

                        // Wait 0.1 seconds
                        Thread.Sleep(1000);

                        // Iterate through computers and check isRunning status and report 
                        bool isRunning = false;
                        foreach (var item in dgComputers.Items)
                        {
                            if (item != null && item.GetType() == typeof(Computer) && (item as Computer).IsRunning)
                            {
                                isRunning = true;
                            }
                        }
                        int ir = isRunning ? 1 : 0;
                        bg.ReportProgress(ir);
                    }

                };
                bg.ProgressChanged += (_, args) =>
                {
                    IsRunning = args.ProgressPercentage == 1 ? true : false;
                };

            
                bg_checker.DoWork += (_, args) =>
                {
                    while (true)
                    {
                        Thread.Sleep(1000);
                        bg_checker.ReportProgress(0);
                    }
                };
                bg_checker.ProgressChanged += (_, args) =>
                {
                    if (CountDown == 0)
                    {
                        if (PSOperations.Check_Internet_Connection())
                        {
                            foreach (Computer computer in Computers)
                                computer.IsOnline();
                            Check_Online();
                            CountDown = Test_Connect_mSecs / 100;
                        }
                    }
                    else if (IsChecking == Visibility.Hidden)
                        CountDown--;
                };
                Check_Online();
                bg_checker.RunWorkerAsync();

                IsOpen = true;

            }
            catch (Exception e)
            {
                BaseClass.Show("Error: " + e.Message);
                IsOpen = false;
                Close();
            }
        }

        #region ScaleValue Depdency Property
        // This Region is used to scale/zoom in the application as user changes the size up or down.

        public static readonly DependencyProperty ScaleValueProperty
            = DependencyProperty.Register("ScaleValue", typeof(double),
                typeof(RunRemoteWindow), new UIPropertyMetadata(1.0,
                    new PropertyChangedCallback(OnScaleValueChanged),
                    new CoerceValueCallback(OnCoerceScaleValue)));
        private static object OnCoerceScaleValue(DependencyObject o, object value)
        {
            RunRemoteWindow Run_Remote_Window = o as RunRemoteWindow;
            if (Run_Remote_Window != null)
                return Run_Remote_Window.OnCoerceScaleValue((double)value);
            else
                return value;
        }
        private static void OnScaleValueChanged(DependencyObject o, DependencyPropertyChangedEventArgs e)
        {
            RunRemoteWindow Run_Remote_Window = o as RunRemoteWindow;
            if (Run_Remote_Window != null)
                Run_Remote_Window.OnScaleValueChanged((double)e.OldValue, (double)e.NewValue);
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
            double yScale = ActualHeight / 450; //change the denominator up will increase the windows size vertically
            double xScale = ActualWidth / 800; //change the denominator up will increase the windows size horizontally
            double value = Math.Min(xScale, yScale);
            //value = 1;
            ScaleValue = (double)OnCoerceScaleValue(Run_Remote_Window, value);
        }
        #endregion

        private void Click_Run_Selected(object sender, RoutedEventArgs e)
        {
            TaskIsRunning();
            StartBackgroundTask();

            bg.RunWorkerAsync();
        }

        private void StartBackgroundTask()
        {
            foreach (Computer item in Computers)
            {
                if (item.IsSelected && !item.bgw.IsBusy && item.Online)
                {
                    item.Run(datastore);
                }
            }
        }

        private void TaskIsRunning()
        {
            // Update UI to reflect bg task
            btnRun_Selected.IsEnabled = false;
            progressBar_Run.Visibility = Visibility.Visible;
            btnCancel_Run.IsEnabled = true;
        }

        private void TaskIsComplete()
        {
            this.btnRun_Selected.IsEnabled = true;
            this.progressBar_Run.Visibility = Visibility.Hidden;
            this.btnCancel_Run.IsEnabled = false;
            bg.CancelAsync();
        }

        private void Click_Cancel_Run(object sender, RoutedEventArgs e)
        {
            foreach (Computer item in Computers)
            {
                if (item.IsSelected || item.IsRunning)
                {
                    item.bgw.CancelAsync();
                }
            }
        }

        public static string computer_list = "Data/last_computers.json";
        private void Click_Save(object sender, RoutedEventArgs e)
        {
            Save();
        }
        private void Save()
        {
            Log.Add("Click_Save()");

            try
            {
                // Create / Overwrite the last_computers list file
                using (FileStream fs = File.Create(computer_list))
                {
                    byte[] info = new UTF8Encoding(true).GetBytes(JsonConvert.SerializeObject(Computers));
                    fs.Write(info, 0, info.Length);
                }

                Log.Add("Computers Saved Successfully.");
                BaseClass.Show("Computers Saved Successfully.");
                Saved = true;

                OG_Computers = new List<Computer>(Computers);
            }
            catch (IOException ioe)
            {
                BaseClass.EShow("IOERROR:" + ioe.Message);
            }
            catch (Exception err)
            {
                BaseClass.EShow("ERROR:" + err.Message);
            }
        }
        private void CheckForChanges()
        {
            for (int i = 0; i < OG_Computers.Count; i++)
            {
                if(Computers[i].Name != OG_Computers[i].Name)
                {
                    Saved = false;
                    return;
                }
            }
        }
        private bool Restore_Computers()
        {
            Log.Add("Restore_Computers()");

            OG_Computers = new List<Computer>();
            try
            {
                if (File.Exists(computer_list))
                {
                    // read the last_benchmark file
                    using (StreamReader sr = File.OpenText(computer_list))
                    {
                        string file = sr.ReadToEnd();
                        Computers = JsonConvert.DeserializeObject<List<Computer>>(file);
                        OG_Computers = JsonConvert.DeserializeObject<List<Computer>>(file);
                        foreach (var item in Computers)
                        {
                            item.IsSelected = false;
                            item.IsRunning = false;
                            item.Completed = 0;
                            item.FinishText = "Not Run";
                            item.Run_Results = null;
                            item.Online = false;
                            item.IsOnline();
                        }
                    }

                    Log.Add("Computers Restored Successfully.", Log.Level.GEN);
                    return true;
                }
                else
                {
                    Log.Add("Last Computers File Doesn't Exist.", Log.Level.GEN);
                    return false;
                }
            }
            catch (IOException ioe)
            {
                BaseClass.EShow("IOERROR:" + ioe.Message);
                return false;
            }
            catch (Exception e)
            {
                BaseClass.EShow("ERROR:" + e.Message);
                return false;
            }
        }
        /// <summary>
        /// Get_Computer_Names allows other classes to access the remote computers list
        /// </summary>
        /// <returns></returns>
        public static List<string> Get_Computer_Names()
        {
            Log.Add("Get_Computer_Names()");

            List<string> names = new List<string>();
            try
            {
                if (File.Exists(computer_list))
                {
                    // read the last_benchmark file
                    using (StreamReader sr = File.OpenText(computer_list))
                    {
                        string file = sr.ReadToEnd();
                        List<Computer> Computers = JsonConvert.DeserializeObject<List<Computer>>(file);
                        foreach (var item in Computers)
                        {
                            names.Add(item.Name);
                            //item.IsSelected = false;
                            //item.IsRunning = false;
                            //item.Completed = 0;
                            //item.FinishText = "Not Run";
                            //item.Run_Results = null;
                            //item.Online = false;
                            //item.IsOnline();
                        }
                    }

                    Log.Add("Return Computer Names Successfully.", Log.Level.GEN);
                    return names;
                }
                else
                {
                    Log.Add("Last Computers File Doesn't Exist.", Log.Level.GEN);
                    return names;
                }
            }
            catch (IOException ioe)
            {
                BaseClass.EShow("IOERROR:" + ioe.Message);
                return null;
            }
            catch (Exception e)
            {
                BaseClass.EShow("ERROR:" + e.Message);
                return null;
            }
        }
        private void Click_AllSelected(object sender, RoutedEventArgs e)
        {
            e.Handled = true;

            CheckBox cb = sender as CheckBox;

            if (cb == null) return;

            foreach (var item in dgComputers.Items)
            {
                if(item != null && item.GetType() == typeof(Computer))
                    (item as Computer).IsSelected = cb.IsChecked.Value;
            }
        }

        private void Click_Close(object sender, RoutedEventArgs e)
        {
            Close();
        }

        private async void Check_Online()
        {
            IsChecking = Visibility.Visible;
            lblCountDown.Visibility = Visibility.Hidden;
            void del()
            {
                bool ischecking = false;
                do {
                    ischecking = false;
                    foreach (Computer item in Computers)
                    {
                        if (item.IsChecking)
                            ischecking = true;
                    }
                } while (ischecking);
            }
            await Task.Run(del);
            IsChecking = Visibility.Hidden;
            lblCountDown.Visibility = Visibility.Visible;

        }

        private void Click_Cell_Changed(object sender, SelectedCellsChangedEventArgs e)
        {
            Computer comp = dgComputers.SelectedItem as Computer;
            if (comp != null)
                comp.IsSelected = !comp.IsSelected;
        }

        private void btnCheckNow_Click(object sender, RoutedEventArgs e)
        {
            foreach (Computer computer in Computers)
                computer.IsOnline();
            Check_Online();
            CountDown = Test_Connect_mSecs / 100;
        }

        private void Run_Remote_Window_Closing(object sender, CancelEventArgs e)
        {
            CheckForChanges();
            if (!Saved)
            {
                if (BaseClass.RShow("Would you like to save before closing?\n\rAny unsaved changes will be lost."))
                {
                    Save();
                }
            }
            IsOpen = false;
        }

        private void dgComputers_CellEditEnding(object sender, DataGridCellEditEndingEventArgs e)
        {
            CheckForChanges();
        }

        private void Click_Delete(object sender, RoutedEventArgs e)
        {
            if(dgComputers != null && dgComputers.SelectedItem.GetType() == typeof(Computer))
            {
                Computers.Remove(dgComputers.SelectedItem as Computer);
                dgComputers.Items.Refresh();
            }
        }
    }
}
