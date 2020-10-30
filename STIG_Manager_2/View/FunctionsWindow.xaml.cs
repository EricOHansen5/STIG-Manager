using STIG_Manager_2.Class;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
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
    /// Interaction logic for FunctionsWindow.xaml
    /// </summary>
    public partial class FunctionsWindow : Window, INotifyPropertyChanged
    {

        #region Notify Property Changed Members
        public event PropertyChangedEventHandler PropertyChanged;
        private void OnPropertyChanged([CallerMemberName] string name = "")
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
        }
        #endregion

        #region ScaleValue Depdency Property
        // This Region is used to scale/zoom in the application as user changes the size up or down.

        public static readonly DependencyProperty ScaleValueProperty
            = DependencyProperty.Register("ScaleValue", typeof(double),
                typeof(FunctionsWindow), new UIPropertyMetadata(1.0,
                    new PropertyChangedCallback(OnScaleValueChanged),
                    new CoerceValueCallback(OnCoerceScaleValue)));
        private static object OnCoerceScaleValue(DependencyObject o, object value)
        {
            FunctionsWindow Functions_Window = o as FunctionsWindow;
            if (Functions_Window != null)
                return Functions_Window.OnCoerceScaleValue((double)value);
            else
                return value;
        }
        private static void OnScaleValueChanged(DependencyObject o, DependencyPropertyChangedEventArgs e)
        {
            FunctionsWindow Functions_Window = o as FunctionsWindow;
            if (Functions_Window != null)
                Functions_Window.OnScaleValueChanged((double)e.OldValue, (double)e.NewValue);
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
            ScaleValue = (double)OnCoerceScaleValue(Functions_Window, value);
        }
        #endregion

        public MainWindow mainWindow { get; set; }



        private Dictionary<string, PSHeaderFunction> _FunctionList;
        public Dictionary<string, PSHeaderFunction> FunctionList
        {
            get { return _FunctionList; }
            set { if (value != _FunctionList) _FunctionList = value; OnPropertyChanged(); }
        }

        public FunctionsWindow(MainWindow mainWindow)
        {
            this.mainWindow = mainWindow;
            FunctionList = mainWindow.datastore.HeaderFunctions;
            AutoCompleteList = mainWindow.AutoCompleteList;

            InitializeComponent();
            DataContext = this;

            lbFunctions.DataContext = FunctionList;
            lbFunctions.ItemsSource = FunctionList;
        }

        private void Close_Click(object sender, RoutedEventArgs e)
        {
            if(BaseClass.RShow("Are you sure you want to close?\nAnything changed since last save will not be saved."))
                Close();
        }

        private void Save_Click(object sender, RoutedEventArgs e)
        {
            Log.Add("Save_Click()");
            mainWindow.datastore.Save_HeaderFunctions();
            BaseClass.Show("Save Complete");
        }

        private void Add_Function_Click(object sender, RoutedEventArgs e)
        {
            Get_Input get_name = new Get_Input("Add New Function", "Function Name");
            if (get_name.ShowDialog().Value)
            {
                string name = get_name.Data;
                PSHeaderFunction func = new PSHeaderFunction()
                {
                    Title = name
                };
                func.Add_Function("");

                FunctionList.Add(name, func);

                lbFunctions.Items.Refresh();
            }
        }

        private void Remove_Function_Click(object sender, RoutedEventArgs e)
        {
            bool func = lbFunctions.SelectedIndex >= 0 ? true : false;
            if(func && BaseClass.RShow("Are you sure you want to remove selected function?\nIf one of the scripts needs this function, you could get errors when running them."))
            {
                Log.Add("Remove_Function_Click()");
                FunctionList.Remove(((KeyValuePair<string, PSHeaderFunction>)lbFunctions.SelectedItem).Key);
                lbFunctions.Items.Refresh();
                BaseClass.Show("Function Removed");
            }
        }

        #region AutoComplete
        public string[] AutoCompleteList;
        private void TextBox_KeyUp(object sender, System.Windows.Input.KeyEventArgs e)
        {
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

            if (query.Length == 0)
            {
                stkAutoComplete.Children.Clear();
                border.Visibility = Visibility.Collapsed;
            }
            else
            {
                border.Visibility = Visibility.Visible;
            }

            stkAutoComplete.Children.Clear();

            foreach (var obj in AutoCompleteList)
            {
                if (obj.ToLower().StartsWith(query.ToLower()))
                {
                    addItem(obj);
                    found = true;
                }
            }

            if (!found)
            {
                stkAutoComplete.Children.Add(new TextBlock() { Text = "No Results." });
            }

            if (e.Key.Equals(Key.Tab) && !(stkAutoComplete.Children[0] as TextBlock).Text.Contains("No Results."))
            {
                e.Handled = true;
                int ix = txtFunction.Text.IndexOf(query);
                (sender as TextBox).Text = (sender as TextBox).Text.Substring(0, ix) + (stkAutoComplete.Children[0] as TextBlock).Text + end_str;
                (sender as TextBox).SelectionStart = ix + (stkAutoComplete.Children[0] as TextBlock).Text.Length;

                stkAutoComplete.Children.Clear();
                border.Visibility = Visibility.Collapsed;
            }

            if (e.Key.Equals(Key.Escape))
            {
                stkAutoComplete.Children.Clear();
                border.Visibility = Visibility.Collapsed;
            }
        }

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
                string sub_str = txtFunction.Text.Substring(0, txtFunction.SelectionStart);
                string end_str = txtFunction.Text.Substring(txtFunction.SelectionStart);
                // This splits the substring into an array
                string[] words = sub_str.Split(new char[] { ' ', '\n', '\r', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                int last = words.Length > 0 ? words.Length - 1 : 0;
                string query = words[last];
                int ix = txtFunction.Text.IndexOf(query);
                txtFunction.Text = txtFunction.Text.Substring(0, ix) + (sender as TextBlock).Text + end_str;
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

    }
}
