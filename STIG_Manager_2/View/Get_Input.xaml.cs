using System;
using System.Collections.Generic;
using System.Linq;
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
    /// Interaction logic for Get_Input.xaml
    /// </summary>
    public partial class Get_Input : Window
    {
        public string Data { get; set; }

        public Get_Input(string title, string statement)
        {
            InitializeComponent();
            lblStatement.Content = statement;
            this.Title = title;
        }

        private void Button_Click(object sender, RoutedEventArgs e)
        {
            this.DialogResult = false;
            Close();
        }

        private void Submit_Click(object sender, RoutedEventArgs e)
        {
            if (txtData.Text != "")
            {
                Data = txtData.Text;
                this.DialogResult = true;
                this.Close();
            }
            else
            {
                txtData.Tag = txtData.BorderBrush;
                txtData.BorderBrush = Brushes.Red;
            }
        }

        private void txtData_LostFocus(object sender, RoutedEventArgs e)
        {
            if(txtData.Text != "")
            {
                txtData.BorderBrush = txtData.Tag as Brush;
            }
        }
    }
}
