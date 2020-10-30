using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;

namespace STIG_Manager_2.View
{
    /// <summary>
    /// Interaction logic for Message.xaml
    /// </summary>
    public partial class Message : Window
    {
        public string Msg { get; set; }
        public bool isYesNo { get; set; }
        public bool isCancel { get; set; }

        public Message(string Msg, bool isYesNo = false, bool isCancel = false)
        {
            this.Msg = Msg;
            this.isYesNo = isYesNo;
            this.isCancel = isCancel;

            InitializeComponent();
            DataContext = this;
            SetVisibility();

            Icon icon = SystemIcons.Question;
            BitmapSource bs = Imaging.CreateBitmapSourceFromHIcon(icon.Handle, Int32Rect.Empty, BitmapSizeOptions.FromEmptyOptions());
            System.Windows.Controls.Image uiImage = new System.Windows.Controls.Image()
            {
                Source = bs,
                Stretch = Stretch.Uniform,
                VerticalAlignment = VerticalAlignment.Top
            };
            stkIcons.Children.Add(uiImage);
        }

        private void SetVisibility()
        {
            if (isYesNo)
            {
                btnYes.Visibility = Visibility.Visible;
                btnNo.Visibility = Visibility.Visible;
                btnOk.Visibility = Visibility.Hidden;
                btnCancel.Visibility = Visibility.Hidden;
                return;
            }

            if (isCancel)
            {
                btnYes.Visibility = Visibility.Hidden;
                btnNo.Visibility = Visibility.Hidden;
                btnOk.Visibility = Visibility.Visible;
                btnCancel.Visibility = Visibility.Visible;
                return;
            }

            btnYes.Visibility = Visibility.Hidden;
            btnNo.Visibility = Visibility.Hidden;
            btnOk.Visibility = Visibility.Visible;
            btnCancel.Visibility = Visibility.Hidden;
        }

        private void btn_Click(object sender, RoutedEventArgs e)
        {
            switch((sender as Button).Name)
            {
                case "btnYes":
                    this.DialogResult = true;
                    break;
                case "btnNo":
                    this.DialogResult = false;
                    break;
                case "btnOk":
                    this.DialogResult = true;
                    break;
                case "btnCancel":
                    this.DialogResult = false;
                    break;
                default:
                    this.DialogResult = true;
                    break;
            }
        }
    }
}
