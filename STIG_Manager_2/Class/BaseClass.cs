using System;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows;

namespace STIG_Manager_2.Class
{
    public class BaseClass : INotifyPropertyChanged
    {
        #region Notify Property Changed Members
        public event PropertyChangedEventHandler PropertyChanged;
        public void OnPropertyChanged([CallerMemberName] string name = "")
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
        }
        #endregion

        /// <summary>
        /// 
        /// </summary>
        /// <param name="message"></param>
        public static void Show(string message)
        {
            //Console.WriteLine(message);
            MessageBox.Show(message, "Notification", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        public static void EShow(string error)
        {
            MessageBox.Show(error, "Error", MessageBoxButton.OK, MessageBoxImage.Error);

            Log.Add(error, Log.Level.ERR);

            Console.WriteLine(error);
        }

        public static bool RShow(string question)
        {
            //Console.WriteLine();
            if (MessageBox.Show(question, "Question", MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes)
                return true;
            return false;
        }
    }
}
