using Microsoft.VisualStudio.TestTools.UnitTesting;
using STIG_Manager_2.Class;
using STIG_Manager_2.View;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace STIG_Manager_2.Class.Tests
{
    [TestClass()]
    public class ComputerTests
    {
        [TestMethod()]
        public void Create_Checklist_FileTest()
        {
            MainWindow mw = new MainWindow();

            Computer comp = new Computer()
            {
                Name = "RIEMNB5555X"
            };

            RunRemoteWindow rrw = new RunRemoteWindow(mw.datastore);
            rrw.Computers.Add(comp);
        }

        [TestMethod()]
        public void Test_Connection()
        {

        }
    }
}