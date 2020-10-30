using Microsoft.VisualStudio.TestTools.UnitTesting;
using STIG_Manager_2;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace STIG_Manager_2.Tests
{
    [TestClass()]
    public class MainWindowTests
    {
        [TestMethod()]
        public void InitializeDatastoreTest()
        {
            MainWindow mw = new MainWindow();
            //Assert.IsTrue(mw.datastore.DBInfo.Exists);
            //Assert.IsTrue(mw.datastore.DBInfoBAK.Exists);
            //Assert.IsTrue(mw.datastore.ChecklistObj.Loaded);
        }
    }
}