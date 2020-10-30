using Microsoft.VisualStudio.TestTools.UnitTesting;
using STIG_Manager_2.Class;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace STIG_Manager_2.Class.Tests
{
    [TestClass()]
    public class LogTests
    {
        [TestMethod()]
        public void AddTest()
        {
            Log.Add("Test Log", Log.Level.GEN);
            Log.Add("Test Log Warning", Log.Level.WARN);
            Log.Add("Test Log Error", Log.Level.ERR);
            Log.Add("Test Log Critical", Log.Level.CRIT);

            Assert.IsTrue((new FileInfo(Log.filename)).Length > 0);
        }
    }
}