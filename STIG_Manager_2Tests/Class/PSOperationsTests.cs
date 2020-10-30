using Microsoft.VisualStudio.TestTools.UnitTesting;
using STIG_Manager_2.Class;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace STIG_Manager_2.Class.Tests
{
    [TestClass()]
    public class PSOperationsTests : BaseClass
    {
        [TestMethod()]
        public void RunTest()
        {
            // Setup
            var headerFunctions = Operations.Parse_Header_Functions(@"C:\Users\eric.hansen\Desktop\LOCAL The STIGs\Scripts\Windows10STIGManualChecks_2019Q2.ps1");
            Datastore ds = new Datastore();
            ds.HeaderFunctions = headerFunctions;
            string results = PSOperations.Run("$P = Get-Process\n$P.ProcessName", ds.Get_HeaderFunctions());
            //Show(results);

            Assert.IsTrue(!string.IsNullOrEmpty(results));
            Assert.IsTrue(results.Contains("\n\r"));
        }

        [TestMethod()]
        public void TestConnectionTest()
        {
            string results = PSOperations.TestConnection("RIEMNB5568X");
            Assert.IsTrue(results != "");
            Assert.IsTrue(!results.Contains("Error running PS-Script"));
            //Show(results);
        }

        [TestMethod()]
        public void RunRemoteScriptTest()
        {
            // Setup
            var headerFunctions = Operations.Parse_Header_Functions(@"C:\Users\eric.hansen\Desktop\LOCAL The STIGs\Scripts\Windows10STIGManualChecks_2019Q2.ps1");
            Datastore ds = new Datastore();
            ds.HeaderFunctions = headerFunctions;
            var results = PSOperations.Run_Remote("RIEMNB5568X", "$P = Get-Process\n$P.ProcessName", ds.Get_HeaderFunctions());
            //Show(results);

            //Assert.IsTrue(results.Count > 0);
        }
    }
}