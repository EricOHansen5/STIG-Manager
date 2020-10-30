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
    public class DatastoreTests
    {
        [TestMethod()]
        public void Add_VulnTest()
        {
            // Setup
            Datastore ds = new Datastore();
            Vuln vuln = new Vuln()
            {
                ID = "V-6000",
                Comments = "Test Vuln"
            };

            // Check that vuln was actually added
            Assert.IsTrue(ds.Add_Vuln(vuln));
        }

        [TestMethod()]
        public void Update_VulnTest()
        {
            // Setup
            Datastore ds = new Datastore();
            Vuln vuln = new Vuln()
            {
                ID = "V-6000",
                Comments = "Test Vuln"
            };
            // Add Vuln to DB and Check that it's content is correct
            Assert.IsTrue(ds.Add_Vuln(vuln));
            Assert.IsTrue(ds.Vuln_DB[vuln.ID].Comments == "Test Vuln");

            // Update content
            vuln.Comments = "Test Vuln Update";

            // Update Vulns and check that the content is correct
            Assert.IsTrue(ds.Update_Vuln(vuln));
            Assert.IsTrue(ds.Vuln_DB[vuln.ID].Comments == "Test Vuln Update");
        }

        [TestMethod()]
        public void Create_DB_FileTest()
        {
            // Setup
            Datastore ds = new Datastore();

            // Remove existing db files
            File.Delete(Datastore.dbfile);
            File.Delete(Datastore.dbfileBAK);

            // Check if file exists
            Assert.IsTrue(ds.Create_DB_File());
            // Create backup
            ds.Copy_DB_File();

            // Check if file created from backup
            File.Delete(Datastore.dbfile);
            Assert.IsTrue(ds.Create_DB_File(true));

            // Check if file created after both backup and origin deleted
            File.Delete(Datastore.dbfile);
            File.Delete(Datastore.dbfileBAK);
            Assert.IsTrue(ds.Create_DB_File());
        }

        [TestMethod()]
        public void Copy_DB_FileTest()
        {
            // Setup
            Datastore ds = new Datastore();
            Assert.IsTrue(ds.Create_DB_File());
            File.Delete(Datastore.dbfileBAK);

            // Creates backup of db file
            Assert.IsTrue(ds.Copy_DB_File());

            // Try to create another copy
            Assert.IsFalse(ds.Copy_DB_File());

            // Force create a copy
            Assert.IsTrue(ds.Copy_DB_File(true));
        }

        [TestMethod()]
        public void Load_DB_FileTest()
        {
            // Setup
            File.Delete(Datastore.dbfile);
            File.Delete(Datastore.dbfileBAK);
            Datastore ds = new Datastore();
            Vuln vuln = new Vuln()
            {
                ID = "V-6000",
                Comments = "Test Vuln"
            };
            Assert.IsTrue(ds.Create_DB_File());

            // Add Vuln and Check that it was added successfully.
            Assert.IsTrue(ds.Add_Vuln(vuln));
            Assert.IsTrue(ds.Vuln_DB.Count > 0);

            // Load in empty DB File and Check that it is empty
            Assert.IsTrue(ds.Load_DB_File());
            Assert.IsTrue(ds.Vuln_DB.Count == 66);

            // Add Vuln and Save to DB File
            //Assert.IsTrue(ds.Add_Vuln(vuln));
            Assert.IsTrue(ds.Update_DB_File());
            Assert.IsTrue(ds.Load_DB_File());
            Assert.IsTrue(ds.Vuln_DB.Count >= 66);
        }

        [TestMethod()]
        public void Update_DB_FileTest()
        {
            // Setup
            Datastore ds = new Datastore();
            DateTime d1 = ds.DBInfo.LastWriteTime;
            Assert.IsTrue(ds.Update_DB_File());
            DateTime d2 = ds.DBInfo.LastWriteTime;

            // Checks to see if the newly updated db file has a newer lastwritetime
            Assert.IsTrue(d1.CompareTo(d2) <= 0);
        }

        [TestMethod()]
        public void Get_HeaderFunctionsTest()
        {
            Datastore ds = new Datastore();
            if (!ds.Restore_HeaderFunctions())
            {
                ds.HeaderFunctions = Operations.Parse_Header_Functions("Data/Windows10STIGManualChecks_v1.2.ps1");
                Assert.IsTrue(ds.Save_HeaderFunctions());
            }

            Assert.IsTrue(ds.Get_HeaderFunctions().Length > 0);
        }

        [TestMethod()]
        public void Restore_HeaderFunctionsTest()
        {
            Datastore ds = new Datastore();
            Assert.IsTrue(ds.Restore_HeaderFunctions());
        }
    }
}