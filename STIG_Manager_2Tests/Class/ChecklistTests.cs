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
    public class ChecklistTests
    {
        public static string myDocDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments) , @"SMv2");
        
        [TestMethod()]
        public void Load_ChecklistTest()
        {
            Checklist chklst = new Checklist();

            chklst.Load_Checklist(@"Data\testWIN10.ckl");

            Assert.IsTrue(chklst.Vulns.Count >= 283);
        }

        [TestMethod()]
        public void Save_ChecklistTest()
        {
            
            Checklist chklst = new Checklist();
            chklst.Copy_Checklist(myDocDir + @"\Data\Jan_20_Manual_MRESNNB0001X.ckl", false);
            Assert.IsTrue(File.Exists(myDocDir + @"\Data\Jan_20_Manual_MRESNNB0001X.ckl"));

            FileInfo fi1 = new FileInfo(myDocDir + @"\Data\Jan_20_Manual.ckl");
            FileInfo fi2 = new FileInfo(myDocDir + @"\Data\Jan_20_Manual_MRESNNB0001X.ckl");
            Assert.AreEqual(fi1.Length, fi2.Length);
        }

        [TestMethod()]
        public void Update_ChecklistTest()
        {
            string filename = $"Data\\Jan_20_Manual.ckl";
            Checklist chklst = new Checklist();
            // Load Checklist File
            chklst.Load_Checklist(filename);

            string val = "Testing Update_Checklist Method";
            // Copy Checklist File to load
            chklst.Copy_Checklist(Path.GetFileNameWithoutExtension(filename) + "_" + Environment.MachineName + ".ckl");

            // Load Checklist File
            chklst.Load_Checklist(filename);
            // Get Random Value from Dictionary
            Vuln test1 = chklst.Vulns.Values.ToArray()[5];
            // Update Value
            test1.Comments = val;
            // Update Vuln in Dictionary
            chklst.Vulns[test1.ID] = test1;

            // Update Checklist File
            Checklist.Update_Checklist(Path.GetFileNameWithoutExtension(filename) + "_" + Environment.MachineName + ".ckl", chklst.Vulns);

            // Update FileName to reflect copied file
            filename = Checklist.Generate_Filename(filename, Environment.MachineName);

            // Load Updated Checklist File
            chklst.Load_Checklist(filename); 
            // Get the Same Value from Dictionary
            Vuln test2 = chklst.Vulns.Values.ToArray()[5];

            // Compare both Vuln items
            Assert.AreEqual(test1.Comments, test2.Comments);

        }
    }
}