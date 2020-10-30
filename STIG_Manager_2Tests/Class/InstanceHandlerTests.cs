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
    public class InstanceHandlerTests
    {
        [TestMethod()]
        public void GetNumberOfInstancesTest()
        {
            Assert.IsTrue(InstanceHandler.GetNumberOfInstances() >= 0);
        }

        [TestMethod()]
        public void UpdateNumberOfInstancesTest()
        {
            InstanceHandler.UpdateNumberOfInstances();
            Assert.IsTrue(File.Exists(InstanceHandler.file));
        }

        [TestMethod()]
        public void GetOtherInstancesTest()
        {
            InstanceHandler.UpdateNumberOfInstances();
            string[] instances = InstanceHandler.GetOtherInstances();
            Assert.IsTrue(instances.Length == 0);
        }

        [TestMethod()]
        public void RemoveInstanceTest()
        {
            FileInfo fi1 = new FileInfo(InstanceHandler.file);
            InstanceHandler.RemoveInstance();
            FileInfo fi2 = new FileInfo(InstanceHandler.file);

            Assert.IsTrue(!fi2.Exists || fi1.Length > fi2.Length);
        }
    }
}