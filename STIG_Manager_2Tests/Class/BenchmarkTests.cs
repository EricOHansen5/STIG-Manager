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
    public class BenchmarkTests
    {
        [TestMethod()]
        public void ReadXccdfFileTest()
        {
            string filename = @"Data\\U_MS_Windows_10_V1R17_STIG_SCAP_1-2_Benchmark.zip";
            Benchmark bench = new Benchmark();

            bench.Load_Benchmark(filename);

            Assert.IsTrue(bench.SelectedVulns.Count == 213);
        }
    }
}