using Microsoft.VisualStudio.TestTools.UnitTesting;
using STIG_Manager_2.Class;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Win32;
using System.Text.RegularExpressions;

namespace STIG_Manager_2.Class.Tests
{
    [TestClass()]
    public class OperationsTests
    {
        [TestMethod()]
        public void Parse_ScriptTest()
        {
            // Setup
            Dictionary<string, string> PSResults = Operations.Parse_Script(@"C:\Users\eric.hansen\Desktop\LOCAL The STIGs\Scripts\Windows10STIGManualChecks_2019Q2.ps1");
            int count = PSResults.Count;

            // Check that PSResults didn't return as null
            Assert.IsNotNull(PSResults);
            Assert.IsTrue(count > 65);

            var psresults = Operations.Parse_Script(@"C:\Users\eric.hansen\Desktop\LOCAL The STIGs\Scripts\ESXi_STIGs.ps1");
            count = psresults.Count;
            Assert.IsNotNull(psresults);
            Assert.IsTrue(count > 30);
            foreach (var item in psresults)
            {
                Assert.IsTrue(item.Key.Length <= 8);
            }
        }

        [TestMethod()]
        public void Parse_Header_FunctionsTest()
        {
            // Setup
            var headerFunctions = Operations.Parse_Header_Functions(@"C:\Users\eric.hansen\Desktop\LOCAL The STIGs\Scripts\Windows10STIGManualChecks_2019Q2.ps1");
            //string val = headerFunctions.Values.ToArray()[0].LastFunction;

            // Check that there is 8 header functions
            Assert.IsNotNull(headerFunctions.Count == 8);
        }

        [TestMethod()]
        public void Parse_AutoComplete_CmdletsTest()
        {
            string[] cmdlets = Operations.Parse_AutoComplete_Cmdlets();
            Assert.IsTrue(cmdlets.Length >= 1303);
        }

        [TestMethod()]
        public void Load_ScriptsTest()
        {
            Datastore ds = new Datastore();
            ds.Load_DB_File();
            ds.Update_DB_File();

            ds.Merge();
            Console.WriteLine(ds.Vuln_DB.Count);
        }

        [TestMethod()]
        public void Clean_ScriptTest()
        {
            string val = "Some Script with Different TYPES of capitalizations | Out-file $logName -append";

            string clean_val = Operations.ReplaceCaseInsensitive(val, "| Out-file $logname -append", "");

            Assert.AreEqual("Some Script with Different TYPES of capitalizations ", clean_val);
        }

        [TestMethod()]
        public void Try_Parse_PowerShellTest()
        {
            string val =
@"Run ""PowerShell"".
Copy the lines below to the PowerShell window and enter.

""([ADSI]('WinNT://{0}' -f $env:COMPUTERNAME)).Children | Where { $_.SchemaClassName -eq 'user' } | ForEach {
$user = ([ADSI]$_.Path)
$lastLogin = $user.Properties.LastLogin.Value
$enabled = ($user.Properties.UserFlags.Value - band 0x2) -ne 0x2
if ($lastLogin - eq $null) {
$lastLogin = 'Never'
 }
            Write - Host $user.Name $lastLogin $enabled
}""

This will return a list of local accounts with the account name, last logon, and if the account is enabled(True/False).
For example: User1 10/31/2015 5:49:56 AM True

Review the list to determine the finding validity for each account reported.

Exclude the following accounts:
Built-in administrator account(Disabled, SID ending in 500)
Built-in guest account(Disabled, SID ending in 501)
Built-in DefaultAccount(Disabled, SID ending in 503)
Local administrator account

If any enabled accounts have not been logged on to within the past 35 days, this is a finding.

Inactive accounts that have been reviewed and deemed to be required must be documented with the ISSO.";
            string result = Operations.Try_Parse_PowerShell(val);
            Assert.IsTrue(result.Length >= 373);
            val = @"Security Option ""Audit: Force audit policy subcategory settings(Windows Vista or later) to override audit policy category settings"" must be set to ""Enabled"" (WN10-SO-000030) for the detailed auditing subcategories to be effective.

Use the AuditPol tool to review the current Audit Policy configuration:
Open a Command Prompt with elevated privileges(""Run as Administrator"").
Enter ""AuditPol /get /category:*"".

Compare the AuditPol settings with the following.If the system does not audit the following, this is a finding:

Account Logon >> Credential Validation - Failure
";
            result = Operations.Try_Parse_PowerShell(val);
            Assert.IsTrue(result.Length >= 35);

            val = @"Verify the DoD Interoperability cross-certificates are installed on unclassified systems as Untrusted Certificates.

Run ""PowerShell"" as an administrator.

Execute the following command:

Get - ChildItem - Path Cert: Localmachine\disallowed | Where {$_.Issuer - Like ""*DoD Interoperability*"" - and $_.Subject - Like ""*DoD*""} | FL Subject, Issuer, Thumbprint, NotAfter

       If the following certificate ""Subject"", ""Issuer"", and ""Thumbprint"", information is not displayed, this is finding.

       If an expired certificate(""NotAfter"" date) is found, this is a finding.

Subject: CN = DoD Root CA 3, OU = PKI, OU = DoD, O = U.S.Government, C = US
Issuer: CN = DoD Interoperability Root CA 2, OU = PKI, OU = DoD, O = U.S.Government, C = US
Thumbprint: AC06108CA348CC03B53795C64BF84403C1DBD341
NotAfter: 1 / 22 / 2022

Subject: CN = DoD Root CA 2, OU = PKI, OU = DoD, O = U.S.Government, C = US
Issuer: CN = DoD Interoperability Root CA 1, OU = PKI, OU = DoD, O = U.S.Government, C = US
Thumbprint: A8C27332CCB4CA49554CE55D34062A7DD2850C02
NotAfter: 8 / 26 / 2022

Alternately use the Certificates MMC snap-in:

Run ""MMC"".

Select ""File"", ""Add/Remove Snap-in"".

Select ""Certificates"", click ""Add"".

Select ""Computer account"", click ""Next"".

Select ""Local computer: (the computer this console is running on)"", click ""Finish"".

Click ""OK"".

Expand ""Certificates"" and navigate to ""Untrusted Certificates >> Certificates"".

For each certificate with ""DoD Root CA…"" under ""Issued To"" and ""DoD Interoperability Root CA…"" under ""Issued By"":

Right - click on the certificate and select ""Open"".

Select the ""Details"" Tab.

Scroll to the bottom and select ""Thumbprint"".

If the certificates below are not listed or the value for the ""Thumbprint"" field is not as noted, this is a finding.

If an expired certificate(""Valid to"" date) is not listed in the results, this is not a finding.

Issued To: DoD Root CA 2
Issued By: DoD Interoperability Root CA 1
Thumbprint: A8C27332CCB4CA49554CE55D34062A7DD2850C02
Valid to: Friday, August 26, 2022

Issued To: DoD Root CA 3
Issued By: DoD Interoperability Root CA 2
Thumbprint: AC06108CA348CC03B53795C64BF84403C1DBD341
Valid to: Saturday, January 22, 2022";

            result = Operations.Try_Parse_PowerShell(val);
            Assert.IsTrue(result.Length >= 189);
        }

        [TestMethod()]
        public void Remove_OutfileTest()
        {
            string script = "blah blah blah | Out-FIle $logName -append";
            script = Operations.Remove_Outfile(script);

            Assert.IsTrue(script.Equals("blah blah blah "));

            script = "blah blah blah | Out-FIle $logName -append\nhmmm okay?\rout-file | out-file $logname";
            script = Operations.Remove_Outfile(script);

            Assert.IsTrue(script.Equals("blah blah blah \r\nhmmm okay?\r\nout-file \r\n"));

        }
    }
}