//Project 4 CSE 340 Spring 2016
//Created by the masterMind

using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Project4Test
{
    public struct inputArgs
    {
        public string args;
    }

    [TestClass]
    public class UnitTest1
    {
        // DO NOT CHANGE
        //go up three directorys for base.
        private static string baseDir = AppDomain.CurrentDomain.SetupInformation.ApplicationBase + @"\..\..\..\";
        private static string savedTestsDir = baseDir + @"\TestResults";
        private static string baseTestsDir = baseDir + @"\tests\";
        private System.IO.DirectoryInfo di = new DirectoryInfo(savedTestsDir);
        // DO NOT CHANGE

        //clean up tests results folder. set to true if you want to keep the data
        private bool keepResults = false;

        //clean up output files. set to true if you want to keep the .out files
        private bool keepOutputFiles = true;

        //set this to true to make output to console window instead of file
        private bool allToConsole = false;
        private string Inconclusive =
            "Output is redirected to console. Cannot automatically determine the expected result. Please change bool \'allToConsole\' to false.";


        private string exeName = "Ryan-aes.exe";//name of the complied project. It is usually named after the project name. Varies person to person.
        [TestMethod]
        public void Encrypt_test1()
        {
            String baseFile = "test1.txt";
            String pathToExe = baseDir + @"\Debug\" + exeName;

            inputArgs input;
            input.args = "-k 000102030405060708090a0b0c0d0e0f -i 00112233445566778899aabbccddeeff";


            String outputFilePath = baseTestsDir + baseFile + ".out";
            String expectedOutputPath = baseTestsDir + baseFile + ".expected";
            ProcessTestCase(pathToExe, input, outputFilePath);
            if (allToConsole == false)
                Assert.AreEqual(true, FileCompare(outputFilePath, expectedOutputPath));//true means files are same
            else
                Assert.Inconclusive(Inconclusive);
        }
       

        //repeater method to process all files
        public void ProcessTestCase(String pathToExe, inputArgs input, String outputFilePath)
        {
            StreamWriter sw = new StreamWriter(outputFilePath);
            StringBuilder output = new StringBuilder();

            Process process = new Process();
            process.StartInfo.FileName = pathToExe;
            process.StartInfo.UseShellExecute = false;
            process.StartInfo.RedirectStandardOutput = true;
            process.StartInfo.Arguments = input.args;
            process.EnableRaisingEvents = true;

            if (allToConsole == false)
            {
                //write output to streamWriter, which in turns writes to a file
                process.OutputDataReceived += new DataReceivedEventHandler((sender, e) =>
                {
                    if (!String.IsNullOrEmpty(e.Data))
                    {
                        sw.WriteLine(e.Data);
                    }
                });
            }
            else
            {
                process.OutputDataReceived += new DataReceivedEventHandler((sender, e) =>
                {
                    if (!String.IsNullOrEmpty(e.Data))
                    {
                        Console.WriteLine(e.Data);//output will display in bottom left hand corner. Look for a blue link named "Output"
                    }
                });
            }

            process.Start();


            process.BeginOutputReadLine();
            process.WaitForExit();
            sw.Close();
        }


        //helper methods to compare two files
        //bassed off of http://stackoverflow.com/questions/7931304/comparing-two-files-in-c-sharp/7931353#7931353
        // This method accepts two strings that have filepaths. 
        //returns true if same
        public bool FileCompare(string file1, string file2)
        {

            // Determine if the same file was referenced two times.
            if (file1 == file2)
            {
                // Return true to indicate that thes files are the same.
                return true;
            }

            // Open the two files.
            StreamReader file1Reader = new StreamReader(file1);
            StreamReader file2Reader = new StreamReader(file2);
            String file1Line, file2Line;

            // Read and compare a line from each file until either a
            // non-matching set of line is found or until the end of
            // file1 is reached.
            do
            {
                // Read one byte from each file.
                file1Line = file1Reader.ReadLine();
                file2Line = file2Reader.ReadLine();
                if (file1Line != file2Line)
                    return false;
            }
            while ((file1Line == file2Line) && (file1Line != null));

            // Close the files.
            file1Reader.Close();
            file1Reader.Close();

            // Return the success of the comparison. "file1byte" is 
            // equal to "file2byte" at this point only if the files are 
            // the same.
            return true;
        }

        //Run this function after tests are completed
        [TestCleanup]
        public void delete_saved_tests()
        {
            if (keepResults == false)
            {
                foreach (FileInfo file in di.GetFiles())
                {
                    file.Delete();
                }
                foreach (DirectoryInfo dir in di.GetDirectories())
                {
                    dir.Delete(true);
                }
            }
            if (keepOutputFiles == false)
            {
                foreach (string file in Directory.GetFiles(baseTestsDir, "*.out").Where(item => item.EndsWith(".out")))
                {
                    File.Delete(file);
                }
            }

        }
    }

}
