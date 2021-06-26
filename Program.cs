using Docker.DotNet;

using Docker.DotNet.Models;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Threading;

namespace WaitForFinish
{
    class Program
    {
        static int Main(string[] args)
        {
            var parameters = new ContainersListParameters()
            {
                All = true
            };

            DockerClient client = null;

            Credentials credentials = null;
            //var credential = Environment.GetEnvironmentVariable("CREDENTIAL_TYPE");
            //if (string.Equals(credential, "BASIC", StringComparison.InvariantCultureIgnoreCase))
            //{
            //    var username = Environment.GetEnvironmentVariable("USERNAME");
            //    var password = Environment.GetEnvironmentVariable("PASSWORD");
            //    credentials = new BasicAuthCredentials(username, password);
            //}
            //else if (string.Equals(credential, "X509", StringComparison.InvariantCultureIgnoreCase))
            //{
            //    var file = Environment.GetEnvironmentVariable("CERTIFICATE_PATH");
            //    var pass = Environment.GetEnvironmentVariable("CERTIFICATE_PASSWORD");
            //    credentials = new CertificateCredentials(new X509Certificate2(file, pass));
            //}
            

            var address = Environment.GetEnvironmentVariable("URI");
            Uri uri = null;
            if (!string.IsNullOrWhiteSpace(address))
            {
                uri = new Uri(address);
            }

            if (uri != null)
            {
                client = new DockerClientConfiguration(uri, credentials).CreateClient();
            }
            else
            {
                client = new DockerClientConfiguration(credentials).CreateClient();
            }

            string[] names = Environment.GetEnvironmentVariable("CONTAINER_NAMES")?.Split(",") ?? throw new InvalidOperationException("Container names should be informed!");
            var treatEnv = Environment.GetEnvironmentVariable("TREAT_UNKNOWN_AS_FAILED");
            bool treatUnknownStatusAsFailed = false;
            if (treatEnv != null)
            {
                treatUnknownStatusAsFailed = bool.Parse(treatEnv);
            }
            



            var atLeastOneIsRunning = true;
            var secondsBetweeenTests = 1;
            var exitCodeList = new List<int>();
            do
            {
                try
                {
                    var containers = client.Containers.ListContainersAsync(parameters).Result;

                    var containersWithNameMatched = containers.Where(container =>
                    {
                        var anyNameOfThisContainerIsInListProvidedByUser = container.Names
                            .Select(r => r.Replace("/", string.Empty))
                            .Any(name => names.Contains(name));
                        return anyNameOfThisContainerIsInListProvidedByUser;
                    }).ToList();

                    exitCodeList.Clear();
                    atLeastOneIsRunning = containersWithNameMatched.AsParallel().Any(container =>
                    {
                        var running = string.Equals(container.State.ToString().ToLower(), "running");
                        if (!running)
                        {
                            try
                            {
                                var va = container.Status.SkipWhile(a => a != '(').Skip(1).TakeWhile(a => a != ')');
                                var exitCode = new String(va.ToArray());
                                exitCodeList.Add(Convert.ToInt32(exitCode));
                            }
                            catch (Exception ex)
                            {
                                if (treatUnknownStatusAsFailed)
                                {
                                    exitCodeList.Add(1);
                                }
                                else
                                {
                                    exitCodeList.Add(0);
                                }
                            }
                        }
                        return running;
                    });

                    Console.Out.WriteLine(DateTime.Now.ToString() + " - Is at least one alive? " + atLeastOneIsRunning.ToString());
                    Thread.Sleep(secondsBetweeenTests * 1000);
                }
                catch (Exception exception)
                {
                    Console.Out.WriteLine(exception.Message + Environment.NewLine + exception.Source + Environment.NewLine + exception.StackTrace);

                    if (exception is AggregateException agg)
                    {
                        foreach (var item in agg.InnerExceptions)
                        {
                            Console.Out.WriteLine(exception.Message + Environment.NewLine + exception.Source + Environment.NewLine + exception.StackTrace);
                        }
                    }
                }
            } while (atLeastOneIsRunning);

            var anyFail = exitCodeList.Any(exitCode => exitCode != 0);
            if (anyFail)
            {
                Console.Out.WriteLine(DateTime.Now.ToString() + " - At least one of the containers FAIL!");
                return 1;
            } 
            else
            {
                Console.Out.WriteLine(DateTime.Now.ToString() + " - Containers exited successfully!");
                return 0;
            }
            //var atLeastOneIsSuccess = true;
            //var secondsBetweeenTests = 1;
            //do
            //{
            //    atLeastOneIsSuccess = args.AsParallel().Any(arg =>
            //    {
            //        var success = SuccessTest(arg);
            //        return success;
            //    });

            //    Console.Out.WriteLine(DateTime.Now.ToString() + " Is at least one alive? " + atLeastOneIsSuccess.ToString());
            //    Thread.Sleep(secondsBetweeenTests * 1000);

            //} while (atLeastOneIsSuccess);
        }

        private static bool SuccessTest(string arg)
        {
            var success = false;
            if (arg.Contains(":"))
            {
                try
                {
                    var splitted = arg.Split(":");
                    using (var client = new TcpClient(splitted.First(), Convert.ToInt32(splitted.Last())))
                    {
                        client.SendTimeout = 1000;
                        client.ReceiveTimeout = 1000;
                        success = true;
                    }
                }
                catch (SocketException ex)
                {
                    success = false;
                }

            }
            else
            {
                try
                {
                    using (Ping ping = new Ping())
                    {
                        var r = ping.Send(arg);
                        success = r.Status == IPStatus.Success;
                    }
                }
                catch (PingException ex)
                {
                    success = false;
                }
            }
            return success;
        }
    }
}
