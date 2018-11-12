/*
 * SSLEchoServer
 *
 * Author Michael Claudius, ZIBAT Computer Science
 * Version 1.0. 2014.02.12, 1.1 2015.10.09
 * Copyright 2014 by Michael Claudius
 * Revised 2015.11.10
 * All rights reserved
 */

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

// Inspired by https://msdn.microsoft.com/en-us/library/system.net.security.sslstream.aspx

namespace SSLEchoServer
{
    class SSLEchoServer
    {

        public static void Main(string[] args)
        {
            try
            {
                string serverCertificateFile = "c:/certificates/ServerSSL.cer";  // or ServerSSL.pfx
                X509Certificate serverCertificate = new X509Certificate(serverCertificateFile, "secret");
                bool clientCertificateRequired = true;
                bool checkCertificateRevocation = false;
                SslProtocols enabledSSLProtocols = SslProtocols.Tls;  //superseeds the former SslProtocols.Ssl3
                IPAddress ip = IPAddress.Parse("127.0.0.1");
                //IPAddress ip = IPAddress.Any; // listen any device
                TcpListener serverSocket = new TcpListener(ip, 6789);
                serverSocket.Start();
                Console.WriteLine("Server started");
                TcpClient connectionSocket = serverSocket.AcceptTcpClient();
                Console.WriteLine("Server activated");
                Stream unsecureStream = connectionSocket.GetStream();
                //Setup for handling the validation of client  
                var userCertificateValidationCallback = new RemoteCertificateValidationCallback(ValidateClientCertificate);

                // Decorator/Wrapper design pattern  
                SslStream sslStream = new SslStream(unsecureStream, false, userCertificateValidationCallback, null);
                sslStream.AuthenticateAsServer(serverCertificate, true, enabledSSLProtocols, false);
                Console.WriteLine("Server authenticated");
                StreamReader sr = new StreamReader(sslStream);
                StreamWriter sw = new StreamWriter(sslStream) { AutoFlush = true };
                // enable automatic flushing
                string message = sr.ReadLine();
                while (true)
                {
                    if (message != null && message.Equals("stop"))
                    {
                        throw new Exception("Server stop");
                    }
                    Console.WriteLine("Client: " + message);
                    if (message != null)
                    {
                        var answer = message.ToUpper();
                        sw.WriteLine(answer);
                    }
                    message = sr.ReadLine();
                }

                sslStream.Close();
                connectionSocket.Close();
                serverSocket.Stop();
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }
            
        }


        private static bool ValidateClientCertificate(object sender, X509Certificate clientCertificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            Console.WriteLine("Server Sender: " + sender.ToString());
            Console.WriteLine("Server : " + clientCertificate.ToString());
            Console.WriteLine("Server : " + sslPolicyErrors.ToString());

            if (sslPolicyErrors == SslPolicyErrors.None)
            {
                Console.WriteLine("Server  validation of client certificate successful.");
                return true;
            }
            Console.WriteLine("Errors in certificate validation:");
            Console.WriteLine(sslPolicyErrors);
            return false;
        }

       

    }

}


