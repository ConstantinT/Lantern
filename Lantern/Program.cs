﻿using CommandLine;
using JWT;
using JWT.Algorithms;
using JWT.Builder;
using JWT.Serializers;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Lantern
{

   

    class Program
    {
       
        static void Main(string[] args)
        {
            PrintBanner();
            //CommandLine.Parser.Default.ParseArguments<OptionsMutuallyExclusive>(args).WithParsed(RunOptions).WithNotParsed(HandleParseError);
            Parser.Default.ParseArguments<NonceOptions, CookieOptions, TokenOptions, DeviceOptions, DeviceKeyOptions>(args)
            .MapResult(
                (DeviceKeyOptions options) => RunKey(options),
                (DeviceOptions options) => JoinDevice(options),
                (NonceOptions options) => RunNonce(options),
                (CookieOptions options) => RunCookie(options),
                (TokenOptions options) => RunToken(options),
                errors => Error());
        }

        static int RunKey(DeviceKeyOptions opts)
        {
            String refreshtoken = null;
            string tenantId = null;
            var serializer = new JsonNetSerializer();
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, urlEncoder);
            if (opts.RefreshToken != null)
            {
                string initToken = Helper.authenticateWithRefreshToken(opts.RefreshToken, opts.Proxy, AzResourceEnum.MDMResource, AzResourceEnum.AzureMDMClientID);
                string checkAccessToken = JToken.Parse(initToken)["access_token"].ToString();
                string decodedaccesstoken = decoder.Decode(checkAccessToken);
                JToken parsedAccessToken = JToken.Parse(decodedaccesstoken);
                String aud = parsedAccessToken["aud"].ToString();
                tenantId = parsedAccessToken["tid"].ToString();
                if (aud != AzResourceEnum.MDMResource)
                {
                    Console.WriteLine("AccessToken does not contain correct Audience...");
                    return 1;
                }
                refreshtoken = opts.RefreshToken;
            }
            else if (opts.UserName != null && opts.Password != null)
            {
                String initTokens = Helper.getToken(opts, AzResourceEnum.MDMResource, AzResourceEnum.AzureMDMClientID);
                if (initTokens == null)
                {
                    Console.WriteLine("Authentication failed... ");
                    return 1;
                }
                JToken parsedInitToken = JToken.Parse(initTokens);
                tenantId = Helper.getTenantFromAccessToken(parsedInitToken["access_token"].ToString());
                refreshtoken = parsedInitToken["refresh_token"].ToString();               
            }
            if (refreshtoken != null && tenantId != null)
            {
                X509Certificate2 cert = new X509Certificate2(opts.PFXPath, "", X509KeyStorageFlags.Exportable);
                var privateKey = cert.GetRSAPrivateKey();
                var x5c = Convert.ToBase64String(cert.Export(X509ContentType.Cert));

                string nonce = Helper.getNonce2(opts.Proxy);

                Dictionary<string, string> headerRaw = new Dictionary<string, string>
                    {
                        { "alg", "RS256" },
                        { "typ", "JWT" },
                        { "x5c", x5c }
                    };

                string headerRawString = JsonConvert.SerializeObject(headerRaw, Formatting.None);
                var header = Helper.Base64UrlEncode(System.Text.Encoding.UTF8.GetBytes(headerRawString));

                Dictionary<string, string> rawPayload = new Dictionary<string, string>
                    {
                        { "request_nonce", nonce },
                        { "scope", "openid aza ugs" },
                        { "win_ver", "10.0.18363.0" },
                        { "grant_type", "refresh_token" },
                        { "refresh_token", refreshtoken },
                        { "client_id", "29d9ed98-a469-4536-ade2-f981bc1d605e" }

                    };

                string rawPayloadString = JsonConvert.SerializeObject(rawPayload, Formatting.None);
                var payload = Helper.Base64UrlEncode(System.Text.Encoding.UTF8.GetBytes(rawPayloadString));

                var dataBin = System.Text.Encoding.UTF8.GetBytes(header + "." + payload);

                var signature = privateKey.SignData(dataBin, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                var signatureb64 = Helper.Base64UrlEncode(signature);

                var JWT = header + "." + payload + "." + signatureb64;

                var formContent = new FormUrlEncodedContent(new[]
                   {
                    new KeyValuePair<string, string>("windows_api_version", "2.0"),
                    new KeyValuePair<string, string>("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                    new KeyValuePair<string, string>("request", JWT),
                    new KeyValuePair<string, string>("client_info", "2")
                    });

                string result = Helper.postToTokenEndpoint(formContent, opts.Proxy, tenantId);
                JToken parsedResult = JToken.Parse(result);
                string PRT = parsedResult["refresh_token"].ToString();
                string JWE = parsedResult["session_key_jwe"].ToString();
                string[] JWESplitted = JWE.Split(".");
                byte[] encKey = Helper.Base64Decode(JWESplitted[1]);
                var formatter = new System.Security.Cryptography.RSAOAEPKeyExchangeDeformatter(privateKey);
                var dekey = formatter.DecryptKeyExchange(encKey);
                string decryptionKey = Convert.ToBase64String(dekey);

                Console.WriteLine();
                Console.WriteLine("Here is your PRT:");
                Console.WriteLine();
                Console.WriteLine(Convert.ToBase64String(Encoding.ASCII.GetBytes(PRT)));
                Console.WriteLine();
                Console.WriteLine("Here is your session key:");
                Console.WriteLine();
                Console.WriteLine(decryptionKey);

                return 0;
            }
            else
            {
                Console.WriteLine("For this you need a username and a password");
                return 1;
            }
        }

        static int JoinDevice(DeviceOptions opts)
        {
            String accesstoken = null;
            String upn = null;
            string tenantId = null;
            var serializer = new JsonNetSerializer();
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, urlEncoder);
            if (opts.AccessToken != null)
            {
                
                string decodedaccesstoken = decoder.Decode(opts.AccessToken);
                JToken parsedAccessToken = JToken.Parse(decodedaccesstoken);
                String aud = parsedAccessToken["aud"].ToString();
                tenantId = parsedAccessToken["tid"].ToString();
                upn = parsedAccessToken["upn"].ToString();
                if (aud != AzResourceEnum.DeviceMgmtClientID)
                {
                    Console.WriteLine("AccessToken does not contain correct Audience...");
                    return 1;
                }

                accesstoken = opts.AccessToken;

            }
            else
            {
                String initTokens = Helper.getToken(opts);
                if (initTokens == null)
                {
                    Console.WriteLine("Authentication failed... ");
                    return 1;
                }
                JToken parsedInitToken = JToken.Parse(initTokens);
                String initAccesstoken = decoder.Decode(parsedInitToken["access_token"].ToString());
                String refreshtoken = parsedInitToken["refresh_token"].ToString();
                var parsedInitAccessToken = JToken.Parse(initAccesstoken);
                tenantId = parsedInitAccessToken["tid"].ToString();
                upn = parsedInitAccessToken["upn"].ToString();
                string tokenForDevMgmt = Helper.getAccessTokenWithRefreshtoken(refreshtoken, "01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9", tenantId, opts.Proxy);
                JToken parsedTokenForDevMgmt = JToken.Parse(tokenForDevMgmt);
                accesstoken = parsedTokenForDevMgmt["access_token"].ToString();


            }
            if (accesstoken != null && upn != null && tenantId != null)
            {

                // https://github.com/Gerenios/AADInternals/blob/23831d5af045eeaa199ab098d29df9d4a60f460e/PRT_Utils.ps1#L95
                //RSACng rsa = (RSACng)RSA.Create(2048);
                RSACng rsa = new RSACng(2048);
                string CN = "CN=7E980AD9-B86D-4306-9425-9AC066FB014A";
                CertificateRequest req = new System.Security.Cryptography.X509Certificates.CertificateRequest(CN, rsa, System.Security.Cryptography.HashAlgorithmName.SHA256, System.Security.Cryptography.RSASignaturePadding.Pkcs1);
                var crs = Convert.ToBase64String(req.CreateSigningRequest());
                var transportKey = Convert.ToBase64String(rsa.Key.Export(CngKeyBlobFormat.GenericPublicBlob));
                string responseJoinDevice = Helper.addNewDeviceToAzure(opts.Proxy, accesstoken, crs, transportKey, upn.Split("@")[1], opts.DeviceName, opts.RegisterDevice);
                JToken parsedJoinResponse = JToken.Parse(responseJoinDevice);
                byte[] binCert = Convert.FromBase64String(parsedJoinResponse["Certificate"]["RawBody"].ToString());
                X509Certificate2 cert = new X509Certificate2(binCert, "", X509KeyStorageFlags.UserKeySet | X509KeyStorageFlags.Exportable);

                string deviceId = cert.Subject.Split("=")[1];
                Console.WriteLine("Device successfull added to Azure");
                Console.WriteLine("");
                Console.WriteLine("The deviceId is: " + deviceId);
                Console.WriteLine("");
                var beautified = parsedJoinResponse.ToString(Formatting.Indented);
                Console.WriteLine(beautified);
                Console.WriteLine("");
                
                // https://github.com/dotnet/runtime/issues/19581
                var keyPair = cert.CopyWithPrivateKey(rsa);
                byte[] certData = keyPair.Export(X509ContentType.Pfx, "");
                File.WriteAllBytes(deviceId + ".pfx", certData);

                Console.WriteLine("Device Certificate written to " + deviceId + ".pfx");

            }
            else
            {
                return 1;
            }

            return 0;
        }

        static int Error() {
            Console.WriteLine("Please tell me want you want to do...");
            return 1;
        
        }

        static void PrintBanner()
        {
            String banner = @"
.____                   __                       
|    |   _____    _____/  |_  ___________  ____  
|    |   \__  \  /    \   __\/ __ \_  __ \/    \ 
|    |___ / __ \|   |  \  | \  ___/|  | \/   |  \
|_______ (____  /___|  /__|  \___  >__|  |___|  /
        \/    \/     \/          \/           \/ ";
            Console.WriteLine("");
            Console.WriteLine(banner);
            Console.WriteLine("");
        }

        static int RunNonce(NonceOptions opts)
        {

            Console.WriteLine(Helper.getNonce(opts.Proxy));
            return 0;
        }

        static int RunCookie(CookieOptions opts)
        {
            if (opts.PRT == null | opts.DerivedKey == null | opts.Context == null)
            {
                Console.WriteLine("Please set the corect arguments.");
                return 1;
            }
            else
            {
                Console.WriteLine("Here is your PRT-Cookie:");
                Console.WriteLine("");
                Console.WriteLine(Helper.createPRTCookie(opts.PRT, opts.Context, opts.DerivedKey, opts.Proxy));
                Console.WriteLine("");
                Console.WriteLine("You can use it with this tool or add it to a browser.");
                Console.WriteLine("Set as cookie \"x-ms-RefreshTokenCredential\" with HTTPOnly flag");
            }

            return 0;
        }

        static int RunToken(TokenOptions opts)
        {

            String result = Helper.getToken(opts, opts.ResourceID, opts.ClientID);
            if (result != null)
            {
                var serializer = new JsonNetSerializer();
                var urlEncoder = new JwtBase64UrlEncoder();
                var decoder = new JwtDecoder(serializer, urlEncoder);

                JToken parsedJson = JToken.Parse(result);
                if (parsedJson["id_token"] != null)
                {
                    var id_token = decoder.Decode(parsedJson["id_token"].ToString());
                    var parsedIDToken = JToken.Parse(id_token);
                    parsedJson["id_token"] = parsedIDToken;
                }

                Console.WriteLine("Here is your token:");
                Console.WriteLine("");
                var beautified = parsedJson.ToString(Formatting.Indented);
                Console.WriteLine(beautified);

                return 0;
            }
            return 1;
        }
    }
}
