using CommandLine;
using JWT;
using JWT.Algorithms;
using JWT.Builder;
using JWT.Serializers;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Net.Http;
using System.Text;

namespace Lantern
{
    public class OptionsMutuallyExclusive
    {

        [Option(SetName = "Nonce", HelpText = "Ask for Nonce")]
        public bool AskNonce { get; set; }

        [Option(SetName = "Cookie", HelpText = "Ask for PRT Cookie")]
        public bool AskCookie { get; set; }

        [Option(SetName = "Token", HelpText = "Ask for token")]
        public bool AskToken { get; set; }

        [Option(HelpText = "Set Proxy")]
        public string Proxy { get; set; }

        [Option(HelpText = "Set PRT")]
        public string PRT { get; set; }

        [Option(HelpText = "Set DerivedKey")]
        public string DerivedKey { get; set; }

        [Option(HelpText = "Set Context")]
        public string Context { get; set; }

        [Option(HelpText = "Set Refreshtoken")]
        public string RefreshToken { get; set; }

        [Option(HelpText = "Set PRTCookie")]
        public string PrtCookie { get; set; }

        [Option(HelpText = "Set ClientID (ApplicationID)")]
        public string ClientID { get; set; }

        [Option(HelpText = "Set Client Secret")]
        public string ClientSecret { get; set; }

        [Option(HelpText = "Set Tenant")]
        public string Tenant { get; set; }

        [Option(HelpText = "Set username")]
        public string UserName { get; set; }

        [Option(HelpText = "Set password")]
        public string Password { get; set; }
    }

    class Program
    {
        static HttpClient getDefaultClient(String proxy, bool useCookies = true)
        {
            HttpClientHandler handler = new HttpClientHandler();
            if (proxy != null)
            {
                handler.Proxy = new WebProxy(proxy);
                handler.UseProxy = true;
            }

            handler.ClientCertificateOptions = ClientCertificateOption.Manual;
            handler.ServerCertificateCustomValidationCallback =
                (httpRequestMessage, cert, cetChain, policyErrors) =>
                {
                    return true;
                };
            handler.AllowAutoRedirect = false;

            handler.UseCookies = useCookies;
            var client = new HttpClient(handler);
            client.BaseAddress = new Uri("https://login.microsoftonline.com");
            client.DefaultRequestHeaders.Clear();
            client.DefaultRequestHeaders.Add("UA-CPU", "AMD64");
            client.DefaultRequestHeaders.Add("User-Agent", "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; Win64; x64; Trident/7.0; .NET4.0C; .NET4.0E)");
            return client;

        }

        static string getCodeFromPRTCookie(string cookie, string proxy)
        {
            String uri = string.Format(@"/Common/oauth2/authorize?resource={0}&client_id={1}&response_type={2}&haschrome={3}&redirect_uri={4}&client-request-id={5}&x-client-SKU={6}&x-client-Ver={7}&x-client-CPU={8}&x-client-OS={9}&site_id={10}&mscrid={11}",
                "https://graph.windows.net/",
                "1b730954-1685-4b74-9bfd-dac224a7b894",
                "code",
                "1",
                "urn:ietf:wg:oauth:2.0:oob",
                //Guid.NewGuid(),
                "AAAAAAA",
                "PCL.Desktop",
                "3.19.7.16602",
                "x64",
                "Microsoft Windows NT 10.0.19569.0",
                "501358",
                Guid.NewGuid());
            HttpClient client = getDefaultClient(proxy);
            using (client)
            {
                var message = new HttpRequestMessage(HttpMethod.Get, uri);
                String xcookie = "x-ms-RefreshTokenCredential=" + cookie;
                message.Headers.Add("Cookie", xcookie);
                var response = client.SendAsync(message).Result;
                if (response.StatusCode.Equals("200"))
                {
                    Console.WriteLine("Something went wrong, cannot fetch code with PRT cookie, maybe Conditional Access Policy blocks.");
                    return null;
                }

                string location = "";

                if (response.Headers.Contains("Location"))
                {
                    location = response.Headers.Location.ToString();
                }
                else
                {
                    Console.WriteLine("Something went wrong, cannot fetch code with PRT cookie, maybe Conditional Access Policy blocks.");
                    return "";
                }
                
                int startOf = location.IndexOf("code=");
                if (startOf == -1)
                {
                    Console.WriteLine("Something went wrong, cannot fetch code with PRT cookie, maybe Conditional Access Policy blocks.");
                    return null;
                }
                int endOf = location.IndexOf("&", startOf + 5);
                int len = endOf - startOf;
                string code = location.Substring(startOf + 5, len - 5);
                client.Dispose();
                return code;
            }
        }


        static string postToTokenEndpoint(FormUrlEncodedContent formContent, string proxy, string uri = "/common/oauth2/token")
        {
            using (var message = new HttpRequestMessage(HttpMethod.Post, uri))
            using (var client = getDefaultClient(proxy, false))
            {
                message.Headers.Add("client-request-id", Guid.NewGuid().ToString());
                message.Headers.Add("return-client-request-id", "true");
                message.Content = formContent;
                var response = client.SendAsync(message).Result;
                if (response.IsSuccessStatusCode)
                {
                    var result = response.Content.ReadAsStringAsync().Result;
                    return result;
                }
                return null;
            }
        }

        static string authenticateWithClientIDandSecret(string clientID, string clientSecret, string tennant, string proxy)
        {
            var formContent = new FormUrlEncodedContent(new[]
                {
                new KeyValuePair<string, string>("grant_type", "client_credentials"),
                new KeyValuePair<string, string>("client_id", clientID),
                new KeyValuePair<string, string>("resource", "https://graph.windows.net"),
                new KeyValuePair<string, string>("client_secret", clientSecret)
                });
            return postToTokenEndpoint(formContent, proxy, "/" + tennant + "/oauth2/token");
        }

        static string authenticateWithUserNameAndPassword(string username, string password, string proxy)
        {
            var formContent = new FormUrlEncodedContent(new[]
                {
                new KeyValuePair<string, string>("grant_type", "password"),
                new KeyValuePair<string, string>("scope", "openid"),
                new KeyValuePair<string, string>("resource", "https://graph.windows.net"),
                new KeyValuePair<string, string>("client_id", "1b730954-1685-4b74-9bfd-dac224a7b894"),
                new KeyValuePair<string, string>("username", username),
                new KeyValuePair<string, string>("password", password)
                });
            return postToTokenEndpoint(formContent, proxy);
        }

        static string authenticateWithRefreshToken(string token, string proxy)
        {
            var formContent = new FormUrlEncodedContent(new[]
                {
                new KeyValuePair<string, string>("grant_type", "refresh_token"),
                new KeyValuePair<string, string>("resource", "https://graph.windows.net"),
                new KeyValuePair<string, string>("client_id", "1b730954-1685-4b74-9bfd-dac224a7b894"),
                new KeyValuePair<string, string>("refresh_token", token),
                });
            return postToTokenEndpoint(formContent, proxy);
        }
        static string authenticateWithCode(string code, string proxy = "")
        {
            var formContent = new FormUrlEncodedContent(new[]
                {
                new KeyValuePair<string, string>("grant_type", "authorization_code"),
                new KeyValuePair<string, string>("resource", "https://graph.windows.net"),
                new KeyValuePair<string, string>("client_id", "1b730954-1685-4b74-9bfd-dac224a7b894"),
                new KeyValuePair<string, string>("redirect_uri", "urn:ietf:wg:oauth:2.0:oob"),
                new KeyValuePair<string, string>("code", code)
                });

            return postToTokenEndpoint(formContent, proxy);
        }

        // https://stackoverflow.com/questions/1459006/is-there-a-c-sharp-equivalent-to-pythons-unhexlify
        static byte[] Hex2Binary(string hex)
        {
            var chars = hex.ToCharArray();
            var bytes = new List<byte>();
            for (int index = 0; index < chars.Length; index += 2)
            {
                var chunk = new string(chars, index, 2);
                bytes.Add(byte.Parse(chunk, NumberStyles.AllowHexSpecifier));
            }
            return bytes.ToArray();
        }

        static string createPRTCookie(string prt, string context, string derived_sessionkey, string proxy)
        {
            string secret = derived_sessionkey.Replace(" ", "");
            string nonce = getNonce(proxy);

            var padlen = prt.Length % 4;
            for (int i = 0; i < padlen; i++)
            {
                prt = prt + "=";
            }

            byte[] data = Convert.FromBase64String(prt);
            string prtdecoded = Encoding.UTF8.GetString(data);

            var payload = new Dictionary<string, object>
            {
                { "refresh_token", prtdecoded },
                { "is_primary", "true" },
                { "request_nonce", nonce }
            };

            var header = new Dictionary<string, object>
            {
                { "ctx", Hex2Binary(context) }
            };

            IJwtAlgorithm algorithm = new HMACSHA256Algorithm(); // symmetric
            IJsonSerializer serializer = new JsonNetSerializer();
            IBase64UrlEncoder urlEncoder = new JwtBase64UrlEncoder();
            IJwtEncoder encoder = new JwtEncoder(algorithm, serializer, urlEncoder);

            var sdata = Hex2Binary(secret);
            var cookie = encoder.Encode(header, payload, sdata);
            return cookie;
        }

        static String getNonce(string proxy)
        {
            using (var client = getDefaultClient(proxy))
            {
                // Original from auth.py
                //String uri = string.Format(@"/Common/oauth2/authorize?resource={0}&client_id={1}&response_type={2}&haschrome={3}&redirect_uri={4}&client-request-id={5}&x-client-SKU={6}&x-client-Ver={7}&x-client-CPU={8}&x-client-OS={9}&site_id={10}&mscrid={11}",
                //    "https://graph.windows.net/",
                //    "1b730954-1685-4b74-9bfd-dac224a7b894",
                //    "code",
                //    "1",
                //    "urn:ietf:wg:oauth:2.0:oob",
                //    Guid.NewGuid(),
                //    "PCL.Desktop",
                //    "3.19.7.16602",
                //    "x64",
                //    "Microsoft Windows NT 10.0.19569.0",
                //    "501358",
                //    Guid.NewGuid());


                String uri = string.Format(@"/Common/oauth2/authorize?client_id={0}", "1b730954-1685-4b74-9bfd-dac224a7b894");
                var response = client.GetAsync(uri).Result;
                var responseContent = response.Content;
                string responseString = responseContent.ReadAsStringAsync().Result;
                int startOf = responseString.IndexOf("\"nonce\":\"");
                int endOf = responseString.IndexOf("\"", startOf + 9);
                int len = endOf - startOf;
                string nonce = responseString.Substring(startOf + 9, len - 9);
                client.Dispose();
                return nonce;
            }
        }

        static void Main(string[] args)
        {
            CommandLine.Parser.Default.ParseArguments<OptionsMutuallyExclusive>(args).WithParsed(RunOptions).WithNotParsed(HandleParseError);
        }

        static void RunOptions(OptionsMutuallyExclusive opts)
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

            if (opts.AskNonce) {
                Console.WriteLine(getNonce(opts.Proxy));
            }
            else if (opts.AskCookie)
            {
                if (opts.PRT == null | opts.DerivedKey == null | opts.Context == null)
                {
                    Console.WriteLine("Please set the corect arguments.");
                    return;
                }
                else
                {
                    Console.WriteLine("Here is your PRT-Cookie:");
                    Console.WriteLine("");
                    Console.WriteLine(createPRTCookie(opts.PRT, opts.Context, opts.DerivedKey, opts.Proxy));
                    Console.WriteLine("");
                    Console.WriteLine("You can use it with this tool or add it to a browser.");
                    Console.WriteLine("Set as cookie \"x-ms-RefreshTokenCredential\" with HTTPOnly flag");
                }

            }
            else if (opts.AskToken)
            {
                string result = null;
                if (opts.PRT != null & opts.DerivedKey != null & opts.Context != null)
                {
                    string prtCookie = createPRTCookie(opts.PRT, opts.Context, opts.DerivedKey, opts.Proxy);
                    string code = getCodeFromPRTCookie(prtCookie, opts.Proxy);
                    result = authenticateWithCode(code, opts.Proxy);
                }
                else if (opts.PrtCookie != null)
                {
                    string code = getCodeFromPRTCookie(opts.PrtCookie, opts.Proxy);
                    result = authenticateWithCode(code, opts.Proxy);
                    

                }
                else if (opts.RefreshToken != null)
                {
                    result = authenticateWithRefreshToken(opts.RefreshToken, opts.Proxy);
                }
                else if (opts.UserName != null & opts.Password != null)
                {
                    result = authenticateWithUserNameAndPassword(opts.UserName, opts.Password, opts.Proxy);
                }
                else if (opts.Tenant != null & opts.ClientID != null & opts.ClientSecret != null)
                {
                    result = authenticateWithClientIDandSecret(opts.ClientID, opts.ClientSecret, opts.Tenant, opts.Proxy);
                }
                else
                {
                    Console.WriteLine("Please set the corect arguments.");
                    return;
                }

                if(result != null)
                {
                   

                    var serializer = new JsonNetSerializer();
                    var urlEncoder = new JwtBase64UrlEncoder();
                    var decoder = new JwtDecoder(serializer, urlEncoder);

                    JToken parsedJson = JToken.Parse(result);
                    if (parsedJson["id_token"] != null) {
                        var id_token = decoder.Decode(parsedJson["id_token"].ToString());
                        var parsedIDToken = JToken.Parse(id_token);
                        parsedJson["id_token"] = parsedIDToken;
                    }
                    

                    Console.WriteLine("Here is your token:");
                    Console.WriteLine("");
                    var beautified = parsedJson.ToString(Formatting.Indented);
                    Console.WriteLine(beautified);
                }
                else
                {
                    Console.WriteLine("Sorry something went wrong...");
                }

                
            }
            else
            {
                Console.WriteLine("Please tell me want you want to have: --asknonce, --askcookie, --asktoken or --help");

            }
        }
        static void HandleParseError(IEnumerable<Error> errs)
        {
            //handle errors
        }
    }
}
