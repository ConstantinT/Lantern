using CommandLine;


namespace Lantern
{
    [Verb("devicekeys", HelpText = "Play with Device Keys")]
    class DeviceKeyOptions : TokenOptions
    {
        [Option(HelpText = "Set PFX path", Required = true)]
        public string PFXPath { get; set; }

    }

    [Verb("nonce", HelpText = "Request a nonce from Azure.")]
    class NonceOptions
    {
        [Option(HelpText = "Set Proxy")]
        public string Proxy { get; set; }
    }
    [Verb("cookie", HelpText = "Create a PRT Cookie for further usage or your browser")]
    class CookieOptions
    {
        [Option(HelpText = "Set Proxy")]
        public string Proxy { get; set; }
        [Option(HelpText = "Set PRT")]
        public string PRT { get; set; }

        [Option(HelpText = "Set DerivedKey")]
        public string DerivedKey { get; set; }

        [Option(HelpText = "Set Context")]
        public string Context { get; set; }


    }
    [Verb("token", HelpText = "Play with Azure Tokens")]
    class TokenOptions
    {
        [Option(HelpText = "Set Proxy")]
        public string Proxy { get; set; }

        [Option(HelpText = "Set PRT")]
        public string PRT { get; set; }

        [Option(HelpText = "Set Session Key")]
        public string SessionKey { get; set; }

        [Option(HelpText = "Set DerivedKey")]
        public string DerivedKey { get; set; }

        [Option(HelpText = "Set Context")]
        public string Context { get; set; }

        [Option(HelpText = "Set Refreshtoken")]
        public string RefreshToken { get; set; }

        [Option(HelpText = "Set PRTCookie")]
        public string PrtCookie { get; set; }

        [Option(HelpText = "Set ClientID (ApplicationID), for example GraphAPI (1b730954-1685-4b74-9bfd-dac224a7b894)", Default = "1b730954-1685-4b74-9bfd-dac224a7b894")]
        public string ClientID { get; set; }

        [Option(HelpText = "Set Client Secret")]
        public string ClientSecret { get; set; }

        [Option(HelpText = "Set Tenant")]
        public string Tenant { get; set; }
         
        [Option(HelpText = "Set username")]
        public string UserName { get; set; }

        [Option(HelpText = "Set password")]
        public string Password { get; set; }

        [Option(HelpText = "Set resource ID for access token, for example for Device Management (01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9)", Default = "https://graph.windows.net")]
        public string ResourceID { get; set; }

    }
    [Verb("device", HelpText = "Join a device to Azure")]
    class DeviceOptions : TokenOptions
    {
        [Option(HelpText = "Set device name", Required = true)]
        public string DeviceName { get; set; }

        [Option(HelpText = "Set this, if you want only register the device", Default = false)]
        public bool RegisterDevice { get; set; }

        [Option(HelpText = "Set access token")]
        public string AccessToken { get; set; }
    }
}
