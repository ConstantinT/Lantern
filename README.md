# Lantern

Lantern is a small tool I created to learn about Azure authentication, tokens and C#. Maybe It helps you to learn, too. The code for authentication, is mainly adapted from [auth.py](https://github.com/dirkjanm/ROADtools/blob/master/roadlib/roadtools/roadlib/auth.py) of [roadtools](https://github.com/dirkjanm/ROADtools) from [Dirk-Jan](https://twitter.com/_dirkjan) and ported to c#. All credits for the authentication part goes to him.

How Azure PRT works is mainly described in these two articles:

* [https://dirkjanm.io/abusing-azure-ad-sso-with-the-primary-refresh-token/](https://dirkjanm.io/abusing-azure-ad-sso-with-the-primary-refresh-token/)
* [https://dirkjanm.io/digging-further-into-the-primary-refresh-token/](https://dirkjanm.io/digging-further-into-the-primary-refresh-token/)

Additionally, I started to implement Azure Device Join and to learn about that. Here I copied and adapted the code mainly from [AADInternals](https://github.com/Gerenios/AADInternals). Here all credits goes to [Dr. Nestori Syynimaa](https://twitter.com/DrAzureAD). If you want to learn more about device join I can recommend reading [this](https://o365blog.com/) blog.

At the moment you can request some tokens in various ways and join a device to Azure. Additionally you can use this device the get PRT and a session key. More is coming.

**Note:** This tools is for learning and it is in pre-, pre-, pre- (what comes before alpha?) status. 

## Compiling

You can build it with VisualStudio 2019 and .NetCore. Simple open the project and compile it. I tested it for Windows and Linux.

## Usage

### Proxy

You can always see whats going on if you add a proxy. For example like:  

```
--proxy http://127.0.0.1:8080
```

Tipp: Disable HTTP2 support on your proxy. The library I use does not support HTTP2 and I had problems with burp, if I didn't disable HTTP2.

### Help

```
.\Lantern.exe --help


.____                   __
|    |   _____    _____/  |_  ___________  ____
|    |   \__  \  /    \   __\/ __ \_  __ \/    \
|    |___ / __ \|   |  \  | \  ___/|  | \/   |  \
|_______ (____  /___|  /__|  \___  >__|  |___|  /
        \/    \/     \/          \/           \/

Lantern 0.0.1-alpha

  nonce         Request a nonce from Azure.

  cookie        Create a PRT Cookie for further usage or your browser

  token         Play with Azure Tokens

  device        Join a device to Azure

  devicekeys    Play with Device Keys - Ask for PRT and SessionKey for a certificate

  help          Display more information on a specific command.

  version       Display version information.

```

### Nonce

Request a nonce you can use the following command: 

```cmd
Lantern.exe nonce
```

### PRT-Cookie

Create a PRT-Cookie for the browser you can use:

```cmd
Lantern.exe cookie --derivedkey <Key from Mimikatz> --context <Context from Mimikatz> --prt <PRT from Mimikatz>
```

```cmd
Lantern.exe cookie --sessionkey <SessionKey> --prt <PRT from Mimikatz>
```

### Access Token

Create an access token you can use various combination:

```cmd
Lantern.exe token --derivedkey <Key from Mimikatz> --context <Context from Mimikatz> --prt <PRT from Mimikatz>
```

```cmd
Lantern.exe token --prtcookie <PRT Cookie>
```

```cmd
Lantern.exe token --username <Username> --password <Password>
```

```cmd
Lantern.exe token --refreshtoken <RefreshToken>
```

### DeviceJoin

Join a device:

```cmd
Lantern.exe device --accesstoken (or some combination from the token part) --devicename <Name> --outpfxfile <Some path>
```

### Device Keys

Generate PRT and Session Key

```cmd

Lanter.exe --devicekeys --pfxpath XXXX.pfx --refreshtoken (--prtcookie / ---username + --password ) 

```
