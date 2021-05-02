# Lantern

Lantern is a small tool I created to learn something about Azure authentication, tokens and about C#. Maybe It helps you to learn too. The code for authentication, is mainly copied from [auth.py](https://github.com/dirkjanm/ROADtools/blob/master/roadlib/roadtools/roadlib/auth.py) of [roadtools](https://github.com/dirkjanm/ROADtools) from [Dirk-Jan](https://twitter.com/_dirkjan) and ported to c#. All credits for the authentication poart goes to him.

How Azure PRT works is mainly described in these two articles:

* [https://dirkjanm.io/abusing-azure-ad-sso-with-the-primary-refresh-token/](https://dirkjanm.io/abusing-azure-ad-sso-with-the-primary-refresh-token/)
* [https://dirkjanm.io/digging-further-into-the-primary-refresh-token/](https://dirkjanm.io/digging-further-into-the-primary-refresh-token/)

Addtionally I started to implement Azure Device Join and to learn about that. Here I copied and adapted the code mainly from [AADInternals](https://github.com/Gerenios/AADInternals). Here all credits goes to [Dr. Nestori Syynimaa](https://twitter.com/DrAzureAD). If you want to learn more about device join I can recommend reading [this](https://o365blog.com/) blog.

At the moment you can request some tokens in various ways and join deviced to Azure. More is coming.

**Note:** This tools is for learning and it is in pre-, pre-, pre- (what comes before alpha?) status. =)

## Compiling

The is built with VisualStudio 2019 and .NetCore. Simple open the project and compile it. I tested it for Windows and Linux.

## Usage

### Proxy

You can always see whats going on if you add a proxy. For example like:  

```
--proxy http://127.0.0.1:8080
```

Tipp: Disable HTTP2 support on your proxy. The library I use does not support HTTP2 and I had problems with burp, if I didn't disables HTTP2.

### Help

```
.\Lantern.exe --help


.____                   __
|    |   _____    _____/  |_  ___________  ____
|    |   \__  \  /    \   __\/ __ \_  __ \/    \
|    |___ / __ \|   |  \  | \  ___/|  | \/   |  \
|_______ (____  /___|  /__|  \___  >__|  |___|  /
        \/    \/     \/          \/           \/

Lantern 0.0.1
Copyright (C) 2021 Constantin Wenz

  nonce      Request a nonce from Azure.

  cookie     Create a PRT Cookie for further usage or your browser

  token      Play with Azure Tokens

  device     Join a device to Azure

  help       Display more information on a specific command.

  version    Display version information.
```

### Nonce

To request a nonce you can use the following command: 

```PowerShell
Lantern.exe nonce
```

### PRT-Cookie

To create a PRT-Cookie you can use:

```
Lantern.exe cookie --derivedkey <Key from Mimikatz> --context <Context from Mimikatz> --prt <PRT from Mimikatz>
```

### Access Token

To create an access token you can use various combination:

```
Lantern.exe token --derivedkey <Key from Mimikatz> --context <Context from Mimikatz> --prt <PRT from Mimikatz>
```

```
Lantern.exe token --prtcookie <PRT Cookie>
```

```
Lantern.exe token --username <Username> --password <Password>
```

```
Lantern.exe token --refreshtoken <RefreshToken>
```

### DeviceJoin

```
Lantern.exe device --accesstoken (or some combination from the token part) --devicename <Name> --outpfxfile <Some path>
```
