# Lantern

Latern is a small tool I created to learn about Primary Refresh Token (PRT) of Azure and how to use them. The code is mainly copied from [auth.py](https://github.com/dirkjanm/ROADtools/blob/master/roadlib/roadtools/roadlib/auth.py) of [roadtools](https://github.com/dirkjanm/ROADtools) from [Dirk-Jan](https://twitter.com/_dirkjan) and ported to c#. All credits goes to him.

How Azure PRT works is mainly described in these two articles:

* [https://dirkjanm.io/abusing-azure-ad-sso-with-the-primary-refresh-token/](https://dirkjanm.io/abusing-azure-ad-sso-with-the-primary-refresh-token/)
* [https://dirkjanm.io/digging-further-into-the-primary-refresh-token/](https://dirkjanm.io/digging-further-into-the-primary-refresh-token/)

## Compiling

The is built with VisualStudio 2019 and .NetCore. Simple open the project and compile it. 

## Usage

### Nonce

To ask for a Azure nonce you can use the following command: 

```PowerShell
Lantern.exe --asknonce
```

### PRT-Cookie

To create a PRT-Cookie you can use:

```
Lantern.exe --askcookie --derivedkey <Key from Mimikatz> --context <Context from Mimikatz> --prt <PRT from Mimikatz>
```

### Access Token

To create an access token you can use various combination:

```
Lantern.exe --asktoken --derivedkey <Key from Mimikatz> --context <Context from Mimikatz> --prt <PRT from Mimikatz>
```

```
Lantern.exe --asktoken --prtcookie <PRT Cookie>
```

```
Lantern.exe --asktoken --username <Username> --password <Password>
```

```
Lantern.exe --asktoken --refreshtoken <RefreshToken>
```

