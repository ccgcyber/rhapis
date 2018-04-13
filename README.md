![alt tag](http://rhapis-data.appspot.com/hylxewMvLuCRVA4SdeC5FVxH5IB8yeQwNBbodEytie7BOt0MFCUzApSlFxWj81vdw2NehqlbC4dEcilfZJSVl7fllaz6GzdlR2VNll98KEJpK8aGtro11NKjkjLx5QeL3JcCji4BHkWM2LqdyzhfJ4nz9jPzcZEk5vLqIu1eW180VoDaQyaw3wtaX9Oe.png)

<b>RHAPIS - Network Intrusion Detection Systems Simulator</b><br>
http://rhapis-data.appspot.com

[![Build Status](https://travis-ci.org/fsiamp/rhapis.svg?branch=master)](https://travis-ci.org/fsiamp/rhapis)

# Screenshots

![alt tag](https://s9.postimg.cc/euz8x1t2n/screen1.png)

![alt tag](https://s10.postimg.cc/tqxwx76qx/screen2.png)

# Basic Usage

Type HELP in the console in order to see the available commands. RHAPIS is written in Lua language. You need to have installed Lua in order to run RHAPIS.

The first commands that you must enter in order to install a virtual network intrusion detection system are the following:

<b>SET NETIP1</b> [ip address], basic address of network in which NIDS is installed (network counters are 1-6).<br>
<b>SET HOSTIP1</b> [ip address], address of a host inside NIDS (host counters are 1-6).<Br>
<b>INCLUDE config</b>, loads a random configuration file<br>
<b>INCLUDE ruleset</b>, reads a set of rules that will be identified by the intrusion detection system<br>

Now you have activated detectability.

<b>SET ATTHOSTIP1</b> [ip address]. With the current command you set an attacker's identity. In this way, you will be able to make virtual attacks on random destinations by using the command ATTACK afterwards.<br><Br>Host counters are again 1-6.

In order your attacks to be recognized by the intrusion detection system, you need to attack hosts that are part of the established network intrusion detection system. 

For example:<br>
```
SET HOSTIP1 7.7.7.7
ATTACK XSS 7.7.7.7
ATTACK XSS 9.9.9.9
DETECT XSS
```
In the above commands, the attack which will only be identified by NIDS will be that on destination address 7.7.7.7 because this is an active host of the network in which NIDS is installed. <br><br>On the other hand, the attack on 9.9.9.9 will not be detected.

# Simulator Commands

<b>ATTACK</b> [type of attack] [destination IP address] = DOS,XSS,RFI,SQL,SHELL,REMBUFF,MALWARE,BRUTE,ARP,CSRF,MASQUERADE,PROBE,HIJACK

<b>REPEAT</b> [type of attack] = DOS,SHELL,REMBUFF,CSRF,SQL,XSS,ARP,RFI

<b>GENERATE</b> [type of traffic] [number of packets] = IN,OUT,MAL

<b>SEND</b> [type of packets] [number of packets] [destination IP address] = ACK,TCP,RST,FIN,MALF,UDP,SYN

<b>INCLUDE</b> ruleset,config

<b>SET</b> [network/hosts] [IP address] = NETIP1,NETIP2,NETIP3,NETIP4,NETIP5,HOSTIP1,HOSTIP2,HOSTIP3,HOSTIP4,HOSTIP5,HOSTIP6,ATTHOSTIP1,ATTHOSTIP2,ATTHOSTIP3,ATTHOSTIP4,ATTHOSTIP5,ATTHOSTIP6,ATTNETIP1,ATTNETIP2,ATTNETIP3,ATTNETIP4,ATTNETIP4,ATTNETIP5

<b>HIDE/UNHIDE</b> [undetectability] = MIX,DC

<b>ATTEMPT</b> [type of attack] [destination IP address] = DOS,XSS,LDAP,XPATH,SHELL

<b>DETECT</b> [type of attack] = DOS,XSS,RFI,SQL,SHELL,REMBUFF,MALWARE,BRUTE,ARP,CSRF,MASQUERADE,PROBE,HIJACK

<b>ANALYZE</b> [type of data] = HEX/FRAMES

The rest possible commands to be used are:<br> 
<b>ALARMS</b>, <b>VISUALIZE</b>, <b>DATASET</b>, <b>INTRUDERS</b>, <b>HELP</b>, <b>INFO</b>, <b>ANONYMIZE</b>


# Examples
```
ATTACK DOS 7.7.7.7
ATTACK SHELL 2.2.2.2
GENERATE IN 660
DETECT SHELL
GENERATE MAL 1500
ATTACK MALWARE 5.5.5.5
DATASET
ATTEMPT XSS 10.10.10.10
```
Inside the main directory you can find log files for every type of information you enter on RHAPIS console (datasets, alarms, configuration, intruders, etc).
