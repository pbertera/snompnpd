# snompnpd

snom Plug and Play daemon.

snompnpd is a deamon that handle Plug&Play provisioning requests sent by snom phones.

### Features

* multiple matching rules, you can distinguish between phone models, mac address, firmware, ecc..
* multiple network interface support
* custom response (IGNORE or DENY specific requests)
* execution of external commands 

### The process

The PnP process are described [here](http://wiki.snom.com/Features/Auto_Provisioning/PnP).

### Installation

#### Configuration

* you need to modify some variables in CONFIG file:

  * **DESTDIR** defines the installation directory
  * **PYTHON_LIB** defines the directory where all needed python modules will be installed
  * **INITDIR** defines the directory where the init script will be placed
  * **DAEMONDIR** defines where the main script will be placed
  * **CONFDIR** defines the configuration directory
  * **USER** and **GROUP** manages the ownership
  * **PIDFILE** defines where the daemon PID must be saved (some distro requires it in init.d script)
  * **LOGFILE** the logfile
  * **TARGET** defines the distributrion where the daemon is installed, supported values: *rh* and *deb*, this affects the init script

#### Building it

run the comannd

    make install

## Configuring the daemon

The installation process will install a sample configuration file named *snompnpd.conf* in the directory defined by **CONFDIR** into *CONFIG* file.

The config file defines all needed parameters inside the **main** section.
**rule_XX* sections contain matching rules.

#### The main section

**local_ip**: this parameter defines the ip address used in answering the phone requests. Differents values are allowed:

  * *default*: the daemon will autodiscover the local ip reaching an host (snom.com)
  * *xxx.xxx.xxx.xxx*: an IP address: you can insert a local IP address to use as a source address
  * *eth0*: a network interface name: the daemon will use the IP address associated to an interface
  * *0.0.0.0*: using this value the daemon doesn't binds to a specific IP address
  
**unicast_port**: this defines the source port for generated responses (ignored in case of *local_ip=0.0.0.0*)  

**pid_file**: a file where the PID will be stored

**log_file**: here you can insert a file path or a syslog server definition following this syntax: syslog:IP_ADDRESS:PORT:FACILITY

Eg.: *syslog:172.16.18.99:514:local7* will send all messages to the remote syslog on 172.16.18.99, using the 514 UDP port and the local7 facility.

**debug**: here you can insert True or False, use True only during debug purpose

**daemon**: another boolean value, using False the program will start in foreground, useful for debugging purpose

#### Matching rules

Every matching rule is defined by a section named *rule_XX* where XX defines the ordering number. Every rule must contains a *regex* and *subst* statement.

When a SUBSCRIBE request comes the daemon starts looping inside the rules, for each rule the regular expression defined by *regex* is evaluaed against the full SUBSCRIBE (headers and body too). If the pattern is found, a substitution defined by *subst* is applied and the resulting string is used as body in NOTIFY sent by the daemon to the phone.

When a pattern rule is found the evaluation loop stops, so the first matching rule wins.

In subst statement you can use the special placeholder *${local_ip}* this placeholder will be substituted with the local ip address (discovered following same rules of *local_ip* configuration paramether).

For more informations about python regex see: 

* [http://docs.python.org/2/library/re.html](http://docs.python.org/2/library/re.html)
* [http://docs.python.org/2/howto/regex.html](http://docs.python.org/2/howto/regex.html)

##### Denying requests

When subst statement starts with DENY prefix the daemon doesn't send the NOTIFY and reply with a SIP Response code and message extracted from the DENY statement 

Eg.:
 
    subst=DENY:401:Unauthorized you're not allowed

replies with a "SIP/2.0 401 Unauthorized you're not allowed" message

##### Ignoring requests

    subst=DISCARD
    
When subst statement is DISCARD the daemon ignores the matched request: This can be useful in some installation with multiple PnP deamons running in the same network

#### Executing external commands

A rule can contains also a *command* statement that is meant for executing a command in case of a rule matching. The command is executed in a new process, with these environment variables:

* **RULE_IDX**: a number showing the matched rule index
* **REGEX**: the content in matched rule *regex* statement
* **SUBST**: the content in matched rule *subst* statement
* **REGEX_GROUP_X**: a variable for each matching group contained in *regex* statement, the group index is defined by the **X** value.

**NB: Be careful in evauating REGEX_GROUP_ variable in order to avoid any shell injection.** 

## Running the daemon

You can start the daemon trough the init.d script:

    /etc/init.d/snompnpd start

Or manually (after configuring the PYTHNPATH variable according with *PYTHON_LIB* defined in *CONFIG* file):

    export PYTHONPATH=$PYHONPATH:"/opt/snompnpd/lib/python"
    /opt/snompnpd/usr/sbin/snompnpd -s /etc/snompnpd.conf 

## Examples

#### Matching all requests rule

Matching rule:

    regex = (.*\n)*
    subst = http://172.16.16.5
 
SUBSCRIBE Request sent from the phone to **sip.mcast.net**:

    SUBSCRIBE sip:MAC%3a00135E874B49@fake SIP/2.0
    Content-Length: 0
    Via: SIP/2.0/UDP 172.16.18.90:5060;rport
    From: <sip:MAC%3a00135E874B49>;tag=658512961
    Expires: 0
    Accept: application/url
    To: <sip:MAC%3a00135E874B49>
    Contact: <sip:172.16.18.90:5060>
    CSeq: 1 SUBSCRIBE
    Call-ID: 1930770594@ciccio
    Event: ua-profile;profile-type="device";vendor="snom";model="snom720";version="7.1.19"

Messages sent by the daemon to the phone:

SIP 200 OK:

    SIP/2.0 200 OK
    Content-Length: 0
    Via: SIP/2.0/UDP 172.16.18.90:5060;rport
    From: <sip:MAC%3a00135E874B49>;tag=658512961
    Expires: 0
    To: <sip:MAC%3a00135E874B49>
    Contact: <sip:172.16.18.90:53465;transport=udp;handler=dum>
    CSeq: 1 SUBSCRIBE
    Call-ID: 1930770594@ciccio

SIP NOTIFY:

    NOTIFY sip:172.16.18.90:5060 SIP/2.0
    Content-Length: 18
    Via: SIP/2.0/UDP 172.16.18.90:5060;rport
    From: <sip:MAC%3a00135E874B49>;tag=658512961
    Subscription-State: terminated;reason=timeout
    To: <sip:MAC%3a00135E874B49>
    Contact: <sip:172.16.18.90:53465;transport=udp;handler=dum>
    CSeq: 3 NOTIFY
    Max-Forwards: 20
    Call-ID: 1930770594@ciccio
    Content-Type: application/url
    Event: ua-profile;profile-type="device";vendor="snom720";model="snom720";version="7.1.19"
    
    http://172.16.18.5

#### Denying a specific phone model and executing an external command

Matching rule:

    ; DENY snom300 models only
    regex = ^SUBSCRIBE\s.*MAC%3a(.*)@.*\n(.*\n)*Event:\s.*model="snom300";.*\n(.*\n)*
    subst = DENY:401:Unauthorized: go away
    command = /opt/snompnpd/logdeny.sh

The script **/opt/snompnpd/logdeny.sh** (don't forget to make it executable):

	#!/bin/bash
	
	DATE=$(date)
	LOGFILE=/tmp/unwanted-snom300.log
	
	# Regex Rule in config file:
	# regex = ^SUBSCRIBE\s.*MAC%3a(.*)@.*\n(.*\n)*Event:\s.*model="snom300";.*\n(.*\n)*
	#                             ^  ^     ^    ^                               ^    ^
	#                             |  |     |    |                               |    |
	#             $REGEX_GROUP_1 -+--+     |    |                               |    |
	#             $REGEX_GROUP_2 ----------+----+                               |    |
	#             $REGEX_GROUP_2 -----------------------------------------------+----+
	
	PHONE_MAC=$REGEX_GROUP_1
	
	echo "$DATE: request received by $PHONE_MAC" >> $LOGFILE
	
	# DEBUG ONLY: save the environment
	# echo "------START ENV------" >> /tmp/log.txt
	# env >> /tmp/log.txt
	# echo "------STOP ENV------" >> /tmp/log.txt
	# echo "ARGS: $@" >> /tmp/log.txt

SUBSCRIBE Request sent by the phone to **sip.mcast.net**:

    SUBSCRIBE sip:MAC%3a00135E874B49@fake SIP/2.0
    Content-Length: 0
    Via: SIP/2.0/UDP 172.16.18.90:5060;rport
    From: <sip:MAC%3a00135E874B49>;tag=658512961
    Expires: 0
    Accept: application/url
    To: <sip:MAC%3a00135E874B49>
    Contact: <sip:172.16.18.90:5060>
    CSeq: 1 SUBSCRIBE
    Call-ID: 1930770594@ciccio
    Event: ua-profile;profile-type="device";vendor="snom";model="snom300";version="7.1.19"

Messages sent by the daemon to the phone:

    SIP/2.0 401 Unauthorized: go away
    Content-Length: 0
    Via: SIP/2.0/UDP 172.16.18.90:5060;rport
    From: <sip:MAC%3a00135E874B49>;tag=658512961
    Expires: 0
    To: <sip:MAC%3a00135E874B49>
    Contact: <sip:172.16.18.90:55365;transport=udp;handler=dum>
    CSeq: 1 SUBSCRIBE
    Call-ID: 1930770594@ciccio

Content of */tmp/unwanted-snom300.log*:

    Wed Oct 30 12:40:02 CET 2013: request received by 00135E874B49

## Debugging

You can configure the *debug=True* statement in config file and in order to log all SIP messages and daemon activities. Using *daemon=False* the process will not detached, without defining a *log_file* all log messages will be printed on stdout.

## Usage

This software is released for didactical and debugging purposes. You're free to use it at your own risk. You can modify and redistribute this program under the [LGPLv3](http://www.gnu.org/licenses/lgpl-3.0.txt) license terms.

[![Bitdeli Badge](https://d2weczhvl823v0.cloudfront.net/pbertera/snompnpd/trend.png)](https://bitdeli.com/free "Bitdeli Badge")

