#!/usr/bin/python
# vi:si:et:sw=4:sts=4:ts=4
# -*- coding: UTF-8 -*-
# -*- Mode: Python -*-

import socket
import struct
import shlex
import re
import sys
import select
import ConfigParser
import os
import signal
import logging
import logging.handlers
import cStringIO
import subprocess
from string import Template

from snomprovisioning import sip
from snomprovisioning import daemon

# a workaround to avoid zoombie child in external commands
import signal
signal.signal(signal.SIGCHLD, signal.SIG_IGN)

version = "__VERSION__"

logging.handlers.raiseExceptions = True

logger = logging.getLogger(sys.argv[0])
log_handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
log_handler.setFormatter(formatter)
logger.addHandler(log_handler)
logger.setLevel(logging.INFO)

class Error:
    def __init__(self, message=None):
        if message:
            logger.error(message)
        pass

class UnsupportedSIPVersion(Error): pass
class UnsupportedSIPTransport(Error): pass
class SendDataError(Error): pass
class SystemError(Error): pass
class ConfigError(Error): pass

class Debug:
    def __init__(self, message=None):
        if message:
            logger.debug(message)
        pass

class DebugMessage(Debug): pass

class Info:
    def __init__(self, message=None):
        if message:
            logger.info(message)
        pass

class CreateSocketError(Error): pass

class InfoMessage(Info): pass

class SocketOptionError(Error): pass
class BindSocketError(Error): pass
class InvalidRegexError(Error): pass

class MCastServer:
    def __init__(self, local_ip,
            regex=[r'^SUBSCRIBE\s.*MAC%3a(.*)@.*\n(.*\n)*Event:\s.*model="(.*)";.*\n(.*\n)*'],
            subst=[r'http://provisioning.snom.com/\3/\3.php?mac=\1'], run_commands=[], mcast=True, mport=5060, uport=5060):
    
        self.mcast = mcast
        self.port = mport #listen port for multicast requests
        self.uni_port = uport #source port for unicast requests

        self.local_ip = local_ip
        if self.mcast:
            self.listen_addr = "224.0.1.75"
        else:
            self.listen_addr = local_ip

        DebugMessage("Local unicast IP: %s" % self.local_ip)
        DebugMessage("Multicast listening IP: %s" % self.listen_addr)

        
        self.recvsocket = self._create_mcast_socket()
        self.regex = []

        for x in regex:
            try:
                self.regex.append(re.compile(x, re.MULTILINE))
            except Exception:
                raise InvalidRegexError(x)          

        self.subst = subst
        self.run_commands = run_commands

    def listen(self):
        # Sockets from which we expect to read
        inputs = [self.recvsocket]
        # Sockets to which we expect to write
        outputs = [ ]

        DebugMessage("Starting listening loop")

        while inputs:

            readable, writable, exceptional = select.select(inputs, outputs, inputs)
            # Handle inputs
            for s in readable:
                # is SUBSCRIBE
                if s is self.recvsocket:
                    subscription = self.recvsocket.recv(10240)
                    try:
                        request = sip.Request(subscription)
                        if request.method != "SUBSCRIBE":
                            DebugMessage("Received a non SUBSCIBE: %s" % request.method)
                            continue
                    except sip.SipUnpackError:
                        # NOT a SUBSCRIBE
                        continue

                    matched = self.check_request(request)
                    if matched:
                        response = sip.Response()
                        if self.subst[self.matched_rule_index].startswith("DENY:"):
                            response.reason = ":".join(self.subst[self.matched_rule_index].split(":")[2:])
                            response.status = self.subst[self.matched_rule_index].split(":")[1]
                        elif self.subst[self.matched_rule_index] == "DISCARD":
                            DebugMessage("Ignoring request due to 'DISCARD' rule")
                            continue
                        response.headers['from'] = request.headers['from']
                        response.headers['to'] = request.headers['to']
                        response.headers['call-id'] = request.headers['call-id']
                        response.headers['cseq'] = request.headers['cseq']
                        response.headers['expires'] = 0
                        response.headers['via'] = request.headers['via']
                        response.headers['contact'] = "<sip:%s:%d;transport=udp;handler=dum>" % (self.local_ip, self.uni_port)
                        response.headers['content-length'] = 0  
                        #Regexp parsing via Header: SIP/2.0/UDP 172.16.18.90:5060;rport
                        p = re.compile(r'SIP/(.*)/(.*)\s(.*):([0-9]*);*')
                        m = p.search(request.headers['via'])

                        if m:
                            version = m.group(1)
                            transport = m.group(2)
                            if version != "2.0": 
                                UnsupportedSIPVersion("Unsupported SIP version in Via: header: %s" % version)
                                continue
                            phone_ip = m.group(3)
                            phone_port = m.group(4)
                            #phone_port = "5060"
                        else:
                            Error("Wrong Via: header")
                
                        if transport.upper() == "UDP": 
                            DebugMessage("Creating send socket")
                            try:
                                self.sendsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
                                if self.local_ip == "0.0.0.0":
                                    self.sendsock.connect((phone_ip, int(phone_port)))
                                    ip = self.sendsock.getsockname()[0]
                                    port = self.sendsock.getsockname()[1]
                                    DebugMessage("Sending trough local IP: %s" % ip)
                                    DebugMessage("Using local Port: %s" % port)
                                    response.headers['contact'] = "<sip:%s:%d;transport=udp;handler=dum>" % (ip, port)
                            except Exception, e:
                                CreateSocketError("Cannot create socket: %s" % e)
                                continue
                            try:
                                self.sendsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                                self.sendsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                            except AttributeError:
                                DebugMessage("Cannot set SO_REUSEADDR or SO_REUSEPORT")
                        else:
                            UnsupportedSIPTransport("Unsupported Transport in Via: header")
                            continue

                        if self.local_ip != "0.0.0.0":
                            try:
                                DebugMessage("Binding to local ip:port %s:%s" % (self.local_ip, self.uni_port))
                                self.sendsock.bind((self.local_ip, self.uni_port))
                            except Exception, e:
                                SendDataError("Cannot bind socket to %s:%d: %s" % (self.local_ip, self.uni_port, e))
                        
                        # sent the OK (or 404 if DENY)
                        try:
                            DebugMessage("Sending response to %s:%s : \n%s" % (phone_ip, phone_port, str(response)))
                            self.sendsock.send(str(response))
                        except Exception, e:
                            SendDataError("Cannot send OK/DENY response to %s:%s: %s" % (phone_ip, phone_port, e))
                            self.sendsock.close()
                            continue

                        # if DENY doesn't send the NOTIFY
                        if self.subst[self.matched_rule_index].startswith("DENY:"):
                            self.sendsock.close()
                            continue
                        
                        # create the NOTIFY message
                        cseq = int(request.headers['cseq'].split()[0]) + 2

                        DebugMessage("Forging NOTIFY")      
                        notify = sip.Request()
                        notify.method = "NOTIFY"
                        notify.version ="2.0"
                        notify.uri = "sip:%s:%s" % (phone_ip, phone_port)
                        notify.headers['via'] = request.headers['via']
                        notify.headers['max-forwards'] = 20
                        notify.headers['to'] = request.headers['to']
                        notify.headers['from'] = request.headers['from']
                        notify.headers['call-id'] = request.headers['call-id']
                        notify.headers['cseq'] = "%d NOTIFY" % cseq
                        notify.headers['content-type'] = "application/url"
                        notify.headers['subscription-state'] = "terminated;reason=timeout"
                        notify.headers['event'] = 'ua-profile;profile-type="device";vendor="OEM";model="OEM";version="7.1.19"'
                        
                        try:
                            if self.local_ip == "0.0.0.0":
                                self.sendsock.connect((phone_ip, int(phone_port)))
                                ip = self.sendsock.getsockname()[0]
                                port = self.sendsock.getsockname()[1]
                                DebugMessage("Sending trough local IP: %s" % ip)
                                DebugMessage("Using local Port: %s" % port)
                                notify.headers['contact'] = "<sip:%s:%d;transport=udp;handler=dum>" % (ip, port)
                                subst = Template(self.subst[self.matched_rule_index]).substitute(local_ip=ip)
                                body = self.regex[self.matched_rule_index].sub(subst, str(request))  
                            else:   
                                notify.headers['contact'] = "<sip:%s:%d;transport=udp;handler=dum>" % (self.local_ip, self.uni_port)
                                subst = Template(self.subst[self.matched_rule_index]).substitute(local_ip=local_ip)
                                body = self.regex[self.matched_rule_index].sub(subst, str(request))  
                                
                            notify.body = body
                            notify.headers['content-length'] = "%d" % len(body) 
                            DebugMessage("Sending NOTIFY to %s:%s : \n%s" % (phone_ip, phone_port, str(notify)))
                            self.sendsock.send(str(notify))
                        except Exception, e:
                            SendDataError("Cannot send NOTIFY request to %s:%s: %s" % (phone_ip, phone_port, e))
                        self.sendsock.close()
                
    def check_request(self, request):
        i = 0
        self.matched_rule_index = 0
        res = False
        self.matched_groups = ()
        DebugMessage("Received request")
        DebugMessage("Search:")
        DebugMessage(request)
        for r in self.regex:
            DebugMessage("Evaluating %d rule" % i)
            DebugMessage("Pattern: %s" % r.pattern)
            DebugMessage("Subst: %s" % self.subst[i])
            try:
                #if self.local_ip == "0.0.0.0": 
                    #DebugMessage("Applying temporary local_ip = 0.0.0.0 substitution")
                    #tmp_sub = Template(self.subst[i].substitute(local_ip=local_ip))
                #res = r.sub(self.subst[i], str(request))
                res = r.search(str(request))
            except Exception, e:
                InvalidRegexError("Error applying the regex/subst %d: %s" % (i, e))
                i = i + 1
                continue
            if res == None:
                i = i + 1
                continue
            else:
                InfoMessage("snom PnP matching request found: rule number: %d" % i)
                m = r.search(str(request))
                if m:
                    self.matched_groups = m.groups() 
                #DebugMessage("Result: %s" % res)
                self.matched_rule_index = i
                n = 1
                command_env = {}
                for g in self.matched_groups:
                    command_env["REGEX_GROUP_%d" % n] = g
                    command_env["REGEX"] = r.pattern
                    command_env["SUBST"] = self.subst[i]
                    command_env["RULE_IDX"] = "%d" % i
                    n = n + 1
                if self.run_commands[self.matched_rule_index]:
                    try: 
                        DebugMessage("External command env: %s" % command_env)
                        DebugMessage("Execuding external command: %s" % self.run_commands[self.matched_rule_index])
                        command_pid = subprocess.Popen(shlex.split(self.run_commands[self.matched_rule_index]), env=command_env).pid
                        InfoMessage("Spawned command '%s' with pid %d" % (self.run_commands[self.matched_rule_index], command_pid))
                    except Exception, e:
                        InfoMessage("Error executing command: %s" % e)
                return True
            i = i + 1
        DebugMessage("No Match Found")
        return False

    def _create_mcast_socket(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setblocking(0)
        except Exception, e:
            raise CreateSocketError("Cannot create socket: %s" % e)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except AttributeError:
            pass
        try:
            sock.bind((socket.gethostbyname(self.listen_addr), self.port))
        except Exception, e:
            raise BindSocketError("Cannot bind socket to %s:%d: %s" % (self.listen_addr, self.port, e))
        if self.mcast:
            mreq = struct.pack('4sl', socket.inet_aton(socket.gethostbyname(self.listen_addr)), socket.INADDR_ANY)
            try:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            except socket.error, e:
                raise SocketOptionError("Cannont configure multicast: %s" % e)
        return sock


def get_ip_address(host="snom.com"):
    # This is a simple hack to find our IP address
    # AFAIK this is the only platform-independent way to obtain the address
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect((host, 80))
    ip = s.getsockname()[0]
    s.close()
    return ip

def is_valid_ipv4_address(address):
    try:
        addr= socket.inet_pton(socket.AF_INET, address)
    except AttributeError: # no inet_pton here, sorry
        try:
            addr= socket.inet_aton(address)
        except socket.error:
            return False
        return address.count('.') == 3 #invalidate shortened address (like 127.1)
    except socket.error: # not a valid address
        return False
    return True

def get_ip_address_ifname(iface):
    import fcntl
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', iface[:15])
    )[20:24])

if __name__ == '__main__':
    
    def usage():
        print "\nUsage: %s [options] <config-file>" % sys.argv[0]
        print "\n\tOptions:"
        print "\t\t-c <config-file>\t\tRead a SIP request from stdin and print the response, useful for testing rules"
        print "\t\t-s <config-file>\t\tStart the program"
        sys.exit()
    
    def signal_handler(signal, frame):
        InfoMessage('Killed by SIGTERM. Goodbye.')
        sys.exit(0)

    signal.signal(signal.SIGTERM, signal_handler)


    # TODO: improve command line handling
    if len(sys.argv) < 3:
        print "\nERROR: missing args."
        usage()
    
    if sys.argv[1] not in ["-c", "-s"]:
        print "\nERROR: wrong arg."
        usage()

    config = ConfigParser.RawConfigParser()
    config.read(sys.argv[2])
    
    try:
        debug = config.get('main', 'debug')
        if debug.upper() == 'TRUE':
            logger.setLevel(logging.DEBUG)
            DebugMessage("Log level: DEBUG")
        
    except ConfigParser.NoOptionError:
        pass    
    
    try:
        uport = int(config.get('main', 'unicast_port'))
        DebugMessage("Using %d as unicast port" % int(uport))   
    except ConfigParser.NoOptionError:
        uport = 5060
    try:
        conf_local_ip = config.get('main', 'local_ip')
        if is_valid_ipv4_address(conf_local_ip):
            local_ip = conf_local_ip
            DebugMessage("local_ip: %s" % local_ip)
            
        elif conf_local_ip == "default": #if loca_if == "default" try to reach snom.com
            try:
                local_ip = get_ip_address()
            except Exception, e:
                ConfigError("cannot discover local ip address: %s" % e)
                sys.exit(1)

        else: #network interface name
            try:
                local_ip = get_ip_address_ifname(conf_local_ip)
            except Exception, e:
                ConfigError("cannot determine ip address of %s interface: %s" % (conf_local_ip, e))
                sys.exit(1)

    except ConfigParser.NoOptionError:  
        ConfigError("Missing mandatory parameters in config file, bailing out!")
        sys.exit(1)

    try:
        log_file = config.get('main', 'log_file')       
        if log_file.startswith("syslog"):
            try:
                syslog_host = log_file.split(":")[1]
            except IndexError:
                syslog_host = 'localhost'
            try:
                syslog_port = int(log_file.split(":")[2])
            except IndexError:
                syslog_port = 514
            try:
                syslog_facility = log_file.split(":")[3]
            except IndexError:
                syslog_facility = logging.handlers.SysLogHandler.LOG_USER
            DebugMessage("Logging to syslog (host: %s, port: %s, facility: %s)" % ((syslog_host, syslog_port, syslog_facility)))    
            conf_log_handler = logging.handlers.SysLogHandler((syslog_host, syslog_port), syslog_facility)
        else:
            DebugMessage("Logging to file: %s" % log_file)
            conf_log_handler = logging.FileHandler(log_file)

        conf_log_handler.setFormatter(formatter)
        logger.removeHandler(log_handler)
        logger.addHandler(conf_log_handler)

        InfoMessage("New server started")   
    except ConfigParser.NoOptionError:  
        # no log defined in config file
        pass
    
    regex = []
    subst = []
    run_commands = []

    try:
        rules = sorted([i for i in config.sections() if i.startswith("rule_")], key=lambda num: int(num.split("_")[1]))
    except ValueError, e:
        ConfigError("Invalid rule name: rule name mast be in format rule_XX, where XX is a number, eg. rule_13")
        ConfigError("Config details: %s" % e)
        sys.exit(1)

    InfoMessage("Valuating config sections order: %s" % rules)
        
    for s in rules:
        if s.startswith("rule_"):
            DebugMessage("Rule: %s" % s)
            try:
                reg = config.get(s, 'regex')
                sub = config.get(s, 'subst')
            except ConfigParser.NoOptionError:
                ConfigError("Missing regexp/subst option in %s section" % s)
                sys.exit(1)
            DebugMessage("Regex: %s" % reg)
            ###DebugMessage("Subst: %s" % sub)
            try:
                command = config.get(s, 'command')
                DebugMessage("Command: %s" % command)
            except ConfigParser.NoOptionError:
                command = None

            regex.append(ur'%s' % reg)
            subst.append(ur'%s' % sub)
            run_commands.append(command)
   
    server = MCastServer(local_ip=local_ip, regex=regex, subst=subst, run_commands=run_commands, uport=uport)
    
    if sys.argv[1] == "-c":
        request = "".join(sys.stdin.readlines())
        print "=== Request ==="
        print request
        resp = server.check_request(request)
        if resp:
            print "=== Response NOTIFY body ==="
            print resp
            sys.exit()
        else:
            print "No rules found"
            sys.exit(255)

    if sys.argv[1] == "-s":
        try:
            if config.get('main', 'daemon').upper() == 'TRUE':
                InfoMessage('Daemonizing')
                try:
                    pid_file = config.get('main', 'pid_file')
                    InfoMessage('Using pid file %s' % pid_file)
                    try:
                        pid = daemon.become_daemon(pid_file)
                    except Exception, e:
                        SystemError("Cannot start daemon: %s, exiting" %e)
                        sys.exit(-1)
                except ConfigParser.NoOptionError:
                    try:
                        pid = daemon.become_daemon(None)
                    except Exception, e:
                        SystemError("Cannot start daemon: %s, exiting" %e)
                        sys.exit(-1)
                    InfoMessage('No pid file in configuration file')
                InfoMessage("Daemon started with pid %d" % pid)

        except ConfigParser.NoOptionError:
            InfoMessage('Run in foreground')

        server.listen()
