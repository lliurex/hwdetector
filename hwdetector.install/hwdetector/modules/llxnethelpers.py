#!/usr/bin/env python3
import hwdetector.Detector as Detector
import hwdetector.utils.log as log
import re
import socket
import subprocess
import os


log.debug(u'File '+__name__+u' loaded')

class LlxNetHelpers(Detector):
    _PROVIDES = [u'HELPER_CHECK_OPEN_PORT',u'HELPER_CHECK_NS',u'HELPER_CHECK_PING']
    _NEEDS = []

    def check_open_port(self,*args,**kwargs):
        if len(args) > 2 or len(args) == 0:
            return
        if len(args) == 1:
            port = str(args[0])
            host=u'127.0.0.1'
            m=re.search(r'^\d+$',port)
            if m:
                port=int(args[0])
            else:
                log.warning(u'Trying to check open port with no numerical value host=\'{}\' port\'{}\''.format(host,port))
                return False
        else:
            host=str(args[0])
            #split protocol if there is something
            host=re.findall(r'(?:[^/]+/+)?(.*)$',host)[0]
            m = re.search(r'^(\d+(?:\.\d+){3})$',host)
            if not m:
                if not self.check_ns(host):
                    return False
            port=str(args[1])
            m = re.search(r'^\d+$', port)
            if m:
                port = int(port)
            else:
                log.warning(u'Trying to check open port with no numerical value host=\'{}\' port\'{}\''.format(host,port))
                return False

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        try:
            res = sock.connect_ex((host,port))
        except:
            log.warning(u'Timeout connection to {}:{}'.format(host,port))
            return None
        finally:
            sock.close()

        if res == 0:
            return True
        else:
            return False

    def check_ns(self,*args,**kwargs):
        if len(args) > 1:
            return None
        try:
            ip=socket.gethostbyname(unicode(args[0]))
            return ip
        except:
            log.warning(u'Fail checking dnsname {}'.format(args[0]))
            return False

    def check_ping(selfs,*args,**kwargs):
        if len(args) != 1:
            return None
        ret=False
        try:
            r=subprocess.check_call([u'ping',u'-W1',u'-c1',str(args[0])],stderr=open(os.devnull,u'w'),stdout=open(os.devnull,u'w'))
            if r==0:
                ret=True
        except:
            pass
        return ret

    def run(self,*args,**kwargs):
        return {u'HELPER_CHECK_OPEN_PORT':{u'code':self.check_open_port,u'glob':globals()},
                u'HELPER_CHECK_NS':{u'code':self.check_ns,u'glob':globals()},
                u'HELPER_CHECK_PING':{u'code':self.check_ping,u'glob':globals()}
                }