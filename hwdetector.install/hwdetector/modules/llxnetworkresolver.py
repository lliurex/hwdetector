#!/usr/bin/env python3
import hwdetector.Detector as Detector
import hwdetector.utils.log as log
import re

log.debug(u'File '+__name__+u' loaded')

class LlxNetworkResolver(Detector):

    _PROVIDES=[u'RESOLVER_INFO']
    _NEEDS=[u'LLIUREX_RELEASE',u'LLIUREX_SESSION_TYPE',u'HELPER_CHECK_OPEN_PORT',u'HELPER_CHECK_ROOT',u'HELPER_CHECK_NS',u'LDAP_MODE',u'HELPER_CHECK_PING',u'LDAP_MASTER_IP',u'N4D_VARS']

    def __init__(self,*args,**kwargs):
        self.output={u'RESOLVED': [] ,u'UNRESOLVED':[],u'REACHABLE':[],u'UNREACHABLE':[],u'STATUS':True}

    def addr_checks(self,*args,**kwargs):
        ns=str(args[0])
        ret=False
        only_ip = re.findall(r'\d+\.\d+\.\d+\.\d+',ns)
        go_to_ping = True

        if only_ip:
            ip = ns
        else:
            ip=self.check_ns(ns)
            if ip:
                self.output[u'RESOLVED'].append(ns)

            else:
                self.output[u'UNRESOLVED'].append(ns)
                go_to_ping=False

        if go_to_ping:
            if only_ip:
                ns=u''
            else:
                ns=u'({})'.format(ns)
            if self.check_ping(ip):
                self.output[u'REACHABLE'].append(u'{} {}'.format(ip,ns))
                ret=True
            else:
                self.output[u'UNREACHABLE'].append(u'{} {}'.format(ip,ns))

        return ret

    def run(self,*args,**kwargs):
        release=kwargs[u'LLIUREX_RELEASE']
        if release:
            release=release.lower()
        session=kwargs[u'LLIUREX_SESSION_TYPE']
        if session:
            session = session.lower()
        ldap_mode=kwargs[u'LDAP_MODE']
        if ldap_mode:
            ldap_mode=ldap_mode.lower()
        ldap_master_ip=kwargs[u'LDAP_MASTER_IP']
        n4d_vars=kwargs[u'N4D_VARS']

        nslist=[u'server']

        if release == u'server': # SERVERS
            if ldap_mode == u'slave':
                if ldap_master_ip:
                    nslist.append(ldap_master_ip)
                else:
                    # if self.check_root():
                    #     # if i'm root and is not set ldap_master_ip, there is an error
                    #     # If i'm not root, ldap_master_ip is impossible to get from ldap
                    #     self.output[u'STATUS']=False

                    if n4d_vars[u'MASTER_SERVER_IP'] and n4d_vars[u'MASTER_SERVER_IP'][u'value']:
                        nslist.append(n4d_vars[u'MASTER_SERVER_IP'][u'value'])
                    # else:
                    #     self.output[u'STATUS']=False

            elif ldap_mode == u'independent':
                pass
            elif ldap_mode == u'master':
                pass
            else:
                pass
        elif release == u'client': # CLIENTS
            pass
        else: # OTHERS
            pass

        nslist.extend([u'pmb',u'opac',u'proxy',u'owncloud',u'jclic-aula',u'cups',u'share',u'mirror',u'preseed',u'www',u'ntp',u'srv',u'servidor',u'lliurexlab',u'error',u'ipxeboot',u'admin-center',u'lliurex-mirror'])
        for ns in nslist:
            r = self.addr_checks(ns)
            # if not r:
            #     self.output[u'STATUS']=False

        return {u'RESOLVER_INFO': self.output}




