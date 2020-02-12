#!/usr/bin/env python3
import hwdetector.Detector as Detector
import hwdetector.utils.log as log

log.debug(u'File '+__name__+u' loaded')

class LlxSystemTest(Detector):
    _NEEDS=[u'LLIUREX_RELEASE',u'SYSTEMCTL_INFO',u'DPKG_INFO',u'APACHE_INFO',u'EPOPTES_INFO',u'DNSMASQ_INFO',u'SQUID_INFO',u'PROCESS_INFO',u'VARLOG_INFO',u'HELPER_SEARCH_PROCESS']
    _PROVIDES=[u'LLXSYSTEM_TEST']

    def make_result(self,*args,**kwargs):
        ret=u''
        if not (u'result' in kwargs and u'msg' in kwargs):
            return
        if isinstance(kwargs[u'result'],list):
            result=kwargs[u'result']
        else:
            result=[unicode(kwargs[u'result'])]

        for x in result:
            ret+=u'{}> {}: {}\n'.format(self.__class__.__name__,x,kwargs[u'msg'])
        return ret

    def run(self,*args,**kwargs):

        release=unicode(kwargs[u'LLIUREX_RELEASE'])
        status=True
        msg=[]

        systemctl=kwargs[u'SYSTEMCTL_INFO']
        needed_services={}
        needed_services_common=[{u'n4d':[u'n4d-server']}]

        map(needed_services.update,needed_services_common)

        if u'server' in release.lower():
            map(needed_services.update,[{u'apache2':[u'apache2']},{u'epoptes':[u'epoptes',u'socat']},{u'dnsmasq':[u'dnsmasq']},{u'slapd':[u'slapd']}])

        res_ok=[]
        res_nok=[]
        ps=kwargs[u'PROCESS_INFO']
        for need in needed_services:
            if need in systemctl[u'BYUNIT'] and systemctl[u'BYUNIT'][need][0][u'SUB'] == u'running':
                res_ok.append(u'Service {}'.format(need))
                plist=self.search_process(needed_services[need])
                for x in plist:
                    res_ok.append(u'{} Process matching \'{}\''.format(len(plist[x]),x))
            else:
                res_nok.append(u'Service {}'.format(need))
                status=False


        msg.append(self.make_result(result=res_ok,msg=u'Ok! Running'))
        msg.append(self.make_result(result=res_nok,msg=u'Nok! Down'))

        msg=u''.join(msg)
        output={u'LLXSYSTEM_TEST':{u'status':status,u'msg':msg}}
        return output
