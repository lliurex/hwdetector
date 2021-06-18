#!/usr/bin/env python3
import hwdetector.Detector as Detector
import hwdetector.utils.log as log

log.debug(u'File '+__name__+u' loaded')

class LlxNetworkTest(Detector):
    _NEEDS=[u'NETINFO',u'RESOLVER_INFO',u'HELPER_CHECK_PING',u'LLIUREX_RELEASE',u'HELPER_GET_FILE_FROM_NET']
    _PROVIDES=[u'LLXNETWORK_TEST',u'NETINFO']
    #_PROVIDES=[u'NETINFO']

    def make_result(self,*args,**kwargs):
        ret=u''
        if not (u'result' in kwargs and u'msg' in kwargs):
            return
        if type(kwargs[u'result']) == type(list()):
            result=kwargs[u'result']
        else:
            result=[str(kwargs[u'result'])]
    
        for x in result:
            ret+=u'{}> {}: {}\n'.format(self.__class__.__name__,x,kwargs[u'msg'])
        return ret

    def run(self,*args,**kwargs):

        msg=[]
        status=True

        netinfo=kwargs[u'NETINFO']
        resolution=kwargs[u'RESOLVER_INFO']
        release=str(kwargs[u'LLIUREX_RELEASE']).lower()

        # CHECK NETWORK STATUS

        ifaces = [x for x in netinfo.keys() if x.startswith(u'eth')]
        for x in ifaces:
            if netinfo[x][u'state'].lower() == u'up':
                msg.append(self.make_result(result=x,msg=u'Ok! it\'s up (link-detected)'))
            else:
                msg.append(self.make_result(result=x,msg=u'Nok ! it\'s down (no-link)'))
                status=False

        try:
            gw=netinfo[u'gw'][u'via']
            if self.check_ping(gw):
                msg.append(self.make_result(result=gw,msg=u'Ok! gateway it\'s reachable'))
            else:
                status=False
                raise Exception()
        except:
            status=False
            msg.append(self.make_result(result=x,msg=u'Nok! gateway not reachable'))

        try:
            gw=netinfo[u'gw'][u'via']
            if self.check_ping(gw):
                netinfo[u'gw'][u'reachable']=True
            else:
                netinfo[u'gw'][u'reachable']=False
        except:
            pass

        netinfo[u'internet']={}
        try:
            netinfo[u'internet'].setdefault(u'ping',self.check_ping(u'8.8.8.8'))
            netinfo[u'internet'].setdefault(u'http_get',False)
            if self.get_file_from_net(u'http://lliurex.net',False):
                netinfo[u'internet'][u'http_get']=True
        except:
            pass

        if not netinfo[u'internet'].get(u'http_get'):
            try:
                proxydata={}
                if netinfo[u'proxy'][u'autoconfig'] and netinfo[u'proxy'][u'autoconfig'].get(u'mode',None) == u'auto':
                    proxydata.setdefault(u'proxy',True)
                else:
                    if u'http' in netinfo[u'proxy'] and netinfo[u'proxy'][u'http']:
                        proxydata.setdefault(u'proxy_http',netinfo[u'proxy'][u'http'])
                        proxydata.setdefault(u'proxy',True)
                    if u'https' in netinfo[u'proxy'] and netinfo[u'proxy'][u'https']:
                        proxydata.setdefault(u'proxy_https',netinfo[u'proxy'][u'https'])
                        proxydata.setdefault(u'proxy',True)
                    if u'proxy_http' in netinfo[u'proxy']:
                        proxydata.setdefault(u'proxy_http',netinfo[u'proxy'][u'http_proxy'])
                        proxydata.setdefault(u'proxy',True)
                    if u'proxy_https' in netinfo[u'proxy']:
                        proxydata.setdefault(u'proxy_https',netinfo[u'proxy'][u'https_proxy'])
                        proxydata.setdefault(u'proxy',True)

                netinfo[u'internet'][u'http_get']= False
                if self.get_file_from_net(u'http://lliurex.net',**proxydata):
                    netinfo[u'internet'][u'http_get']= True
            except:
                pass


            #netinfo[u'name_resolution']=
        def check_internet(msg,proxy=False):
            try:
                if proxy or self.check_ping(u'8.8.8.8'):
                    if not proxy:
                        msg.append(self.make_result(result=u'Internet ICMP',msg=u'Ok! conectivity available'))
                    if self.get_file_from_net(u'http://lliurex.net',proxy):
                        msg.append(self.make_result(result=u'Lliurex.net',msg=u'Ok! conectivity available'))
                    else:
                        msg.append(self.make_result(result=u'Lliurex.net',msg=u'Nok! conectivity not available'))
                else:
                    raise Exception()
            except Exception as e:
                msg.append(self.make_result(result=u'Internet ICMP',msg=u'Nok! connectivity not available'))
            return msg

        if release != u'client':
            check_internet(msg)
        else:
            try:
                mode= netinfo[u'proxy'][u'autoconfig'][u'mode']
                if mode == u'auto':
                    pac=netinfo[u'proxy'][u'autoconfig']
                    if netinfo[u'proxy'][u'autoconfig'][u'pacfile'] != u'NOT_AVAILABLE':
                        msg.append(self.make_result(result=u'Proxy autoconfig',msg=u'Ok! Pac file available'))
                        check_internet(msg,True)
                    else:
                        msg.append(self.make_result(result=u'Proxy autoconfig',msg=u'Nok! file not available'))
                elif mode != u'none':
                    check_internet(msg,True)
            except Exception as e:
                msg.append(self.make_result(result=u'Proxy',msg=u'not using proxy'))
                check_internet(msg)

        # CHECK NAME RESOLUTION

        if resolution[u'UNRESOLVED']:
            msg.append(self.make_result(result=resolution[u'UNRESOLVED'],msg=u'Nok ! not resolvable'))
            status=False
        if resolution[u'RESOLVED']:
            msg.append(self.make_result(result=resolution[u'RESOLVED'],msg=u'Ok ! it\'s resolvable'))
            if resolution[u'UNREACHABLE']:
                msg.append(self.make_result(result=resolution[u'UNREACHABLE'],msg=u'Nok ! not reachable'))
                status=False
            else:
                msg.append(self.make_result(result=resolution[u'REACHABLE'],msg=u'Ok! it\'s reachable'))

        msg=u''.join(msg)
        output={}
        output[u'NETINFO']=netinfo
        output[u'LLXNETWORK_TEST']={u'status':status,u'msg':msg}
        return output
