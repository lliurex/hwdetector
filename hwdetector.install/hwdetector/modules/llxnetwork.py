#!/usr/bin/env python
import hwdetector.Detector as Detector
import hwdetector.utils.log as log
import re
from os import listdir
from os import environ

log.debug(u'File '+__name__+u' loaded')

class LlxNetwork(Detector):

    _PROVIDES=[u'NETINFO']
    _NEEDS=[u'HELPER_UNCOMMENT',u'HELPER_GET_FILE_FROM_NET',u'HELPER_EXECUTE',u'HELPER_COMPACT_FILES']

    def get_routes(self,*args,**kwargs):
        routes = self.execute(run=u'ip r',stderr=None)
        if not routes:
            return None
        else:
            routes=routes.split(u'\n')
            rt = {}
            rt[u'names'] = {}
            rt[u'names'][u'bynet'] = {}
            rt[u'names'][u'byiface'] = {}
            for line in routes:
                if u'default' in line:
                    m = re.search(r'default via (?P<via>\S+) dev (?P<dev>\w+)', line)
                    d = m.groupdict()
                    if not d[u'dev'] in rt:
                        rt[d[u'dev']] = []
                    rt[d[u'dev']].append({u'src': u'0.0.0.0', u'net': d[u'via']})
                    rt[u'names'][u'default'] = {u'via': d[u'via'], u'dev': d[u'dev']}
                    rt[u'names'][u'gw'] = d[u'via']
                else:
                    m = re.search(
                        r'(?P<net>\S+) dev (?P<dev>\w+)\s+(?:proto kernel\s+)?scope link\s+(?:metric \d+)?(?:src (?P<src>\S+))?',
                        line)
                    d = m.groupdict()
                    if not u'src' in d or d[u'src'] == None:
                        d[u'src'] = u'unknown'
                    if not d[u'dev'] in rt:
                        rt[d[u'dev']] = []
                    rt[d[u'dev']].append({u'src': d[u'src'], u'net': d[u'net']})
                    rt[u'names'][u'byiface'][d[u'src']] = d[u'net']
                    rt[u'names'][u'bynet'][d[u'net']] = d[u'src']

            rt.setdefault(u'RAW',routes)
            return rt

    def get_resolver(self,*args,**kwargs):
        resolv_lines=self.uncomment(u'/etc/resolv.conf')
        output={}
        for line in resolv_lines.split(u'\n'):
            m=re.search(r'(?:nameserver\s+(?P<nameserver>\S+)|search\s+(?P<search>\w+)|domain\s+(?P<domain>\w+))',line)
            if m:
                d=m.groupdict()
                for key in [u'nameserver',u'search',u'domain']:
                    if key in d and d[key] != None:
                        output[key]=d[key]
        output.setdefault(u'RAW',resolv_lines)
        return output


    def get_ifaces(self,*args,**kwargs):
        devs = listdir(u'/sys/class/net/')
        output = {}
        regif = []
        regif.append(r"\d+: (?P<iface>\w+):")
        regif.append(r"mtu (?P<mtu>\d+)")
        regif.append(r"state (?P<state>UNKNOWN|UP|DOWN)")
        regif.append(r"link/(?:loopback|ether) (?P<ether>\S+) brd (?P<bether>\S+)")
        regif.append(
            r'inet (?P<ifaddr>\S+)(?: brd (?P<bcast>\S+))? scope (?:global|host) (?:dynamic )?(?P<type>\w+(?::\w+)?)(\s+valid_lft \S+ preferred_lft \S+\s+)')

        for dev in devs:
            aliasnum = 1
            info = self.execute(run=u'ip addr show '+dev,stderr=None).replace(u'\n', u'')
            for i in range(0, len(regif)):
                m = [x for x in re.finditer(regif[i], info)]
                for x in m:
                    d = x.groupdict()
                    if u'iface' in d:
                        iface = d[u'iface']
                        output[iface] = {}
                    else:
                        if u'type' in d:
                            if u':' in d[u'type']:
                                for x in d:
                                    output[iface].update({u'alias' + str(aliasnum) + u'_' + x: d[x]})
                                aliasnum = aliasnum + 1
                            else:
                                #d.update({u'nalias':0})
                                output[iface].update(d)
                        else:
                            output[iface].update(d)
            if aliasnum > 1:
                output[iface].update({u'nalias': aliasnum - 1})
                aliasnum = 1
#        output.setdefault(u'RAW',self.execute(run=u'ifconfig -a',stderr=None))
        output.setdefault(u'RAW',self.execute(run=u'ip a',stderr=None))
        return output

    def get_proxy(self,*args,**kwargs):
        output={}
        done=False
        for x in environ:
            if u'proxy' in x.lower():
                output[x]=environ[x]
        try:
            output.setdefault(u'RAW_ENVIRON',output.copy())
        except:
            pass

        try:
            o = self.execute(run=u'dconf dump /system/proxy/',stderr=None)
            save_next=False
            prev= None
            skip_line=False
            for line in o.split(u'\n'):
                line=line.strip()
                if line == u'':
                    continue
                if skip_line:
                    skip_line=False
                keys=[u'[/]', u'[http]', u'[https]']
                store_keys=[u'autoconfig',u'http',u'https']
                for keynum in range(len(keys)):
                    if keys[keynum] in line:
                        save_next = True
                        prev = store_keys[keynum]
                        skip_line=True
                        break
                if skip_line:
                    continue
                if save_next:
                    m = re.search(r"(?:autoconfig-url=\u'(?P<autoconfig>\S+)\'|mode=\u'(?P<mode>\w+)\'|host=\u'(?P<host>\S+)\'|port=(?P<port>\d+))",line)
                    if m:
                        d=m.groupdict()
                        if not prev in output:
                            output[prev] = {}
                        for x in d:
                            if d[x] != None:
                                output[prev][x]=d[x]
                    else:
                        save_next=False
                        prev=None
        except Exception as e:
            raise(e)

        if u'autoconfig' in output:
            pacfile=self.get_file_from_net(output[u'autoconfig'][u'autoconfig'])
            if pacfile:
                output[u'autoconfig'][u'pacfile'] = pacfile
            else:
                output[u'autoconfig'][u'pacfile'] = u''

        try:
            output.setdefault(u'RAW_DCONF',o)
        except:
            pass
        return output

    def get_listens(self,*args,**kwargs):
#        netstat_listen=self.execute(run=u'netstat -4tuln',stderr=None).split(u'\n')
        netstat_listen=self.execute(run=u'ss -4tuln',stderr=None).split(u'\n')
        # TODO:CHECK PROCESS USING PORT AND STORE IT
        regexp=re.compile(r'(?P<PROTO>\w+)\s+\d+\s+\d+\s+(?P<LISTEN_ON>[^:\s]+):(?P<PORT>\d+)\s+.*$')
        netstat_info={u'BYPROTO':{},u'BYPORT':{}}
        for line in netstat_listen:
            listen_info = re.search(regexp,line)
            if listen_info:
                d=listen_info.groupdict()
                proto=d[u'PROTO']
                port=d[u'PORT']
                if proto not in netstat_info[u'BYPROTO']:
                    netstat_info[u'BYPROTO'][proto]={}
                if port in netstat_info[u'BYPROTO'][proto]:
                    netstat_info[u'BYPROTO'][proto][port].append(d[u'LISTEN_ON'])
                else:
                    netstat_info[u'BYPROTO'][proto][port]=[d[u'LISTEN_ON']]

                if port not in netstat_info[u'BYPORT']:
                    netstat_info[u'BYPORT'][port]={}
                if proto in netstat_info[u'BYPORT'][port]:
                    netstat_info[u'BYPORT'][port][proto].append(d[u'LISTEN_ON'])
                else:
                    netstat_info[u'BYPORT'][port][proto]=[d[u'LISTEN_ON']]
        netstat_info.setdefault(u'RAW',netstat_listen)
        return netstat_info

    def run(self,*args,**kwargs):
        rt=self.get_routes()
        output=self.get_ifaces()

        for dev in output:
            if u'ifaddr' in output[dev] and output[dev][u'ifaddr']:
                ip=output[dev][u'ifaddr'].split(u'/')[0]
                try:
                    output[dev][u'net']=rt[u'names'][u'byiface'][ip]
                except:
                    pass
        output[u'routes']=rt
        if rt:
            output[u'gw']=rt[u'names'][u'default']
        else:
            output[u'gw']=None

        resolv=self.get_resolver()
        output[u'resolver']=resolv

        proxy=self.get_proxy()
        output[u'proxy']=proxy

        output[u'netstat']=self.get_listens()
        output[u'network_interfaces']=self.compact_files(path=[u'/etc/network/interfaces',u'/etc/network/interfaces.d/'])
        output[u'iptables_rules']=self.execute(run=u'iptables -L',stderr=None,asroot=True)
        forward=self.execute(run=u'sysctl -n net.ipv4.ip_forward',stderr=None)
        if forward == u'1':
            output[u'forwading']=True
        else:
            output[u'forwading']=False
        #s=json.dumps(output)

        return {u'NETINFO':output}
