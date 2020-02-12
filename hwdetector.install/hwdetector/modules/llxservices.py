#!/usr/bin/env python3
import hwdetector.Detector as Detector
import hwdetector.utils.log as log
import re
import os
import base64,zlib


log.debug(u'File '+__name__+u' loaded')

class LlxServices(Detector):
    _PROVIDES = [u'SYSTEMCTL_INFO',u'APACHE_INFO',u'EPOPTES_INFO',u'DNSMASQ_INFO',u'SQUID_INFO',u'SAMBA_INFO']
    _NEEDS = [u'HELPER_EXECUTE',u'DPKG_INFO',u'N4D_STATUS',u'N4D_MODULES',u'HELPER_UNCOMMENT',u'NETINFO',u'HELPER_COMPRESS_FILE',u'HELPER_COMPACT_FILES',u'HELPER_FILE_FIND_LINE']

    def run(self,*args,**kwargs):
        output={}
        dpkg_info=kwargs[u'DPKG_INFO']
        netinfo=kwargs[u'NETINFO']

        has_apache=False
        if [ x for x in dpkg_info[u'BYNAME'].keys() if x.lower().startswith(u'apache2') ]:
            has_apache=True


        # SYSTEMCTL
        sysctl_out=self.execute(run=u'systemctl --plain --no-legend --no-pager list-units --all -t service')
        info={u'BYUNIT':{},u'BYLOAD':{},u'BYACTIVE':{},u'BYSUB':{},u'RAW':sysctl_out}
        regexp=re.compile(r'(?P<UNIT>[\w\-@]+).service\s+(?P<LOAD>\S+)\s+(?P<ACTIVE>\S+)\s+(?P<SUB>\S+)\s+(?P<NAME>.*$)')
        for line in sysctl_out.split(u'\n'):
            service_info=re.search(regexp,line)
            if service_info:
                d=service_info.groupdict()
                for x in [u'UNIT',u'LOAD',u'ACTIVE',u'SUB']:
                    if d[x] in info[u'BY'+x]:
                        info[u'BY'+x][d[x]].append(d)
                    else:
                        info[u'BY'+x][d[x]]=[d]

        output.update({u'SYSTEMCTL_INFO':info})

        # APACHE
        output.update({u'APACHE_INFO':None})

        if has_apache:
            #apacheconf=u''
            #files=[u'/etc/apache2/apache2.conf',u'/etc/apache2/envvars',u'/etc/apache2/ports.conf']
            #dirs=[u'/etc/apache2/conf-enabled/',u'/etc/apache2/mods-enabled/',u'/etc/apache2/sites-enabled/']
            # for dir in dirs:
            #     if os.path.exists(dir):
            #         for file in os.listdir(dir):
            #             files.append(dir+u'/'+file)
            # for file in files:
            #     if os.path.exists(file):
            #         with open(file,u'r') as f:
            #             apacheconf+=f.read()+u'\n'
            #apacheconf=self.uncomment(apacheconf)
            apacheconf=self.compact_files(path=[u'/etc/apache2/apache2.conf',u'/etc/apache2/envvars',u'/etc/apache2/ports.conf',u'/etc/apache2/conf-enabled/',u'/etc/apache2/mods-enabled/',u'/etc/apache2/sites-enabled/'])
            try:
                syntax=self.execute(run=u'apachectl -t',stderr=u'stdout')
                if u'syntax ok' in syntax.lower():
                    syntax = u'OK'
                mod=self.execute(run=u'apachectl -M -S',stderr=None).split(u'\n')
                modules={}
                ports_used={}
                regexp=re.compile(r'^\s+(?P<module>\S+)\s+\((?P<type>static|shared)\)$')
                regexp2=re.compile(r'^\s+port\s+(?P<PORT>\d+).*$')
                for line in mod:
                    m = re.search(regexp,line)
                    if m:
                        d=m.groupdict()
                        modules.update({d[u'module']:d[u'type']})
                    m = re.search(regexp2,line)
                    if m:
                        ports_used.update(m.groupdict())

                port_in_use=False
                # TODO: CHECK PROCESS NAME FROM PORT
                if u'80' in netinfo[u'netstat'][u'BYPORT']:
                    port_in_use=True
                output.update({u'APACHE_INFO':{u'config':apacheconf,u'syntax':syntax,u'modules':modules,u'PORT_USED':port_in_use}})
            except Exception as e:
                output.update({u'APACHE_INFO':None})
        # EPOPTES

        epoptes_info=None
        has_epoptes=False
        if [ x for x in dpkg_info[u'BYNAME'].keys() if x.lower().startswith(u'epoptes') ]:
            has_epoptes=True
        if has_epoptes:
            epoptes_info={}
            has_epoptes_server=False
            if [ x for x in dpkg_info[u'BYNAME'].keys() if x.lower().startswith(u'n4d-epoptes-server') ]:
                has_epoptes_server=True
            has_epoptes_client=False
            if [ x for x in dpkg_info[u'BYNAME'].keys() if x.lower().startswith(u'n4d-epoptes-client') ]:
                has_epoptes_client=True

            if has_epoptes_server:
                port_in_use=False
                if u'2872' in netinfo[u'netstat'][u'BYPORT']:
                    port_in_use=True
                logfile = None
                file=u'/var/log/epoptes.log'
                if os.path.exists(file):
                    logfile = self.compress_file(file=file)
                epoptes_info={u'logfile':logfile,u'PORT_USED':port_in_use}

        output.update({u'EPOPTES_INFO':epoptes_info})

        # DNSMASQ
        output.update({u'DNSMASQ_INFO':None})
        has_dnsmasq=False
        if [ x for x in dpkg_info[u'BYNAME'].keys() if x.lower() == u'dnsmasq' ]:
            has_dnsmasq=True
        if has_dnsmasq:
            main_conf=self.compact_files(path=[u'/etc/dnsmasq.conf',u'/etc/dnsmasq.d/'])
            lines=self.file_find_line(main_conf,u'conf-dir',u'=',u'.+',multiple_result=True)
            paths=[line[0].split(u'=')[1].strip() for line in lines]
            content=main_conf+u'\n'+self.compact_files(path=paths)
            output.update({u'DNSMASQ_INFO':{u'config':content}})

        # SQUID
        output.setdefault(u'SQUID_INFO',None)
        has_squid=False
        if [ x for x in dpkg_info[u'BYNAME'].keys() if x.lower().startswith(u'squid') ]:
            has_squid=True
        if has_squid:
            main_conf=self.uncomment(u'/etc/squid/squid.conf')
            lines=self.file_find_line(main_conf,u'[^\.]+\.conf"$',multiple_result=True)
            files = [ re.findall(r'[\'\"](\S+)[\'\"]',f[0],re.UNICODE)[0] for f in lines]
            file_contents={}
            file_contents.setdefault(u'/etc/squid/squid.conf',main_conf)
            for file in files:
                file_contents.setdefault(file,self.uncomment(file))
            output.update({u'SQUID_INFO':{u'config':file_contents}})

        #SAMBA
        output.update({u'SAMBA_INFO':None})
        has_samba=False
        if [ x for x in dpkg_info[u'BYNAME'].keys() if x.lower() == u'samba' ]:
            has_samba=True
        if has_samba:
            main_conf=self.uncomment(u'/etc/samba/smb.conf',comments=[u';',u'#'])
            lines=self.file_find_line(main_conf,[[u'include',u'=',u'\S+']])
            paths=[line[0].split(u'=')[1].strip() for line in lines]
            content=main_conf+'\n'+self.compact_files(path=paths)
            resources_local=self.execute(run=u'smbclient -L localhost -N -g',stderr=None)
            resources_server=self.execute(run=u'smbclient -L server -N -g',stderr=None)
            output.update({u'SAMBA_INFO':{u'config':content,u'resources_local':resources_local,u'resources_server':resources_server}})

        return output