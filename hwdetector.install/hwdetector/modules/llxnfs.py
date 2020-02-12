#!/usr/bin/env python3
import hwdetector.Detector as Detector
import hwdetector.utils.log as log
import os.path
import re

log.debug(u'File '+__name__+u' loaded')

class LlxNfs(Detector):
    _NEEDS = [u'HELPER_UNCOMMENT',u'HELPER_EXECUTE']
    _PROVIDES = [u'NFS_INFO']

    def check_exports(self,*args,**kwargs):
        files=[]
        if os.path.isfile(u'/etc/exports'):
            files.append(u'/etc/exports')

        if os.path.isdir(u'/etc/exports.d'):
            for file in os.listdir(u'/etc/exports.d/'):
                files.append(u'/etc/exports.d/'+file)
        content=[]
        for file in files:
            with open(file,u'r') as f:
                content.extend(self.uncomment(f.read()))
        if content:
            content=u'\n'.join(content)
        else:
            content= None
        needed_services=[u'portmapper',u'mountd',u'nfs',u'nlockmgr',u'status']
        services_running=self.execute(run=u'rpcinfo -p',stderr=None)
        if services_running:
            reg=re.compile(r'\s+\d+\s+\d+\s+\w+\s+\d+\s+(\w+)*',re.UNICODE)
            for s in services_running.split(u'\n'):
                m = re.findall(reg,s)
                if m:
                    if m[0] in needed_services:
                        needed_services.remove(m[0])
        if needed_services:
            needed_services=None
        else:
            needed_services=True
        if needed_services:
            exported = self.execute(run=u'showmount -e --no-headers',stderr=None)
            if exported:
                exported = exported.split(u'\n')
            else:
                exported=None
        else:
            exported=None

        return {u'FILES':files,u'CONTENT':content,u'EXPORTED':exported}

    def run(self,*args,**kwargs):
        output ={u'NFS_INFO':u'OK'}
        output.update(self.check_exports())
        return output