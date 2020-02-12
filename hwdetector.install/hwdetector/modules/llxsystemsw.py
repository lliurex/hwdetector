#!/usr/bin/env python3
import hwdetector.Detector as Detector
import hwdetector.utils.log as log
import re


log.debug(u'File '+__name__+u' loaded')

class LlxSystemSW(Detector):
    _PROVIDES = [u'DPKG_INFO',u'APT_SOURCES',u'LLIUREX_TIMESTAMP']
    _NEEDS = [u'HELPER_EXECUTE',u'HELPER_COMPACT_FILES']

    def run(self,*args,**kwargs):
        output={}
        pkg_list=self.execute(run=u'dpkg -l',stderr=None).strip(u'\n')
        dpkg_info={u'BYNAME':{},u'BYSTATUS':{}}
        regexp=re.compile(r'^(?P<STATUS>\w+)\s+(?P<PACKAGE>[^:\s]+)(:(?P<PACKAGE_ARCHITECTURE>\S+))?\s+(?P<VERSION>\S+)\s+(?P<BUILD_ARCHITECTURE>\S+)\s+(?P<DESCRIPTION>.*)$',re.UNICODE)
        for line in pkg_list.split(u'\n'):
            pkg_info=re.search(regexp,line)
            if pkg_info:
                d=pkg_info.groupdict()
                if d[u'PACKAGE_ARCHITECTURE'] == None:
                    d[u'PACKAGE_ARCHITECTURE'] = d[u'BUILD_ARCHITECTURE']
                name = d[u'PACKAGE']
                status = d[u'STATUS']
                del d[u'PACKAGE']
                dpkg_info[u'BYNAME'].setdefault(name,[])
                dpkg_info[u'BYNAME'][name].append(d.copy())
                d[u'NAME']=name
                del d[u'STATUS']
                dpkg_info[u'BYSTATUS'].setdefault(status,{})
                dpkg_info[u'BYSTATUS'][status].setdefault(name,[])
                dpkg_info[u'BYSTATUS'][status][name].append(d)


        output.update({u'DPKG_INFO':dpkg_info})
        output[u'DPKG_INFO'].setdefault(u'RAW',pkg_list)
        output.update({u'APT_SOURCES':self.compact_files(path=[u'/etc/apt/sources.list',u'/etc/apt/sources.list.d/'],regexp=r'[^\.]+\.list$')})
        try:
            output.update({u'LLIUREX_TIMESTAMP':dpkg_info[u'BYNAME'][u'lliurex-version-timestamp'][0][u'VERSION']})
        except:
            output.update({u'LLIUREX_TIMESTAMP':u'NOT_AVAILABLE'})
        return output