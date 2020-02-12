#!/usr/bin/env python3
import hwdetector.Detector as Detector
import hwdetector.utils.log as log
import json
import os
import re
import base64
import zlib

log.debug(u'File '+__name__+u' loaded')

class LlxSystemInfo(Detector):
    _NEEDS=[u'HELPER_EXECUTE',u'HELPER_COMPRESS_FILE',u'HELPER_LIST_FILES',u'HELPER_UNCOMMENT']
    _PROVIDES=[u'LSHW_INFO',u'DMESG_INFO',u'VARLOG_INFO',u'LSUSB_INFO',u'DMESG_JOURNAL_INFO',u'SYSCTL_INFO',u'PAM_INFO',u'SUDO_INFO',u'ALTERNATIVES_INFO',u'ENVIRONMENT']

    def get_lshw(self,*args,**kwargs):
        try:
            lsusb=json.loads(self.execute(run=u'lshw -json',stderr=None))
            return {u'JSON':lsusb,u'RAW':self.execute(run=u'lshw',stderr=None)}
        except Exception as e:
            return None

    def get_dmesg(self,*args,**kwargs):
        try:
            dmesg=self.execute(run=u'journalctl --dmesg --no-pager --reverse --since today',asroot=True,stderr=None)
            return dmesg
        except Exception as e:
            return None

    def get_dmesg2(self,*args,**kwargs):
        try:
            dmesg=self.execute(run=u'dmesg',stderr=None)
            return dmesg
        except Exception as e:
            return None

    def get_varlog(self,*args,**kwargs):
        varlog={}
        regexp=re.compile(r'^[^\.]+(\.log|(\.\d+)+)?$',re.UNICODE)
        #filter=lambda x: [ f for f in x if re.match(regexp,f)]

        try:
            #prefix=u'/var/log'
            #file_names=[]
            #for root,dirnames,filenames in os.walk(prefix):
            #    for filename in filter(filenames):
            #        file_names.append(os.path.join(root,filename))
            file_names=self.list_files(path=u'/var/log',regexp=regexp)
            exceptions=[u'/var/log/lastlog',u'/var/log/wtmp',u'/var/log/wtmp.1']
            file_names=[ x for x in file_names if x not in exceptions]
            for file in file_names:
                comp=self.compress_file(file=file)
                if comp:
                    varlog[file]=comp
                else:
                    log.warning(u'Fail compressing logfile {}'.format(file))
        except Exception as e:
            pass
        return varlog

    def get_lsusb(self,*args,**kwargs):
        lsusb={}
        try:
            lsusb=self.execute(run=u'lsusb',stderr=None)
            return lsusb
        except Exception as e:
            return None

    def get_sysctl(self,*args,**kwargs):
        def make_hierarchy(d={},l=[],value=None):
            if len(l) > 1:
                d.setdefault(l[0],{})
                return make_hierarchy(d[l[0]],l[1:],value)
            else:
                return d.setdefault(l[0],value)
        d={}
        raw_info=self.execute(run=u'sysctl -a',stderr=None)
        if raw_info:
            for key_value in raw_info.split(u'\n'):
                key,value=key_value.split(u' = ')
                make_hierarchy(d,key.split(u'.'),value)
        d.setdefault(u'RAW',raw_info)
        return d

    def get_pams(self,*args,**kwargs):
        files=self.list_files(path=[u'/etc/pam.conf',u'/etc/pam.d/',u'/usr/share/pam-configs/'])
        d={}
        for file in files:
            d.setdefault(file,self.uncomment(file))
        return d

    def get_sudoers(self,*args,**kwargs):
        files=self.list_files(path=[u'/etc/sudoers',u'/etc/sudoers.d/'])
        d={}
        for file in files:
            d.setdefault(file,self.uncomment(file))
        return d

    def get_alternatives(self,*args,**kwargs):
        return self.execute(run=u'update-alternatives --get-selections')

    def run(self,*args,**kwargs):
        output={u'LSHW_INFO':{},u'DMESG_INFO':{},u'SYSLOG_INFO':{},u'LSUSB_INFO':{}}

        output[u'LSHW_INFO']=self.get_lshw()
        output[u'DMESG_INFO']=self.get_dmesg2()
        output[u'DMESG_JOURNAL_INFO']=self.get_dmesg()
        output[u'VARLOG_INFO']=self.get_varlog()
        output[u'LSUSB_INFO']=self.get_lsusb()
        output[u'SYSCTL_INFO']=self.get_sysctl()
        output[u'PAM_INFO']=self.get_pams()
        output[u'SUDO_INFO']=self.get_sudoers()
        output[u'ALTERNATIVES_INFO']=self.get_alternatives()
        output[u'ENVIRONMENT']=dict(os.environ)
        return output