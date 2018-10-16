#!/usr/bin/env python
import hwdetector.Detector as Detector
import hwdetector.utils.log as log
import re

log.debug(u'File '+__name__+u' loaded')

# class Object(object):
#     def search(self,*args,**kwargs):
#         f=lambda n: [ x for x in self.output if n in x[u'FULL_CMD']]
#         l=[]
#         for x in args:
#             if type(x) == type(list()):
#                 l.extend(x)
#             else:
#                 l.extend([x])
#
#         ret={}
#         for i in l:
#             list_proc_matched=f(i)
#             if list_proc_matched:
#                 ret[i]=list_proc_matched
#             else:
#                 ret[i]=None
#         return ret

class LlxProcess(Detector):

    _PROVIDES = [u'PROCESS_INFO',u'HELPER_SEARCH_PROCESS',u'PROCESS_INFO_RAW']
    _NEEDS = [u'HELPER_EXECUTE']

    def search_process(self,*args,**kwargs):
        plist=args[0]
        f=lambda n: [ x for x in plist if n in x[u'FULL_CMD']]
        l=[]
        for x in args[1:]:
            if isinstance(x,list):
                l.extend(x)
            else:
                l.extend([x])
        ret={}
        for i in l:
            list_proc_matched=f(i)
            if list_proc_matched:
                ret[i]=list_proc_matched
            else:
                ret[i]=None
        return ret

    def run(self,*args,**kwargs):
        output=[]

        psout=self.execute(run=u'ps --no-headers -Awwo pid,euid,egid,args')
        regexp=re.compile(r'(?P<PID>\d+)\s+(?P<EUID>\d+)\s+(?P<EGID>\d+)\s+(?P<FULL_CMD>.*)$',re.UNICODE)
        for line in psout.split(u'\n'):
            m=re.search(regexp,line)
            if m:
                output.append(m.groupdict())

        #o=Object()
        #o.output=output

        return {u'PROCESS_INFO': output, u'PROCESS_INFO_RAW':psout,u'HELPER_SEARCH_PROCESS': {u'code':self.search_process,u'glob':globals()}}