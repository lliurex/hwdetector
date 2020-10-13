#!/usr/bin/env python3
import hwdetector.Detector as Detector
import hwdetector.utils.log as log
import os

log.debug(u'File '+__name__+u' loaded')

class LlxVersion(Detector):
    _PROVIDES=[u'LLIUREX_VERSION',u'LLIUREX_RELEASE',u'LLIUREX_SESSION_TYPE',u'HAS_MIRROR',u'ARCHITECTURE',u'LOGIN_TYPE']
    _NEEDS = [u'HELPER_EXECUTE']
    def run(self,*args,**kwargs):
        d={}
        output={}
        output.setdefault(u'LLIUREX_VERSION',None)
        output[u'ARCHITECTURE']=self.execute(run=u'arch',stderr=None)
        try:
            os.stat('/usr/bin/lliurex-version')
        except:
            log.warning('/usr/bin/lliurex-version NOT INSTALLED')
            output.update({'LLIUREX_VERSION':'Non lliurex'})
            output.update({'LLIUREX_RELEASE':'Non lliurex'})
            output.update({'LLIUREX_SESSION_TYPE':'Non lliurex'})
            output.update({'HAS_MIRROR':False})
            output.update({'LOGIN_TYPE':'Unknown'})
            return output

        output.update({u'LLIUREX_VERSION':self.execute(run=u'lliurex-version -n',stderr=None)})
        try:
            for k,v in [ x.split(u'=') for x in self.execute(run=u'lliurex-version -a -e',stderr=None).replace(u'\n',u' ').split(u' ') ]:
                d[k]=v
        except:
            pass

        output.setdefault(u'LLIUREX_RELEASE',None)
        for x in [u'CLIENT',u'DESKTOP',u'SERVER',u'INFANTIL',u'MUSIC',u'PIME']:
            if x in d and d[x].lower() == u'yes':
                output[u'LLIUREX_RELEASE']=x

        output.setdefault(u'LLIUREX_SESSION_TYPE',None)
        for x in [u'LIVE',u'SEMI',u'FAT',u'THIN']:
            if x in d and d[x].lower() == u'yes':
                output[u'LLIUREX_SESSION_TYPE']=x

        if u'MIRROR' in d and d[u'MIRROR'].lower() == u'true':
            output[u'HAS_MIRROR'] = True
        else:
            output[u'HAS_MIRROR'] = False

        output.setdefault(u'LOGIN_TYPE',None)
        if u'LOGIN_TYPE' in d:
            output[u'LOGIN_TYPE']=d[u'LOGIN_TYPE']

        output[u'ARCHITECTURE']=self.execute(run=u'arch',stderr=None)

        return output