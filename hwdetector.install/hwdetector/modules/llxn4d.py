#!/usr/bin/env python3
import hwdetector.Detector as Detector
import hwdetector.utils.log as log
import os.path
import os
import json
import re

log.debug(u'File '+__name__+u' loaded')

class LlxN4d(Detector):
    _NEEDS = [u'HELPER_CHECK_OPEN_PORT',u'HELPER_CHECK_NS',u'HELPER_EXECUTE']
    _PROVIDES = [u'N4D_VARS',u'N4D_STATUS',u'N4D_MODULES',u'N4D_LAST_LOG']

    def check_n4d(self,*args,**kwargs):
        output ={}
        output[u'N4D_STATUS']={u'online':str(self.check_open_port(u'9779'))}
        output[u'N4D_STATUS'].update({u'resolvable':str(self.check_ns(u'server'))})

        try:
            since=self.execute(run='systemctl show --value --property=ActiveEnterTimestamp n4d',stderr=None)
            status=''
            status=self.execute(run=['journalctl','-u','n4d','-o','cat','--no-pager','-S',since,'-q'],stderr=None,asroot=True)
            if status:
                status = status.split('\n')
            output['N4D_LAST_LOG']=status
            if status:
                available=[]
                failed=[]
                into_plugins=False
                for line in status:
                    line = line.strip()
                    if not into_plugins and re.search('\[Core\] Initializing plugins',line):
                        into_plugins=True
                    if into_plugins:
                        if re.search('\[Core\] Executing startups',line):
                            break
                        m = re.search(r'(?P<pluginname>\w+)\s+\.{3}\s+(?P<status>\w+)?$',line)
                        if m:
                            d=m.groupdict()
                            if d[u'status'] and d[u'pluginname']:
                                if d[u'status'].lower() == u'ok':
                                    available.append(d[u'pluginname'])
                                else:
                                    failed.append(d[u'pluginname'])
                available=sorted(available)
                failed=sorted(failed)
                output[u'N4D_MODULES']={u'available':dict(zip(available,available)),u'failed':dict(zip(failed,failed))}
            else:
                log.warning('Cannot get n4d journal')
                output['N4D_MODULES']=''
        except Exception as e:
            output[u'N4D_STATUS'].update({u'initlog':u'not available'})
            output[u'N4D_STATUS'].update({u'initlog_error': str(e)})

        return output

    def get_variables(self,*args,**kwargs):
        vars={}
        folder=u'/var/lib/n4d/variables-dir/'
        if os.path.exists(folder):
            for f in os.listdir(folder):
                file=folder+u'/'+f
                try:
                    with open(file,u'r') as f2:
                        vars.update(json.load(f2))
                except Exception as e:
                    vars[f]=u'NOT_READABLE {}'.format(str(e).decode(u'utf-8'))
        return vars

    def run(self,*args,**kwargs):
        output = {}
        output.update({u'N4D_VARS':self.get_variables()})
        output.update(self.check_n4d())
        return output
