#!/usr/bin/env python
import hwdetector.Detector as Detector
import hwdetector.utils.log as log

log.debug(u'File '+__name__+u' loaded')

class LlxInitialization(Detector):
    _NEEDS = [u'HELPER_UNCOMMENT',u'LDAP_MODE',u'HELPER_FILE_FIND_LINE',u'N4D_VARS']
    _PROVIDES = [u'HOSTNAME',u'INTERNAL_INTERFACE',u'EXTERNAL_INTERFACE',u'NFS_INITIALIZATION']



    def run(self,*args,**kwargs):
        output = {}
        ssync_from = None
        n4d_vars=kwargs[u'N4D_VARS']
        output.update({u'HOSTNAME':self.uncomment(u'/etc/hostname')})
        mapping={u'INTERNAL_INTERFACE':u'INTERNAL_INTERFACE',u'EXTERNAL_INTERFACE':u'EXTERNAL_INTERFACE'}
        for search_var in mapping:
            if search_var in n4d_vars and u'value' in n4d_vars[search_var]:
                output.update({mapping[search_var]:n4d_vars[search_var][u'value']})
            else:
                output.update({mapping[search_var]:None})
        line=self.file_find_line(r'/lib/systemd/system/net-server\x2dsync.mountu',r'What = (\d+(?:\.\d+){3}):/net/server-sync')
        if line:
            ssync_from=u''.join(line)
        else:
            ssync_from=None
        output.update({u'NFS_INITIALIZATION':ssync_from})

        return output