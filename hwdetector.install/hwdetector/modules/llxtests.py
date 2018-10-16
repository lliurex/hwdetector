#!/usr/bin/env python
import hwdetector.Detector as Detector
import hwdetector.utils.log as log
import sys

log.debug(u'File '+__name__+u' loaded')

class LlxAlltests(Detector):
    _NEEDS=[u'LLXSYSTEM_TEST',u'LLXNETWORK_TEST',u'LLXUSERS_TEST']
    _PROVIDES=[u'ALL_TESTS']

    def run(self,*args,**kwargs):
        ret=True
        for test in self._NEEDS:
            if kwargs[test][u'status']:
                pass
                #sys.stderr.write(u'{}>>>Testing {} was OK!\n'.format(kwargs[test][u'msg'],test))
            else:
                pass
                #sys.stderr.write(u'{}>>>Testing {} was Failed!\n'.format(kwargs[test][u'msg'],test))
                ret=False
        output={u'ALL_TESTS':ret}
        return output