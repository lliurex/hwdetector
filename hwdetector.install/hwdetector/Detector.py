#!/usr/bin/env python3
from functools import wraps
import hwdetector.utils.log as log
#log.debug(u'File '+__name__+u' loaded')

import dill as pickle
import time
import sys
import traceback


class _Detector(object):
    _PROVIDES=None
    _NEEDS=None

    def __init__(self):
        log.debug(u'Init detector base class')

    def run(self,*args,**kwargs):
        log.warning(u'Running fake run method from base class')
        pass

    def toString(self):
        log.debug(u'Calling toString base class')
        log.debug(u'My name is: {}'.format( __name__))
        log.debug(u'My needs are: {}'.format(self._NEEDS))
        log.debug(u'My provides are: {}'.format(self._PROVIDES))

class Detector(_Detector):
    def runner(func):
        @wraps(func)
        def wrapper(self,*args, **kwargs):
            # first argument is class instance -> u'self'
            # second argument is the first param passed to instance
            ret = None
            try:
                args = args[1:]
                out = kwargs[u'out']
                del kwargs[u'out']
                ret = func(self,*args, **kwargs)
                if ret:
                    for k in ret.keys():
                        if k[0:6].lower() == u'helper':
                            ret[k]=pickle.dumps(ret[k])
                else:
                    pass
                out.send(ret)
            except Exception as e:
                log.error(u'Exception in plugin({}): {}'.format(self.__class__.__name__,e))
                log.error(u'Traceback:\n{}'.format(traceback.format_exc()))
                return None
            return ret

        return wrapper

    @runner
    def _run(self,*args,**kwargs):
        stime=time.time()
        log.debug(u'Running wrapped plugin {}'.format(self.__class__.__name__))
        if u'stderr' in kwargs:
            sys.stderr=kwargs[u'stderr']
        r=self.run(self,*args,**kwargs)
        rtime=time.time()-stime
        log.info(u'Time running wrapped plugin {} = {}'.format(self.__class__.__name__,rtime))
        return r
