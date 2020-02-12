#!/usr/bin/env python3
import hwdetector.Detector as Detector
import hwdetector.utils.log as log
import json
import subprocess

log.debug(u'File '+__name__+u' loaded')

class CTest(object):
    def __init__(self,*args,**kwargs):
        try:
            val=int(args[0])
        except:
            val = 10
        self.attrib=range(val)

    def toString(self,*args,**kwargs):
        status=True
        if u'range' in kwargs:
            range_val=int(kwargs[u'range'])
            self.attrib=range(range_val)
            status=False

        for x in self.attrib:
            print (x)

        return status

def toString2(*args,**kwargs):
    try:
        for x in self.attrib:
            print (x)
        return True
    except:
        for x in range(1,3):
            print (x)
        return True
    return False

class DetectorObject(object):
    pass

class LlxTest(Detector):

    #_PROVIDES = [u'TEST',u'HELPER_ECHO']
    _PROVIDES = [u'TEST']
    _NEEDS = []

    # def echo(*args,**kwargs):
    #     c=0
    #     o=subprocess.check_output([u'ls'])
    #     for x in args:
    #         c = c + x
    #     print(c)
    #     return o

    def run(self,*args,**kwargs):
        #param=kwargs[u'NETINFO'].upper().replace(u'NULL',u'null')
        #netinfo=json.loads(param)
        #netinfo2=param
        #e = self.echo
        #return {u'TEST':netinfo[u'LO'],u'HELPER_ECHO': {u'code':e,u'glob':globals()}}
        #t=CTest(5)
        #return {u'TEST':  t}
        ####t=DetectorObject()
        ####setattr(t,u'attrib',range(10))
        #t.attrib=range(10)
        ####t.to_string = toString2
        return {u'TEST':u''}