#!/usr/bin/env python3
import sys
import logging
import tempfile
import os

try:
    import colorlog
except:
    pass

class logger(logging.getLoggerClass()):
    def __init__(self,*args,**kwargs):
        self.l = None
        self.color = False
        self.level = logging.INFO
        self.disabled = False
        self.filename_to_log = tempfile.mkstemp()[1] + u'.txt'
        super(logger,self).__init__(*args,**kwargs)

    def __exit__(self, exc_type, exc_value, traceback):
        if os.path.exists(self.filename_to_log):
            os.remove(self.filename_to_log)

    def initLog(self,*args,**kwargs):
        if self.l:
            self.l.handlers = []
        if self.color:
            try:
                colorlog.basicConfig(
                    level=self.level,
                    #format=u'[%(asctime)s] %(levelname)s [%(filename)s.%(funcName)s:%(lineno)d] %(message)s',
                    format=u'%(log_color)s[%(asctime)s:%(msecs)d] %(levelname)s [%(filename)s:%(lineno)d] [%(processName)s] %(message)s %(reset)s',
                    datefmt=u'%H:%M] [%S',
                    stream=sys.stderr
                )
            except:
                logging.basicConfig(
                    level=self.level,
                    #format=u'[%(asctime)s] %(levelname)s [%(filename)s.%(funcName)s:%(lineno)d] %(message)s',
                    format=u'[%(asctime)s:%(msecs)d] %(levelname)s [%(filename)s:%(lineno)d] [%(processName)s] %(message)s',
                    datefmt=u'%H:%M] [%S',
                    stream=sys.stderr
                )
            try:
                self.l = colorlog.getLogger()
            except:
                self.l = logging.getLogger()
        else:
            logging.basicConfig(
                level=self.level,
                #format=u'[%(asctime)s] %(levelname)s [%(filename)s.%(funcName)s:%(lineno)d] %(message)s',
                format=u'[%(asctime)s:%(msecs)d] %(levelname)s [%(filename)s:%(lineno)d] [%(processName)s] %(message)s',
                datefmt=u'%H:%M] [%S',
                stream=sys.stderr
            )
            self.l = logging.getLogger()

        fh=logging.FileHandler(self.filename_to_log,mode=u'w')
        fh.setFormatter(self.l.handlers[0].formatter)
        self.l.addHandler(fh)

        return self

    def debug(self,*args,**kwargs):
        if not self.disabled:
            self.l.debug(*args,**kwargs)
    def warning(self,*args,**kwargs):
        if not self.disabled:
            self.l.warning(*args,**kwargs)
    def error(self,*args,**kwargs):
        if not self.disabled:
            self.l.error(*args,**kwargs)
    def info(self,*args,**kwargs):
        if not self.disabled:
            self.l.info(*args,**kwargs)
    def set_level(self,*args,**kwargs):
        self.level=args[0]
        self.initLog()
    def set_color(self,*args,**kwargs):
        self.color=args[0]
        self.initLog()
    def disable(self,*args,**kwargs):
        self.disabled=True
    def enable(self,*args,**kwargs):
        self.disabled=False

log=logger(u'main')
log.initLog()
#log.debug(u'File log.py loaded')