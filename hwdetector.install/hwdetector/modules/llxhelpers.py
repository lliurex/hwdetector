#!/usr/bin/env python3
import hwdetector.Detector as Detector
import hwdetector.utils.log as log
import re
#import urllib2 as urllib
import urllib.request as urllib
import os.path
import grp,pwd
import subprocess,time
import base64,zlib

log.debug(u'File '+__name__+u' loaded')

class LlxHelpers(Detector):
    _PROVIDES = [u'HELPER_EXECUTE',u'HELPER_UNCOMMENT',u'HELPER_GET_FILE_FROM_NET',u'HELPER_FILE_FIND_LINE',u'HELPER_DEMOTE',u'HELPER_SET_ROOT_IDS',u'HELPER_CHECK_ROOT',u'HELPER_WHO_I_AM',u'HELPER_USERS_LOGGED',u'ROOT_MODE',u'HELPER_COMPRESS_FILE',u'HELPER_LIST_FILES',u'HELPER_COMPACT_FILES']
    _NEEDS = []

    # def _close_stderr(self):
    #     self.errfile=os.fdopen(2,u'w',0)
    #     sys.stderr.close()
    #     sys.stderr = open(os.devnull, u'w')
    #
    #
    # def _open_stderr(self):
    #     sys.stderr.flush()
    #     sys.stderr.close()
    #     sys.stderr = self.errfile
    #
    # def ctl_stderr(self,*args,**kwargs):
    #     keys=[k.lower() for k in kwargs.keys()]
    #     if u'close' in keys:
    #         self._close_stderr()
    #     if u'open' in keys:
    #         self._open_stderr()

    def uncomment(self,*args,**kwargs):
        r = u''
        comments=kwargs.get(u'comments',[u'#'])
        creg=[]
        for c in comments:
            creg.append(c+u'.*')
        creg=u'|'.join(creg)
        try:
            is_file = os.path.isfile(args[0])
        except:
            is_file = False
        if is_file:
            reg=re.compile(r'^(\s*|{})*$'.format(creg),re.UNICODE)
            try:
                with open(args[0],u'r') as f:
                    for line in f.readlines():
                        #line=line.decode('utf-8')
                        line=line
                        m=re.match(reg,line)
                        if not m:
                            r += line
            except Exception as e:
                log.warning(u'Trying to read unreadable file {}'.format(args[0]))
                r += str(u'NOT_READABLE')


        else:
            if isinstance(args[0],list):
                string = u''.join(str(args[0]))
            else:
                string=str(args[0])

            reg=re.compile(r'^(\s*|#.*)*$')
            for line in string.split(u'\n'):
                m=re.match(reg,line)
                if not m:
                    r += line + u'\n'
        try:
            r=r.decode(u'utf-8')
        except:
            r=r.encode(u'utf-8').decode(u'utf-8')
        return r.strip()

    def get_file_from_net(self,*args,**kwargs):
        if not args[0]:
            return None
        if kwargs.get(u'proxy',None):
        #if u'proxy' in kwargs and kwargs[u'proxy'] == True:
            proxy = urllib.ProxyHandler() #use autodetected proxies
            proxydata={}
            if kwargs.get(u'proxy_http',None):
                proxydata.setdefault(u'http',kwargs.get(kwargs.get(u'proxy_http')))
            if kwargs.get(u'proxy_https',None):
                proxydata.setdefault(u'https',kwargs.get(kwargs.get(u'proxy_https')))

            if proxydata:
                proxy = urllib.ProxyHandler(proxydata)

            opener = urllib.build_opener(proxy)
            urllib.install_opener(opener)

        proto=args[0].split(u':')
        if proto[0]:
            proto=proto[0].lower()
        else:
            return None
        if u'http' != proto and u'https' != proto:
            return None
        try:
            content = urllib.urlopen(args[0])
            data = content.read()
            try:
                data=data
            except UnicodeDecodeError:
                data=data
            return data
        except Exception as e:
            return None

    def file_find_line(self, content, *args, **kwargs):

        if not (isinstance(content,str) or isinstance(content,list) or isinstance(content,str)):
            return None

        is_file=os.path.isfile(content)

        multimatch = isinstance(args[0],list)

        if not multimatch:
            keys = [k.strip() for k in args if k]
        else:
            keys = []
            for k_item in args[0]:
                if isinstance(k_item,list):
                    keys.append([k.strip() for k in k_item if k])

        if not is_file:
            if not isinstance(content,list):
                s = content.split(u'\n')
            else:
                s = content
        else:
            with open(content,u'r') as f:
                s=f.readlines()

        if not multimatch:
            r=re.compile(u'\s*'.join(keys),re.IGNORECASE | re.UNICODE)
        else:
            r=[]
            for k in keys:
                r.append(re.compile(u'\s*'.join(k),re.IGNORECASE | re.UNICODE))
        i=0
        output = []
        for line in s:
            if not multimatch:
                m=re.findall(r,line)
                if m:
                    if kwargs.get(u'multiple_result',False):
                        output.append(m)
                    else:
                        return m
            else:
                m=[ test for test in [ re.findall(regexp,line) for regexp in r ] if test ]
                if m:
                    i = i+1
                    output.append(m[0])
                if i == len(r):
                    if kwargs.get(u'multiple_result',False):
                        output.append(m[0])
                    else:
                        return output

        return output

    def demote(self,*args,**kwargs):
        try:
            info=pwd.getpwnam(u'nobody')
            id=info.pw_uid
            gid=info.pw_gid
            os.setgid(gid)
            os.setuid(id)
        except Exception as e:
            return False
        return True
    def set_root_ids(self,*args,**kwargs):
        try:
            os.seteuid(0)
            os.setegid(0)
        except Exception as e:
            return False
        return True
    def check_root(self,*args,**kwargs):
        if os.geteuid() == 0:
            return True
        else:
            return False

    def who_i_am(self,*args,**kwargs):
        euid=os.geteuid()
        user_info=pwd.getpwuid(euid)
        user_name=user_info[0]
        groups = [group[0] for group in grp.getgrall() if user_name in group[3]]
        return {u'id':euid,u'user_info':user_info,u'name':user_name,u'groups':groups}

    def users_logged(self,*args,**kwargs):
        l=[]
        regexp=re.compile(r'^(?P<username>\S+)\s+(?P<terminal>\S+)\s+\S+\s+\S+\s+(?P<display>\S+)?$')
        for line in self.execute(run=u'who').split(u'\n'):
            m = re.match(regexp,line)
            if m:
                d=m.groupdict()
                if d[u'display'] != None and d[u'username'] not in l:
                    l.append(d[u'username'])
        return l

    def execute(self,timeout=3.0,shell=False,*args,**kwargs):
        params={}
        if u'run' not in kwargs:
            log.error(u'Execute called without \'run\' key parameter')
            return None
        else:
            if not isinstance(kwargs[u'run'],list):
                runlist=kwargs[u'run'].split(u' ')
            else:
                runlist=kwargs[u'run']
        timeout_remaning=float(timeout)
        #Ready for python3
        #params.setdefault(u'timeout',int(timeout))
        #Python 2 code
        delay=0.1
        if u'stderr' in kwargs:
            if kwargs[u'stderr'] == u'stdout':
                params.setdefault(u'stderr',subprocess.STDOUT)
            if kwargs[u'stderr'] == None or kwargs[u'stderr'] == u'no':
                params.setdefault(u'stderr',open(os.devnull,u'w'))
            else:
                params.setdefault(u'stderr',subprocess.PIPE)
        else:
            params.setdefault(u'stderr',subprocess.PIPE)
        params.setdefault(u'stdout',subprocess.PIPE)
        with_uncomment=False
        if u'nocomment' in kwargs:
            if kwargs[u'nocomment'] == True or kwargs[u'nocomment'] == u'yes':
                with_uncomment=True

        myinfo=pwd.getpwuid(os.geteuid())
        user = myinfo.pw_name
        group = grp.getgrgid(myinfo.pw_gid).gr_name
        root_mode = False
        if self.check_root():
            if u'asroot' in kwargs:
                if kwargs[u'asroot'] == True or kwargs[u'asroot'] == u'yes':
                    root_mode=True
            if not root_mode:
                params.setdefault(u'preexec_fn', self.demote)
                user = u'nobody'
                group = u'nogroup'
            else:
                params.setdefault(u'preexec_fn', self.set_root_ids)

        params.setdefault(u'shell',shell)
        stdout=None
        stderr=None
        log.info(u'Executing command \'{}\' as {}:{}'.format(u' '.join(runlist),user,group))
        try:
            start=time.time()
            p=subprocess.Popen(runlist,**params)
            ret=p.poll()
            while ret is None and timeout_remaning > 0:
                time.sleep(delay)
                timeout_remaning -= delay
                stdout,stderr = p.communicate()
                ret = p.poll()
            if stdout is None:
                stdout,stderr = p.communicate()
            if timeout_remaning <= 0:
                raise Exception(u'timeout({}) exceded while executing {}'.format(timeout,kwargs[u'run']))
            if ret != 0:
                if stderr != u'':
                    stderr = u'stderr={}'.format(stderr)
                log.warning(u'Execution with exit code {} (possible error) {}'.format(ret,stderr))
        except Exception as e:
            log.error(u'Error executing: {}'.format(e))
            return None
        if stdout != None:
            if with_uncomment:
                out=self.uncomment(stdout.strip())
            else:
                out=stdout.strip()
            try:
                out=out.decode(u'utf-8')
            except UnicodeDecodeError:
                out=out.encode(u'utf-8')
            return out
        else:
            log.error(u'Execution of {} hasn\'t produced any result, returning None'.format(kwargs['run']))
            return None

    def compress_file(self,*args,**kwargs):
        file=kwargs.get(u'file')
        string=kwargs.get(u'string')
        if not (u'file' in kwargs or  u'string' in kwargs):
            log.error(u'Compressing called without \'file\' or \'string\' keyparam')
        if file:
            if os.path.exists(file):
                try:
                    with open(file,u'r') as f:
                        try:
                            content=f.read()
                        except:
                            return None
                        try:
                            return (u'__gz__',base64.b64encode(zlib.compress(content.encode(u'utf-8').strip())))
                        except:
                            return (u'__gz__',base64.b64encode(zlib.compress(content.strip())))
                except Exception as e:
                    log.warning(u'Fail compressing file {} : {}'.format(file,str(e).decode('utf-8')))
                    return str(u'NOT_READABLE')
        if string:
            try:
                try:
                    return (u'__gz__',base64.b64encode(zlib.compress(string.encode(u'utf-8').strip())))
                except:
                    return (u'__gz__',base64.b64encode(zlib.compress(string.strip())))
            except Exception as e:
                log.warning(u'Fail compressing string {} : {}'.format(string,e))
                return None


    def list_files(self,*args,**kwargs):
        path=kwargs.get(u'path',None)
        filter=kwargs.get(u'filter',None)
        regexp=kwargs.get(u'regexp',None)

        if not path:
            log.error(u'List files called without \'path\' keyparameter')
            return None

        paths=[]
        if isinstance(path,str) or isinstance(path,str):
            paths.append(path)
        elif isinstance(path,list):
            for x in [ x for x in path if isinstance(x,str) or isinstance(x,str) ]:
                paths.append(x)
        else:
            return None

        paths=[x for x in paths if os.path.exists(x)]

        if regexp:
            try:
                typ=re._pattern_type
            except:
                typ=re.Pattern
            if isinstance(regexp,typ):
                reg=regexp
            else:
                reg=re.compile(regexp,re.UNICODE)

            filter=lambda x: [ f for f in x if re.match(reg,f)]

        files=[]

        for p in paths:
            if os.path.isdir(p):
                for root,dirnames,filenames in os.walk(p):
                    if filter:
                        for filename in filter(filenames):
                            files.append(os.path.join(root,filename))
                    else:
                        for filename in filenames:
                            files.append(os.path.join(root,filename))
            else:
                files.append(p)
        return files

    def compact_files(self,*args,**kwargs):
        files=self.list_files(*args,**kwargs)
        if not (files and isinstance(files,list)):
            return None
        content=u''
        for file in files:
            try:
                with open(file,u'r') as f:
                    content+=f.read()
            except Exception as e:
                pass

        return self.uncomment(content)

    def run(self,*args,**kwargs):
        return {
            u'ROOT_MODE': self.check_root(),
            u'HELPER_UNCOMMENT':{u'code':self.uncomment,u'glob':globals()},
            u'HELPER_GET_FILE_FROM_NET': {u'code': self.get_file_from_net, u'glob': globals()},
            u'HELPER_FILE_FIND_LINE':{u'code': self.file_find_line, u'glob': globals()},
            u'HELPER_DEMOTE':{u'code':self.demote,u'glob':globals()},
            u'HELPER_SET_ROOT_IDS':{u'code':self.set_root_ids,u'glob':globals()},
            u'HELPER_CHECK_ROOT':{u'code':self.check_root,u'glob':globals()},
            u'HELPER_WHO_I_AM':{u'code':self.who_i_am,u'glob':globals()},
            u'HELPER_EXECUTE':{u'code':self.execute,u'glob':globals()},
            u'HELPER_USERS_LOGGED':{u'code':self.users_logged,u'glob':globals()},
            u'HELPER_COMPRESS_FILE':{u'code':self.compress_file,u'glob':globals()},
            u'HELPER_COMPACT_FILES':{u'code':self.compact_files,u'glob':globals()},
            u'HELPER_LIST_FILES':{u'code':self.list_files,u'glob':globals()}
                }