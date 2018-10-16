#!/usr/bin/env python
import sys
import os
import hwdetector.utils.log as log
#log.debug(u'File '+__name__+u' loaded')
import utils.PluginManager as PluginManager
from multiprocessing import Process,Pipe
import time
import types
import dill as pickle
import copy

from Detector import Detector

class HwDetector:
    def __init__(self,*args,**kwargs):
        log.debug(u'HwDetector initialization: initiating plugin manager')
        self.pm = PluginManager()
        self.all_plugins_are_needed = False
        os.path.dirname(os.path.abspath(__file__))+u'/modules'
        log.debug(u'HwDetector initialization: adding path to plugin manager')
        self.pm.add_path( os.path.dirname(os.path.abspath(__file__))+u'/modules',Detector)
        self.aborting = False
        self.MAX_RUNNING_TIME = None
        self.MAX_PROCESSES = None
        self.START_RUNNING_TIME = None
        self.RUNNING_TIME = None
        self.order = []
        self.capabilities = {}
        self.mapping = {}
        self.fake_capabilities = {}
        self.capabilities_stored = []
        self.helpers = {}
        self.is_classified = False
        self.nproc=0
        self.nproc_started=0

    # def _close_stderr(self):
    #     try:
    #         self.errfile=os.fdopen(2,u'w',0)
    #         sys.stderr.close()
    #         sys.stderr = open(os.devnull, u'w')
    #     except:
    #         pass
    #
    #
    # def _open_stderr(self):
    #     try:
    #         sys.stderr.flush()
    #         sys.stderr.close()
    #         sys.stderr = self.errfile
    #     except:
    #         pass


    def _kill_proc(self,*args,**kwargs):
        #self._close_stderr()
        try:
            while (args[0].is_alive()):
                args[0].terminate()
                time.sleep(0.01)
            self.nproc-=1
            log.debug(u'Killed {} remaning procs={}'.format(args[0].name,self.nproc))
        except Exception as e:
            log.warning(u'Error while killing {}'.format(args[0]))
        #self._open_stderr()

    def printCapabilities(self):
        if not self.aborting:
            for k in sorted(self.capabilities.keys()):
                if k in self.capabilities_stored:
                    if not k.startswith(u'HELPER'):
                        maxval=200
                        value=unicode(self.capabilities[k])
                        if len(value) > maxval:
                            value=value[:maxval]+u'.....'
                        print(u'{} = {}'.format(k,value))

    def _classify(self,*args,**kwargs):
        run_needs=[]
        resolved_needs = []
        free_add_plugins = []
        self.all_needs= []
        self.all_provides = []

        if u'needs' in kwargs:
            run_needs=kwargs[u'needs']
            need_run_plugin=[]

        self.capabilities = {}
        self.order = []
        pending = []

        empty_provides = []

        for classname in self.pm.classes:
            class_provides = self.pm.classes[classname]._PROVIDES
            class_needs = self.pm.classes[classname]._NEEDS

            log.debug(u'Class: {} needs {}'.format(classname,class_needs))
            log.debug(u'Class: {} provides {}'.format(classname,class_provides))

            for x in class_provides:
                if x not in self.mapping:
                    self.mapping[x]={u'PROVIDED':[classname],u'NEEDED':[]}
                else:
                    self.mapping[x][u'PROVIDED'].append(classname)
            for x in class_needs:
                if x not in self.mapping:
                    self.mapping[x]={u'PROVIDED':[],u'NEEDED':[classname]}
                else:
                    self.mapping[x][u'NEEDED'].append(classname)

            self.all_provides.extend(x for x in self.mapping if self.mapping[x][u'PROVIDED'] and x not in self.all_provides)
            self.all_needs.extend(x for x in self.mapping if self.mapping[x][u'NEEDED'] and x not in self.all_needs)
            #self.all_provides.extend([x for x in self.pm.classes[classname]._PROVIDES if x not in self.all_provides])
            #self.all_needs.extend([x for x in self.pm.classes[classname]._NEEDS if x not in self.all_needs])

            if class_provides == None or class_needs == None:
                log.warning(u'Plugin {} with empty provides and needs, maybe it\'s using base class attributes !!! disabling plugin...'.format(classname))
                if self.all_plugins_are_needed:
                    log.error(u'Unable to continue, all plugins are needed to run properly')
                    self.aborting = True
                empty_provides.append(classname)
                continue
            # Disable plugins that not provides nothing
            if not class_provides:
                log.warning(u'Plugin {} disabled because not providing anything!'.format(classname))
                if self.all_plugins_are_needed:
                    log.error(u'Unable to continue, all plugins are needed to run properly')
                    self.aborting = True
                empty_provides.append(classname)
                continue
            # Add plugins that only provides
            if not class_needs and class_provides:
                free_add_plugins.append(classname)
                if not run_needs:
                    add=True
                else:
                    add=False
                    for x in run_needs:
                        if x in class_provides:
                            add=True
                            break
                if add:
                    self.order.append(classname)
                    for x in class_provides:
                        if x:
                            self.capabilities[x] = None
                else:
                    pending.append(classname)
            else:
                for x in run_needs:
                    if x in class_provides:
                        need_run_plugin.append(classname)
                        resolved_needs.extend(class_needs)
                pending.append(classname)

        missing = [ x for x in self.all_needs if x not in [ y for y in self.all_provides]]
        not_necessary = [ x for x in self.all_provides if x not in [y for y in self.all_needs]]

        if not_necessary:
            log.info(u'Provided {} not used by anybody'.format(u','.join(not_necessary)))

        for i in empty_provides:
            log.warning(u'Disabling class {} not providing anything'.format(i))
            if self.all_plugins_are_needed:
                log.error(u'Unable to continue, all plugins are needed to run properly')
                self.aborting = True
            del self.pm.classes[i]

        for x in missing:
            log.error(u'Need {} not provided by any plugin'.format(x))
            if self.all_plugins_are_needed:
                log.error(u'Unable to continue, all plugins are needed to run properly')
                self.aborting = True
            for pl in self.mapping[x][u'NEEDED']:
                if pl in self.pm.classes:
                    del self.pm.classes[pl]
                    self.mapping[x][u'NEEDED'].remove(pl)
                    pending.remove(pl)

        if self.fake_capabilities:
            for x in self.fake_capabilities:
                self.capabilities[x] = self.fake_capabilities[x]

        if run_needs:
            for nr in need_run_plugin:
                add=False
                class_needs=self.pm.classes[nr]._NEEDS
                class_provides=self.pm.classes[nr]._PROVIDES
                for need in class_needs:
                    if need not in self.capabilities:
                        for fp in free_add_plugins:
                            if fp not in self.order and need in class_provides:
                                add=fp
                                break
                        if add and add not in self.order:
                            self.order.append(add)
                            resolved_needs.extend(class_needs)
                            for x in class_provides:
                                if x:
                                    self.capabilities[x] = None
                            if add in pending:
                                pending.remove(add)

        #Resolve other dependencies
        still_ordering=True
        if not run_needs:
            still_missing_for_run=True
        else:
            still_missing_for_run=False
        for x in resolved_needs:
            if x not in self.capabilities:
                still_missing_for_run=True
                break

        while pending != [] and still_ordering and still_missing_for_run and not self.aborting:
            still_ordering=False # Detect full loop without changing anything
            to_remove=[]
            more_needs=[]
            if not run_needs:
                for classname in pending:
                    add=classname
                    for need in self.pm.classes[classname]._NEEDS:
                        if need: #avoid empty
                            if need not in self.capabilities:
                                add=None
                                break


                    if add: # class has resolved all needs
                        #pending.remove(classname)
                        to_remove.append(add)
                        self.order.append(add)
                        #resolved_needs.extend(self.pm.classes[classname]._PROVIDES)
                        for x in self.pm.classes[add]._PROVIDES:
                            if x:
                                self.capabilities[x] = None
            else:
                for need in resolved_needs:
                    if need not in self.capabilities:
                        for classname in pending:
                            add=classname
                            if need in self.pm.classes[classname]._PROVIDES:
                                for x in self.pm.classes[classname]._NEEDS:
                                    if x:
                                        if x not in self.capabilities:
                                            add=None
                                            more_needs.append(x)

                                if add:
                                    to_remove.append(add)
                                    self.order.append(add)
                                    for x in self.pm.classes[add]._PROVIDES:
                                        if x:
                                            self.capabilities[x] = None
            log.debug(u'Endloop classifier')

            for r in to_remove:
                if r in pending:
                    pending.remove(r)
                    still_ordering = True

            for n in more_needs:
                if n not in resolved_needs:
                    resolved_needs.append(n)
                    still_ordering=True

            if still_ordering == False: # none of pending plugins can satisfy more dependencies
                if run_needs:
                    not_found=[]
                    for x in resolved_needs:
                        if x not in self.capabilities:
                            not_found.append(x)

                    if not_found:
                        if self.is_classified:
                            str=u'couldn\'t satisfy all dependencies for needed plugin'
                        else:
                            if self.pm.found_duplicates:
                                str=u'maybe missing dependency?'
                            else:
                                str=u'maybe ciclic dependency?'

                            # Get plugins related to cycle
                            related=[]
                            for plug in self.pm.classes:
                                for prov in self.pm.classes[plug]._PROVIDES:
                                    if prov in not_found and plug not in related:
                                        related.append(plug)

                            str+=u'\nPlugins related with cycle: {}'.format(u','.join(related))

                        log.error(u'Unable to continue, {} !!!\nNotFound providers for ({})'.format(str,u','.join(not_found)))
                        self.aborting = True
                    else:
                        for pl in need_run_plugin:
                            add=pl
                            for need in self.pm.classes[pl]._NEEDS:
                                if need not in self.capabilities:
                                    add=None
                                    break
                            if not add:
                                log.error(u'Disabling class {} needed to run due to unresolved dependencies'.format(pending_class))
                                self.aborting=True
                                break
                            else:
                                self.order.append(add)
                else:
                    for pending_class in pending:
                        log.warning(u'Disabling class {} due to unresolved dependencies'.format(pending_class))
                        if self.all_plugins_are_needed:
                            log.error(u'Unable to continue, all plugins are needed to run properly')
                            self.aborting = True
                            break
                        del self.pm.classes[pending_class]


        self.MAX_PROCESSES = len(self.order)
        log.info(u'Plugin order calculated: {}'.format(u','.join(self.order)))
        self.is_classified = True
        if self.aborting:
            return False
        else:
            return True

    def run(self,*args,**kwargs):
        ret=True
        if not self.is_classified:
            if not self._classify(**kwargs):
                ret=False
        else:
            log.info(u'Running all plugins')

        if not self.START_RUNNING_TIME:
            self.START_RUNNING_TIME = time.time()

        procs = [None]* self.MAX_PROCESSES
        done=None
        remaning=copy.copy(self.order)
        started=[]
        self.capabilities_stored=[]
        if self.fake_capabilities:
            for x in self.fake_capabilities.keys():
                self.capabilities_stored.append(x)
        while done == None and not self.aborting:
            #start processes
            for plug in self.order:
                if done == False: #recalculation in process
                    break
                if procs[self.order.index(plug)] == None:
                    can_start=False
                    if self.pm.classes[plug]._NEEDS:
                        for need in self.pm.classes[plug]._NEEDS:
                            if need:
                                if need in self.capabilities.keys() and need in self.capabilities_stored:
                                    can_start=True
                                else:
                                    can_start=False
                                    break
                    else:
                        can_start = True

                    if can_start:
                        pipe_in, pipe_out = Pipe(duplex=False)
                        #kw = {u'out': pipe_out,u'stderr':open(os.devnull,u'w')}
                        kw = {u'out': pipe_out}
                        args = (pipe_out,)
                        obj = self.pm.classes[plug]()

                        for need in obj._NEEDS:
                            if need and need in self.capabilities.keys():
                                if need.lower()[0:6] == u'helper':
                                    f=pickle.loads(self.helpers[need])
                                    dummy_func=types.FunctionType(f[u'code'].__code__,f[u'glob'],f[u'code'].__code__.co_name)
                                    dummy_func.func_globals.update({u'self':f[u'code'].im_self})
                                    obj.__dict__[f[u'code'].__code__.co_name]=dummy_func
                                    setattr(obj,f[u'code'].__code__.co_name,f[u'code'])
                                    log.debug(u'Helper {} registered into {}'.format(need,obj.__class__.__name__))
                                else:
                                    if self.capabilities[need] == None:
                                        log.warning(u'Providing capability {} with an empty value to {} plugin'.format(need,obj.__class__.__name__))
                                    kw.update({need:self.capabilities[need]})
                                    args = args + (self.capabilities[need],)

                        procs[self.order.index(plug)] = {u'process':Process(target=obj._run,name=plug,args=args,kwargs=kw),
                                                        u'name':plug,
                                                        u'stime':None,
                                                        u'rtime':None,
                                                        u'pin':pipe_in,
                                                        u'pout':pipe_out}
                        if not self.aborting:
                            procs[self.order.index(plug)][u'process'].start()
                            procs[self.order.index(plug)][u'stime'] = time.time()
                            started.append(plug)
                            self.nproc += 1
                            self.nproc_started +=1
                            log.debug(u'Started process number={} ({})'.format(self.nproc_started,plug))

            # check processes
            for pinfo in procs:
                if done == False:   # recalculation in progress
                    break
                if pinfo and pinfo[u'stime']:
                    t = time.time() - pinfo[u'stime']
                    if self.MAX_RUNNING_TIME and t > self.MAX_RUNNING_TIME and not pinfo[u'rtime']:
                        self._kill_proc(pinfo[u'process'])
                        pinfo[u'rtime']=t
                        log.error(u'Plugin {} aborted, maximun running time ({}) exceded'.format(pinfo[u'name'],self.MAX_RUNNING_TIME))
                        if self.all_plugins_are_needed:
                            log.error(u'Unable to continue, all plugins are needed to run properly')
                            self.aborting = True
                        del self.pm.classes[pinfo[u'name']]
                        log.debug(u'Plugin {} deactivated, recalculating dependencies & rerunning'.format(pinfo[u'name']))
                        done = False
                        ret = False
                        break
                    if pinfo[u'pin'].poll():
                        pinfo[u'rtime']=t
                        output = pinfo[u'pin'].recv()
                        pinfo[u'process'].join()
                        self.nproc -= 1
                        log.debug(u'Finished {}'.format(pinfo[u'name']))
                        for provide in self.pm.classes[pinfo[u'name']]._PROVIDES:
                            if provide:
                                if output and type(output) == type(dict()) and provide in output.keys():
                                    #out_stripped=str(output[provide]).upper().replace(u'NULL',u'null').strip()
                                    out_stripped = output[provide]
                                    if provide[0:6].lower()==u'helper':
                                        self.helpers[provide] = out_stripped
                                        out_stripped = u'STORED'
                                    if provide in self.capabilities.keys() and self.capabilities[provide] != None:
                                        log.warning(u'Plugin {} overwrite {} capability'.format(pinfo[u'name'], provide))
                                    else:
                                        log.debug(u'Plugin {} set the capability \'{}\' with value \'{}\' in {}'.format( pinfo[u'name'],
                                                                                                                provide,
                                                                                                                out_stripped,
                                                                                                                pinfo[u'rtime']))
                                    if out_stripped == None:
                                        log.warning(u'Capability {} was stored with and empty value of {}'.format(provide,str(out_stripped)))
                                    self.capabilities[provide] = out_stripped
                                    self.capabilities_stored.append(provide)
                                else: # provide not in output
                                    if provide in self.capabilities_stored:
                                        log.info(
                                            u'Plugin {} was provided by unknown instead of {}, recalculate not needed'.format(
                                                provide,pinfo[u'name']))
                                    else:
                                        log.error(u'Plugin {} mus\'t provide {} which wasn\'t available into result'.format(
                                            pinfo[u'name'], provide))
                                        if self.all_plugins_are_needed:
                                            log.error(u'Unable to continue, all plugins are needed to run properly')
                                            self.aborting = True
                                        del self.pm.classes[pinfo[u'name']]
                                        log.debug(u'Plugin {} deactivated, recalculating dependencies & rerunning'.format(pinfo[u'name']))
                                        done = False
                                        ret = False
                                        break
                        remaning.remove(pinfo[u'name'])

                    elif not pinfo[u'rtime'] and not pinfo[u'process'].is_alive():
                        log.error(u'Plugin {} dead without sending results'.format(pinfo[u'name']))
                        if self.all_plugins_are_needed:
                            log.error(u'Unable to continue, all plugins are needed to run properly')
                            self.aborting = True
                        self.nproc-=1
                        del self.pm.classes[pinfo[u'name']]
                        log.debug(u'Plugin {} deactivated, recalculating dependencies & rerunning'.format(pinfo[u'name']))
                        done = False
                        ret = False

                    if done == False or self.aborting:
                        for pinfo2 in procs:
                            if pinfo2 and pinfo2[u'stime'] and pinfo2[u'process'].is_alive():
                                self._kill_proc(pinfo2[u'process'])
                                pinfo2[u'rtime'] = t
                                if self.aborting:
                                    log.debug(
                                        u'Aborting... terminating process {}'.format(pinfo2[u'name']))
                                else:
                                    log.debug(u'Terminating process {} due recalculation in process'.format(pinfo2[u'name']))


            if done != False:
                if len(remaning) > 0:
                    still = [ p for p in remaning if p in started ]
                    log.debug(u'Endloop plugins still running: {}'.format(u','.join(still)))
                else:
                    log.debug(u'No more plugins to run!')
                #check all finished (done=True) or wait to next round for start & check (done=None)
                done = True
                for pinfo in procs:
                    if not pinfo or pinfo[u'rtime'] == None:
                        done = None
                        timesleep=0.01
                        if log.level < 20:
                            timesleep=0.5
                        time.sleep(timesleep)
                        break

        if done == False:
            # kill all plugins currently running
            for p in procs:
                if p and p[u'stime'] and p[u'process'].is_alive():
                    self._kill_proc(p[u'process'])
                    p[u'rtime'] = t
                    log.debug(u'Terminating process {} before recalculation in process'.format(p[u'name']))
            if not self.aborting:
                self._classify(**kwargs)
                self.run()
        else:
            # when loop start+check finish must have all process completed
            clasifying_success = [ x for x in procs if x != None ]
            if clasifying_success:
                for i in range(0,len(procs)):
                    #if procs[i] == None:
                    if not (procs[i] and procs[i][u'rtime']):
                        log.error(u'Plugin {} can\'t be started, previous plugin fail providing dependencies'.format(self.order[i]))
                        if self.all_plugins_are_needed:
                            log.error(u'Unable to continue, all plugins are needed to run properly')
                            self.aborting = True
                        ret = False
                        break
        if not self.RUNNING_TIME:
            self.RUNNING_TIME = time.time() - self.START_RUNNING_TIME

        return ret
