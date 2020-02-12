import os
import sys
import importlib
import inspect
from .log import log

#log.debug(u'File '+__name__+u' loaded')

def load_module(module_path, filename):
    try:
        print('Loading module: %s'%filename)
        u''" returns the module if filename is a module else None u''"
        if filename.endswith(u'.py'):
            module = filename[:-3]
        elif os.path.exists(os.path.join(module_path, filename, u'__init__.py')):
            module = filename
        else:
            return None
        try:
            return importlib.import_module(module)
        except:
            log.exception(u'Loading %s failed.' % module)
            return None
    except exception as e:
        log.exception('[UTILS][PluginManager]: %s' %e)
        return None

class PluginManager(object):
    def __init__(self):
        self.found_duplicates=False
        self.modules = {}
        self.classes = {}
        self.found = []

    def add_path(self, module_path,typeobj=object):
        sys.path.append(module_path)
        for filename in os.listdir(module_path):
            module = load_module(module_path, filename)
            if module:
                if module.__name__ in self.modules:
                    log.error(u'Duplicated module found {} unable to continue processing'.format(module.__name__))
                    self.found_duplicates=True
                    continue
                self.modules[module.__name__] = module
                self._extract_classes(module,typeobj)
        sys.path.remove(module_path)
        log.info(u'Found {} plugins: {}'.format(len(self.found),u','.join(self.found)))

    def _extract_classes(self, module,typeobj):
        for name in dir(module):
            obj = getattr(module, name)
            if inspect.isclass(obj):
                #if hasattr(obj, u'_VERSION') and obj._VERSION != None and issubclass(obj,typeobj):
                if issubclass(obj, typeobj) and obj != typeobj:
                    #version = getattr(obj, u'_VERSION')
                    #log.info(u'Found plugin: %s.%s %s' % (module.__name__, name, version))
                    if name in self.classes:
                        log.error(u'Duplicated class {} found into module {}, unable to add'.format(name,module.__name__))
                        self.found_duplicates=True
                        continue
                    #self.found.append(u'{}.{}'.format(module.__name__, name))
                    self.found.append(u'{}'.format(name))
                    self.classes[name] = obj


