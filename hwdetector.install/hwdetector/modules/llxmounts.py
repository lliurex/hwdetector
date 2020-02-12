#!/usr/bin/env python3
import hwdetector.Detector as Detector
import hwdetector.utils.log as log
import re
import os

log.debug(u'File '+__name__+u' loaded')

class LlxMounts(Detector):

    _PROVIDES = [u'MOUNTS_INFO',u'FSTAB',u'DISK_IDS',u'SERVER_SYNC_INFO']
    _NEEDS = [u'HELPER_COMPRESS_FILE',u'HELPER_UNCOMMENT',u'HELPER_EXECUTE']

    # def parse_findmnt(self,*args,**kwargs):
    #     ltree=args[0]
    #     output = []
    #     if type(ltree) == type(dict()):
    #         d={}
    #         source=ltree[u'source']
    #         m=re.search(r'(?P<source>/[\/\w:]+)(\[(?P<bind>\S+)\])?',source)
    #         if m:
    #             tmp=m.groupdict()
    #             if tmp[u'bind']:
    #                 d[u'mount_source'] = tmp[u'bind']
    #                 d[u'binding'] = tmp[u'source']
    #             else:
    #                 d[u'mount_source'] = tmp[u'source']
    #         d[u'mount_path'] = ltree[u'target']
    #         d[u'fstype'] = ltree[u'fstype']
    #         d[u'options'] = ltree[u'options'].split(u',')
    #         output.append(d)
    #         if u'children' in ltree:
    #             for ch in ltree[u'children']:
    #                 output.extend((self.parse_findmnt(ch)))
    #     if type(ltree) == type(list()):
    #         for x in ltree:
    #             output.extend(self.parse_findmnt(x))
    #
    #     return output
    #
    # def complete_binding_mapping(self,*args,**kwargs):
    #     list = args[0]
    #     list_bindings = [ (x,list.index(x)) for x in list if u'binding' in x ]
    #     list_sources = []
    #     for b,idx in list_bindings:
    #         list_sources = [ (x,list.index(x)) for x in list if u'device' in x and x[u'device'] == b[u'binding']]
    #         k=0
    #         for s,idx2 in list_sources:
    #             k+=1
    #             list[idx][u'binding_source_link'+str(k)]=s
    #     return list

    def parse_self_mountinfo(self,*args,**kwargs):
        def unescape(string):
            return re.sub(r'\\([0-7]{3})',(lambda m: chr(int(m.group(1),8))),string)

        mounts = {}

        with open(u'/proc/self/mountinfo',u'r') as f:
            for line in f:
                try:
                    values = line.rstrip().split(u' ')
                    mid, pid, devid, root, mp, mopt = tuple(values[0:6])
                    tail = values [6:]
                    extra = []
                    for item in tail:
                        if item != u'-':
                            extra.append(item)
                        else:
                            break
                    fstype, src, fsopt = tail[len(extra)+1:]
                    mount = {u'mid':int(mid),u'pid':int(pid),u'devid':devid,u'root':unescape(root),u'mount_point':unescape(mp),u'mount_options':mopt,u'optional_fields':extra,u'fstype':fstype,u'mount_source':unescape(src),u'superblock_options':fsopt}
                    mounts.setdefault(devid,[]).append(mount)
                except Exception as e:
                    log.error(u'Error processing line /proc/self/mountinfo {}'.format(line))
                    log.error(e)
        all_mounts=[]
        for devid,mnts in mounts.items():
            # Binding detection

            # Skip single mounts
            if len(mnts) <= 1:
                for mnt in mnts:
                    if mnt[u'mount_point'] not in [x[u'mount_point'] for x in all_mounts]:
                        # skip duplicated mount points
                        mnt.setdefault(u'is_binding', u'no')
                        all_mounts.append(mnt)
                continue
            # Sort list to get the first mount of the device's root dir (if still mounted)
            mnts.sort(key=lambda x: x[u'root'])
            src = mnts[0]
            src.setdefault(u'is_binding',u'no')
            all_mounts.append(src)
            binds = mnts[1:]
            for bindmount in binds:
                if src[u'root'] != bindmount[u'root']:
                    bindmount[u'mount_source'] = src[u'mount_point']+u'/'+os.path.relpath(bindmount[u'root'],src[u'root'])
                elif src[u'fstype'] == u'cifs':
                    bindmount[u'mount_source'] = src[u'mount_point']
                elif src[u'fstype'] == u'nfs':
                    bindmount[u'mount_source'] = src[u'mount_point']+bindmount[u'mount_source'][len(src[u'mount_source']):]


                bindmount.setdefault(u'is_binding',u'yes')
                all_mounts.append(bindmount)
        #        print u'{0} -> {1[mount_point]} ({1[mount_options]})'.format(src[u'mount_point'],bindmount)
        #for x in all_mounts:
        #    print u'{mount_source} {mount_point} {fstype} {is_binding}'.format(**x)
        return all_mounts

    def get_mounts(self,*args,**kwargs):
        mounts=self.parse_self_mountinfo()
        #findmnt = json.loads(subprocess.check_output([u'findmnt',u'-J'],stderr=open(os.devnull,u'w')))
        #mounts = self.complete_binding_mapping(self.parse_findmnt(findmnt[u'filesystems']))
        output = {u'PSEUDO':[],u'DISK':[],u'NETWORK':[],u'BIND':[],u'OTHER':[]}
        #mounts =[]
        #with open(u'/proc/mounts', u'r') as f:
        #    reg = re.compile(r'^(?P<device>\S+)\s(?P<mount_path>\S+)\s(?P<type>\S+)\s(?P<options>\S+)\s(?P<dump>\S+)\s(?P<pass>\S+)$')
        #    for line in f.readlines():
        #        m = re.search(reg,line)
        #        if m:
        #            d=m.groupdict()
        #            d[u'options']=d[u'options'].split(u',')
        #            mounts.append(d)

        mapping = {u'PSEUDO': {u'fstype':[u'sysfs',u'proc',u'devtmpfs',u'devpts',u'tmpfs',u'securityfs',u'cgroup',u'pstore',u'autofs',u'mqueue',u'debugfs',u'hugetlbfs',u'rpc_pipefs',u'fusectl',u'binfmt_misc',u'nfsd',u'gvfsd-fuse']},
                   u'NETWORK':{u'fstype':[u'nfs',u'cifs']},
                   u'DISK':{u'mount_source':[u'/dev/']},
                   u'BIND':{u'is_binding':[u'yes']} # u'B'ind is tested first, before u'D'isc
                   }
        for mount in mounts:
            done = False
            for type_mapping in mapping:
                for by in mapping[type_mapping]:
                    if by in mount:
                        for string in mapping[type_mapping][by]:
                            if string in mount[by]:
                                output[type_mapping].append(mount)
                                done=True
                                break
                        if done:
                            break
                if done:
                    break
            if not done:
                output[u'OTHER'].append(mount)

        return output

    def get_server_sync(self,*args,**kwargs):
        if not os.path.isdir(u'/net/server-sync'):
            return u'NO_EXIST'
        lst=self.execute(run=u'getfacl -tp -R /net/server-sync/',stderr=None,asroot=True)
        regexp=re.compile(u'^#\sfile:\s/net/server-sync(\S+)')
        skip_search=False
        d={}

        def make_hierarchy(lkeys,value,d={}):
            if len(lkeys) == 0:
                return value
            elif len(lkeys) == 1:
                return d.setdefault(lkeys[0],value)
            else:
                return d.setdefault(lkeys[0],make_hierarchy(lkeys[1:],value,d[lkeys[0]]))

        attrs={}
        if lst:
            for line in lst.split(u'\n'):
                if line == u'':
                    lsplit=[li for li in skip_search.split(u'/') if li != u'']
                    if u'mask' in attrs:
                        attrs[u'acls']=True
                    else:
                        attrs[u'acls']=False
                    d.update(make_hierarchy(lsplit,attrs,d))
                    skip_search=False
                    attrs={}
                    continue
                if skip_search:
                    fields=[ field for field in line.split(u' ') if field != u'']
                    attrs.setdefault(u'__'+fields[0],{})
                    perms={}
                    if fields[0] not in [u'mask',u'other']:
                        skip_field=0
                    else:
                        skip_field=1
                    perms.setdefault(u'perms',fields[2-skip_field])
                    try:
                        perms.setdefault(u'defaults',fields[3-skip_field])
                    except:
                        perms.setdefault(u'defaults',None)

                    attrs[u'__'+fields[0]].setdefault(fields[1],perms)
                    #attrs[fields[0]][fields[1]].append(perms)

                else:
                    m = re.findall(regexp,line)
                    if m:
                        skip_search=m[0]
                        if os.path.isdir(u'/net/server-sync'+skip_search):
                            attrs[u'__is_dir']=True
                            attrs[u'__is_file']=False
                        else:
                            attrs[u'__is_dir']=False
                            attrs[u'__is_file']=True

        d.setdefault(u'RAW',lst)
        return d


    def run(self,*args,**kwargs):
        output = {u'MOUNTS_INFO':None}
        output[u'MOUNTS_INFO']=self.get_mounts()
        output[u'MOUNTS_INFO'][u'RAW']=self.compress_file(file=u'/proc/self/mounts')
        output[u'FSTAB']=self.uncomment(u'/etc/fstab')
        output[u'DISK_IDS']=self.execute(run=u'blkid',asroot=True,stderr=None)
        output[u'SERVER_SYNC_INFO']=self.get_server_sync()

        return output