#!/usr/bin/env python
import hwdetector.Detector as Detector
import hwdetector.utils.log as log
import re
import base64
import hashlib
import os

log.debug(u'File '+__name__+u' loaded')

class LlxLdap(Detector):
    _NEEDS = [u'HELPER_EXECUTE',u'HELPER_FILE_FIND_LINE',u'HELPER_UNCOMMENT',u'HELPER_CHECK_OPEN_PORT',u'LLIUREX_RELEASE',u'HELPER_CHECK_ROOT',u'NETINFO',u'N4D_VARS',u'HELPER_CHECK_NS',u'HELPER_COMPRESS_FILE']
    _PROVIDES = [u'SERVER_LDAP',u'LDAP_INFO',u'LDAP_MODE',u'LDAP_MASTER_IP',u'LOCAL_LDAP']

    def check_files(self,*args,**kwargs):
        release=args[0]
        mode=args[1]
        server=args[2]

        if not server:
            log.error(u'Unable to locate ldap server')

        if mode and mode.lower() == u'independent':
            servername = server
        else:
            servername = u'localhost'

        output={}
        try:
            content_ldap_conf=self.uncomment(u'/etc/ldap.conf')
            ldap_conf_ok = self.file_find_line(content_ldap_conf,
            [
                [u'^base',u'dc=ma5,dc=lliurex,dc=net'],
                [u'^uri',u'ldap://'+servername],
                [u'^nss_base_group',u'ou=Groups,dc=ma5,dc=lliurex,dc=net'],
                [u'^nss_map_attribute',u'gecos',u'description']
            ])

            if ldap_conf_ok:
                output[u'etc_ldap_conf']={u'syntax':u'OK',u'content':content_ldap_conf}
            else:
                output[u'etc_ldap_conf'] = {u'syntax': u'NOK', u'content': content_ldap_conf}

            content_etc_ldap_ldap_conf=self.uncomment(u'/etc/ldap/ldap.conf')
            etc_ldap_ldap_conf_ok = self.file_find_line(content_etc_ldap_ldap_conf,
            [
                [u'^BASE',u'dc=ma5,dc=lliurex,dc=net'],
                [u'^URI',u'ldaps://'+servername]
            ])

            if etc_ldap_ldap_conf_ok:
                output[u'etc_ldap_ldap_conf']={u'syntax':u'OK',u'content':content_etc_ldap_ldap_conf}
            else:
                output[u'etc_ldap_ldap_conf'] = {u'syntax': u'NOK', u'content': content_etc_ldap_ldap_conf}

            nsswitch_content = self.uncomment(u'/etc/nsswitch.conf')
            nsswitch_ok = self.file_find_line(nsswitch_content,
            [
                [u'passwd:',u'files',u'ldap'],
                [u'group:',u'files',u'ldap'],
                [u'shadow:',u'files',u'ldap']
            ])
            if nsswitch_ok:
                output[u'nsswitch_conf']={u'syntax':u'OK',u'content':nsswitch_content}
            else:
                output[u'nsswitch_conf'] = {u'syntax': u'NOK', u'content': nsswitch_content}
        except:
            pass
        return output

    def check_ports(self,*args,**kwargs):
        ports=[u'389',u'636']
        server=args[0]
        #localldap=args[1]
        # split uri
        #server=re.findall(r'(?:[^/]+/+)?(.*)$',server)[0]
        #if not localldap:
        #    # is dnsname?
        #    is_ip=re.findall(r'(\d+(?:\.\d+){3})',server)[0]
        #    if is_ip:
        #        server=is_ip[0]
        out = {}
        for p in ports:
            out[p]=self.check_open_port(server,p)
        try:
            self.file_find_line(self.execute(run=u'netstat -nx'),u'/var/run/slapd/ldapi')
            out[u'LDAPI']=True
        except Exception as e:
            out[u'LDAPI']=False
        return out

    def parse_tree(self,*args,**kwargs):
        if not (isinstance(args[0],str) or isinstance(args[0],unicode)):
            return None
        output = {}
        lines = args[0].split(u'\n')

        path = output
        atrib=u''
        value=u''
        for line in lines:
            if line==u'':
                path=output
            else:
                if line.startswith(u'dn: '):
                    hierarchy=line[4:].split(u',')
                    hierarchy.reverse()
                    for level in hierarchy:
                        if level not in path:
                            path[level]={}
                        path = path[level]
                elif line.startswith(u' '):
                    value=value+line[1:]
                    path[atrib][-1]=value
                else:
                    parts=line.split(u' ')
                    atrib=parts[0][:-1]
                    value=u' '.join(parts[1:])
                    if atrib in path:
                        path[atrib].append(value)
                    else:
                        path.update({atrib:[value]})
        if output:
            output=self.make_alias(output)
        else:
            log.warning(u'Can\'t parse ldap tree')
            raise Exception(u'No_ldap_tree')
        return output

    def make_alias(self,*args,**kwargs):
        d=args[0]
        if len(args) == 1:
            out={}
        else:
            out = args[1]
        for k in d.keys():
            if isinstance(d[k],dict):
                split = k.split(u'=')
                if len(split) > 1:
                    aliaslevel = split[1]
                    out[aliaslevel] = self.make_alias(d[k])
            else:
                out.update({k:d[k]})
        return out

    def read_pass(self):
        self.pwd=None
        sfile=u'/etc/ldap.secret'
        try:
            if not os.path.exists(sfile):
                sfile=None
            else:
                with open(sfile,u'r') as f:
                    self.pwd=f.read().strip()
        except:
            if sfile:
                log.warning(u'Running as user, secret file verification is not possible')
            pass

    def checkpass(self,*args,**kwargs):
        p=args[0]
        if self.pwd:
            hash_digest_with_salt=base64.b64decode(base64.b64decode(p)[6:]).strip()
            salt=hash_digest_with_salt[hashlib.sha1().digest_size:]
            compare=base64.b64encode(u'{SSHA}' + base64.encodestring(hashlib.sha1(str(self.pwd) + salt).digest() + salt))
            return p == compare
        return None

    def get_ldap_config(self,*args,**kwargs):
        release=unicode(args[0]).lower()
        server=unicode(args[1])
        root_mode=self.check_root()
        kw={u'stderr':None}

        if root_mode:
            kw.setdefault(u'asroot',True)
        auth=u'-Y EXTERNAL'
        uri=u'ldapi:///'

        if release==u'client' and self.pwd:
            auth=u'-D cn=admin,dc=ma5,dc=lliurex,dc=net -w '+self.pwd
            uri=u'ldaps://'+server+u':636'

        try:
            db=self.execute(run=u'ldapsearch {} -H {} -LLL'.format(auth,uri),**kw)
            tree_db=self.parse_tree(db)
        except:
            db=None
            tree_db=None

        if tree_db:
            try:
                config=self.execute(run=u'ldapsearch {} -H {} -b cn=config -LLL'.format(auth,uri),**kw)
                tree_config=self.parse_tree(config)
            except:
                config=None
                tree_config=None
        else:
            config=None
            tree_config=None

        try:
            tree_db[u'net'][u'lliurex'][u'ma5'][u'o']
            init_done=True
        except:
            init_done=False

        if tree_config:
            good_pass=False
            if tree_config[u'config'][u'{1}mdb'][u'olcRootPW:'] and u'cn=admin,dc=ma5,dc=lliurex,dc=net' in tree_config[u'config'][u'{1}mdb'][u'olcRootDN']:
                good_pass=self.checkpass(tree_config[u'config'][u'{1}mdb'][u'olcRootPW:'][0])
        else:
            good_pass=None

        return {u'CONFIG':tree_config,u'DB':tree_db,u'RAW_CONFIG':self.compress_file(string=config),u'RAW_DB':self.compress_file(string=db),u'INITIALIZED':init_done,u'SECRET_STATUS':good_pass}

    def run(self,*args,**kwargs):
        out = {u'LDAP_MASTER_IP':None}
        output = {}
        release=kwargs[u'LLIUREX_RELEASE']
        vars=kwargs[u'N4D_VARS']
        mapping={u'CLIENT_LDAP_URI':u'SERVER_LDAP'}
        server=None
        localldap=None

        # Guess server ldap uri
        for search_var in mapping:
            if search_var in vars and u'value' in vars[search_var]:
                out.update({mapping[search_var]:vars[search_var][u'value']})
                server=vars[search_var][u'value']
                out.setdefault(u'LOCAL_LDAP',True)
                localldap=True
        if not server:
            ip_server=self.check_ns(u'server')
            try:
                ip_server2=kwargs[u'NETINFO'][u'gw'][u'via']
            except:
                ip_server2=None

            if not ip_server:
                log.warning(u'\'server\' not resolvable')
                if ip_server2:
                    server=ip_server2
                    log.warning(u'using gateway trying to guess \'server\' dnsname')
                else:
                    log.warning(u'not detected any gateway')
            else:
                server=ip_server
                if ip_server != ip_server2:
                    log.warning(u'\'server\' is not my gateway')
            if server:
                out.update({u'SERVER_LDAP':server})
                out.update({u'LOCAL_LDAP':False})
                localldap=False
            else:
                out.update({u'SERVER_LDAP':None})
                out.update({u'LOCAL_LDAP':None})
                localldap=None

        self.read_pass()

        output[u'PORTS'] = self.check_ports(server,localldap)
        mode=None

        if output[u'PORTS'][u'636']:
            output[u'CONFIG']=self.get_ldap_config(release,server)
            mode=u'UNKNOWN'
            try:
                test=output[u'CONFIG'][u'INITIALIZED']
            except:
                mode=u'UNNINITIALIZED'
            try:
                test=output[u'CONFIG'][u'CONFIG'][u'config'][u'{1}mdb'][u'olcSyncrepl']
                test=output[u'CONFIG'][u'CONFIG'][u'config'][u'{1}mdb'][u'olcUpdateRef']
                mode=u'SLAVE'
                if output[u'CONFIG'][u'CONFIG'][u'config'][u'{1}mdb'][u'olcSyncrepl'][0]:
                    m=re.search(r'provider=ldapi?://(?P<LDAP_MASTER_IP>\d+\.\d+\.\d+\.\d+)u',output['CONFIGu']['CONFIGu']['configu']['{1}mdbu']['olcSyncrepl'][0])
                    if m:
                        out.update(m.groupdict())
            except:# indep or (master/slave(running without permissions))
                mode=u'INDEPENDENT'
                netinfo=kwargs[u'NETINFO']
                if netinfo:
                    aliased_interfaces = [ k for k in netinfo if isinstance(netinfo[k],dict) and u'nalias' in netinfo[k] and netinfo[k][u'nalias'] > 0 ]
                    for i in aliased_interfaces:
                        for n in range(netinfo[i][u'nalias']):
                            if u'alias'+str(n+1)+u'_ifaddr' in netinfo[i]:
                                ip_alias=netinfo[i][u'alias'+str(n+1)+u'_ifaddr'].split(u'.')[3].split(u'/')[0]
                                if ip_alias==u'1':
                                    mode=u'SLAVE'
                                elif ip_alias==u'254':
                                    mode=u'MASTER'

        output[u'FILES'] = self.check_files(release,mode,server)
        out.update( {u'LDAP_INFO':output,u'LDAP_MODE':mode})

        return out