#!/usr/bin/env python
import hwdetector.Detector as Detector
import hwdetector.utils.log as log
import os

log.debug(u'File '+__name__+u' loaded')

class LlxUsers(Detector):
    _NEEDS = [u'HELPER_EXECUTE',u'HELPER_USERS_LOGGED',u'LDAP_INFO',u'MOUNTS_INFO',u'LLIUREX_SESSION_TYPE',u'LLIUREX_RELEASE',u'HELPER_WHO_I_AM',u'LOGIN_TYPE',u'LDAP_MODE',u'NFS_INITIALIZATION',u'ROOT_MODE']
    _PROVIDES = [u'USERS_INFO',u'USER_TEST']


    def check_mounts(self,username,typeuser,*args,**kwargs):
        mounts_info=kwargs[u'MOUNTS_INFO']
        session_type = kwargs[u'LLIUREX_SESSION_TYPE'].upper()
        release = kwargs[u'LLIUREX_RELEASE'].lower()
        ldap_mode = kwargs[u'LDAP_MODE'].lower()
        nfs_server = kwargs[u'NFS_INITIALIZATION']
        ret = None
        msg = []

        if release != u'server' and release != u'client':
            return (True,[u'Not in classroom model'])

        def check_mount_network(username,shares,mounts_info):
            msgs=[]
            ret = True
            for share in shares:
                mountpoint=u'/run/' + username + u'/' + shares[share]
                mountsource=u'//server/'+share
                for x in mounts_info[u'NETWORK']:
                    ret = False
                    if x[u'mount_point'] ==  mountpoint and x[u'mount_source'] == mountsource and x[u'fstype'] == u'cifs':
                        ret = True
                        msg.append(u'Samba share {} mounted under {}'.format(mountsource,mountpoint))
                        break
                if not ret:
                    msgs.append(u'Samba share {} NOT mounted under {}'.format(mountsource,mountpoint))
                    break
                else:
                    ret = True
            return (ret,msgs)
        def check_binds(username,bind_paths,mounts_info,nfs_server):
            msgs = []
            ret = True
            for bind in bind_paths:
                for x in mounts_info[u'BIND']:
                    ret = False
                    if x[u'mount_point'].startswith(u'/home/' + username) and x[u'mount_source'] == bind_paths[bind]:
                        ret = True
                        msg.append(u'Bindmount {} from {} available'.format(x[u'mount_point'],bind_paths[bind]))
                        if nfs_server:
                            for x2 in mounts_info[u'NETWORK']:
                                ret2 = False
                                if x2[u'devid'] == x[u'devid'] and x2[u'mount_source'].startswith(nfs_server):
                                    ret2 = True
                                    msg.append(u'Referred share ({}) from bindmount ({}) is mounted from server ({})'.format(x2[u'mount_point'],x[u'mount_source'],nfs_server))
                                    break
                            if not ret2:
                                msg.append(u'Referred share ({}) from bindmount ({}) NOT mounted from server ({})'.format(x2[u'mount_point'],x[u'mount_source'],nfs_server))
                                ret = False
                                break
                        else:
                            ret2 = True
                            msg.append(u'Mounting from local without nfs, skipped checking')

                        break
                if not ret:
                    msg.append(u'Bindmount {} from {} NOT available'.format(bind,bind_paths[bind]))
                    break

            return (ret,msgs)

        samba_shares = []
        nfs_bind_paths = {}
        if typeuser == u'student':
            if release == u'server':
                nfs_bind_paths={u'Desktop':u'/net/server-sync/home/students/'+username+u'/Desktop',u'Documents':u'/net/server-sync/home/students/'+username+u'/Documents',u'share':u'/net/server-sync/share',u'groups_share':u'/net/server-sync/groups_share'}
            elif release == u'client':
                if session_type != u'THIN':
                    samba_shares = {u'home':u'home',u'share':u'share',u'groups_share':u'groups_share'}
                nfs_bind_paths={u'Desktop':u'/run/'+username+u'/home/students/'+username+u'/Desktop',u'Documents':u'/run/'+username+u'/home/students/'+username+u'/Documents',u'share':u'/run/'+username+u'/share',u'groups_share':u'/run/'+username+u'/groups_share'}
        elif typeuser == u'teacher':
            if release == u'server':
                nfs_bind_paths={u'Desktop':u'/net/server-sync/home/teachers/'+username+u'/Desktop',u'Documents':u'/net/server-sync/home/teachers/'+username+u'/Documents',u'share':u'/net/server-sync/share',u'groups_share':u'/net/server-sync/groups_share',u'teachers_share':u'/net/server-sync/teachers_share',u'/home/students':u'/net/server-sync/home/students'}
            elif release == u'client':
                if session_type != u'THIN':
                    samba_shares = {u'home':u'home',u'share':u'share', u'groups_share':u'groups_share', u'share_teachers':u'teachers_share'}
                nfs_bind_paths={u'Desktop':u'/run/'+username+u'/home/teachers/'+username+u'/Desktop',u'Documents':u'/run/'+username+u'/home/teachers/'+username+u'/Documents',u'share':u'/run/'+username+u'/share',u'groups_share':u'/run/'+username+u'/groups_share',u'teachers_share':u'/run/'+username+u'/teachers_share',u'/home/students':u'/run/'+username+u'/home/students'}
        elif typeuser == u'admin':
            if release == u'server':
                nfs_bind_paths={u'Desktop':u'/net/server-sync/home/admins/'+username+u'/Desktop',u'Documents':u'/net/server-sync/home/admins/'+username+u'/Documents',u'share':u'/net/server-sync/share',u'groups_share':u'/net/server-sync/groups_share'}
            elif release == u'client':
                if session_type != u'THIN':
                    samba_shares = {u'home':u'home',u'share':u'share',u'groups_share':u'groups_share',u'share_teachers':u'teachers_share'}
                nfs_bind_paths={u'Desktop':u'/run/'+username+u'/home/admins/'+username+u'/Desktop',u'Documents':u'/run/'+username+u'/home/admins/'+username+u'/Documents',u'share':u'/run/'+username+u'/share',u'groups_share':u'/run/'+username+u'/groups_share'}

        ret, msgs = check_mount_network(username,samba_shares,mounts_info)
        msg.extend(msgs)
        if ret:
            ret,msgs=check_binds(username,nfs_bind_paths,mounts_info,nfs_server)
            msg.extend(msgs)

        return (ret,msg)

    def run(self,*args,**kwargs):
        output={}
        LDAP_INFO=kwargs[u'LDAP_INFO']
        LLIUREX_RELEASE=unicode(kwargs[u'LLIUREX_RELEASE']).lower()
        logged_users=self.users_logged()
        myinfo=self.who_i_am()

        try:
            people=LDAP_INFO[u'CONFIG'][u'DB'][u'net'][u'lliurex'][u'ma5'][u'People']
            users=[(x,people[u'Students'][x]) for x in people[u'Students'].keys() if isinstance(people[u'Students'][x],dict)]
            admins=[(x,people[u'Admins'][x]) for x in people[u'Admins'].keys() if isinstance(people[u'Admins'][x],dict)]
            teachers=[(x,people[u'Teachers'][x]) for x in people[u'Teachers'].keys() if isinstance(people[u'Teachers'][x],dict)]
        except Exception as e:
            log.warning(u'Fail getting needed ldap information, using fake information only for current user')
            people = None # NO LDAP ACCESS DO IT ONLY FOR ME
            fake_ldap_info=(myinfo[u'name'],{u'homeDirectory':[myinfo[u'user_info'][5]],u'uid':[myinfo[u'name']]})
            users=[]
            admins=[]
            teachers=[]
            try:
                if unicode(kwargs[u'LOGIN_TYPE']).lower() == u'ldap':
                    if u'students' in myinfo[u'groups']:
                        users.append(fake_ldap_info)
                    elif u'teachers' in myinfo[u'groups']:
                        teachers.append(fake_ldap_info)
                    elif u'admins' in myinfo[u'groups']:
                        admins.append(fake_ldap_info)
            except Exception as e:
                log.error(e)


        # USER TEST FUNCTIONALITY

        homes = [u'/home/'+x for x in os.listdir(u'/home/')]
        cmd = [u'getfacl',u'-tp'] + homes
        perm_info=self.execute(run=cmd,stderr=None).split(u'\n')
        perm_dirs={}
        i=-1
        file=None
        while i < len(perm_info)-1:
            i+=1
            line=perm_info[i]
            if line.startswith(u'#'):
                # complete previous if exists
                if file:
                    if perm_dirs[file][u'group'] or perm_dirs[file][u'user']:
                        perm_dirs[file][u'USE_ACLS']=True
                    else:
                        perm_dirs[file][u'USE_ACLS'] =False
                file=line[8:]
                perm_dirs[file]={u'USER':{},u'GROUP':{},u'user':{},u'group':{},u'other':{},u'mask':{}}
                continue
            if line != u'':
                field=[ x for x in line.split(u' ') if x != u'']
                if field[0] in [u'other',u'mask']:
                    perm_dirs[file][field[0]]=field[1]
                else:
                    perm_dirs[file][field[0]][field[1]]=field[2]
        if users:
            for (u,udata) in users:
                #TEST HOME
                if os.path.exists(udata[u'homeDirectory'][0]):
                    output[u] = {u'HAS_HOME': True}

                    homedir=udata[u'homeDirectory'][0]
                    user=udata[u'uid'][0]

                    try:
                        output[u][u'PERM_OK']=\
                            perm_dirs[homedir][u'USER'][user] == u'rwx' \
                            and perm_dirs[homedir][u'user'][user] == u'rwx' \
                            and perm_dirs[homedir][u'GROUP'][u'nogroup'] == u'r-x' \
                            and perm_dirs[homedir][u'group'][u'students'] == u'---' \
                            and perm_dirs[homedir][u'group'][u'teachers'] == u'rwx' \
                            and perm_dirs[homedir][u'group'][u'admins'] == u'rwx' \
                            and perm_dirs[homedir][u'other'] == u'---'
                    except:
                        output[u][u'PERM_OK']=False

                    if u in logged_users:
                        output[u][u'MOUNTS_OK']=self.check_mounts(u,u'student',**kwargs)
                    else:
                        output[u][u'MOUNTS_OK']=(None,[u'NOT_LOGGED_IN'])
                else:
                    output[u]={u'HAS_HOME': False}

        # TEACHERS
        if teachers:
            for (u,udata) in teachers:
                #TEST HOME
                if os.path.exists(udata[u'homeDirectory'][0]):
                    output[u] = {u'HAS_HOME': True}

                    homedir=udata[u'homeDirectory'][0]
                    user=udata[u'uid'][0]

                    try:
                        output[u][u'PERM_OK']=\
                            perm_dirs[homedir][u'USER'][user] == u'rwx' \
                            and perm_dirs[homedir][u'user'][user] == u'rwx' \
                            and perm_dirs[homedir][u'GROUP'][u'nogroup'] == u'r-x' \
                            and perm_dirs[homedir][u'group'][u'teachers'] == u'---' \
                            and perm_dirs[homedir][u'group'][u'admins'] == u'rwx' \
                            and perm_dirs[homedir][u'other'] == u'---'
                    except:
                        output[u][u'PERM_OK']=False

                    if u in logged_users:
                        output[u][u'MOUNTS_OK']=self.check_mounts(u,u'teacher',**kwargs)
                    else:
                        output[u][u'MOUNTS_OK']=(None,[u'NOT_LOGGED_IN'])

                else:
                    output[u]={u'HAS_HOME': False}

        # ADMINS
        if admins:
            for (u,udata) in admins:
                #TEST HOME
                if os.path.exists(udata[u'homeDirectory'][0]):
                    output[u] = {u'HAS_HOME': True}

                    homedir=udata[u'homeDirectory'][0]
                    user=udata[u'uid'][0]

                    try:
                        output[u][u'PERM_OK']=\
                            perm_dirs[homedir][u'USER'][user] == u'rwx' \
                            and perm_dirs[homedir][u'user'][user] == u'rwx' \
                            and perm_dirs[homedir][u'GROUP'][u'nogroup'] == u'r-x' \
                            and perm_dirs[homedir][u'group'][u'admins'] == u'rwx' \
                            and perm_dirs[homedir][u'other'] == u'---'
                    except:
                        output[u][u'PERM_OK']=False

                    if u in logged_users:
                        output[u][u'MOUNTS_OK']=self.check_mounts(u,u'admin',**kwargs)
                    else:
                        output[u][u'MOUNTS_OK']=(None,[u'NOT_LOGGED_IN'])

                else:
                    output[u]={u'HAS_HOME': False}

        return {u'USERS_INFO':perm_dirs,u'USER_TEST':output}
