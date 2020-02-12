#!/usr/bin/env python3
import hwdetector.Detector as Detector
import hwdetector.utils.log as log

log.debug(u'File '+__name__+u' loaded')

class LlxUsersTest(Detector):
    _NEEDS=[u'MOUNTS_INFO',u'USER_TEST']
    _PROVIDES=[u'LLXUSERS_TEST']

    def make_result(self,*args,**kwargs):
        ret=u''
        if not (u'result' in kwargs and u'msg' in kwargs):
            return
        if isinstance(kwargs[u'result'],list):
            result=kwargs[u'result']
        else:
            result=[unicode(kwargs[u'result'])]

        for x in result:
            ret+=u'{}> {}: {}\n'.format(self.__class__.__name__,x,kwargs[u'msg'])
        return ret

    def run(self,*args,**kwargs):
        msg=[]
        status = False
        msg_debug=[]
        mounts_info=kwargs[u'MOUNTS_INFO']
        user_test=kwargs[u'USER_TEST']
        for u in sorted(user_test.iterkeys()):
            status=True
            if user_test[u][u'HAS_HOME']:
                msg_debug.append(u'\n{}\n'.format(u.upper()))
                for k in user_test[u]:
                    if k != u'MOUNTS_OK':
                        msg_debug.append(u'{} {}\n'.format(k,user_test[u][k]))
                        if user_test[u][k] == False:
                            msg_debug.append(u'Home of user {} has wrong permission,owners or acl\'s\n'.format(u))
                            msg.append(self.make_result(result=[u'Home of user {} has wrong permission,owners or acl\'su'.format(u)],msg='Nok !'))
                            status = False
                    else:
                        msg_debug.append(u'{} {}\nMESSAGES:\n{}\n'.format(k,user_test[u][k][0],u'\n'.join(user_test[u][k][1])))
                        if user_test[u][k][0] == False:
                            msg.append(self.make_result(result=[u'User {} has wrong mounts, detection says'.format(u)],msg=u''))
                            msg.append(self.make_result(result=user_test[u][u'MOUNTS_OK'][1],msg=u''))
                            status = False
                if status:
                    msg.append(self.make_result(result=[u'Home of user {} seems with good permission,owners and acl\'su'.format(u)],msg='Ok!'))
                if u'NOT_LOGGED_IN' in user_test[u][u'MOUNTS_OK'][1]:
                    msg.append(self.make_result(result=u'User {} not logged in, so i can\'t expect to analyze any mountsu'.format(u),msg=''))
                else:
                    msg.append(self.make_result(result=[u'User {} has correct mounts, detection says'.format(u)],msg=u''))
                    msg.append(self.make_result(result=user_test[u][u'MOUNTS_OK'][1],msg=u'Ok!'))

        msg=u''.join(msg)
        msg_debug=u''.join(msg_debug)
        log.debug(msg_debug)
        return {u'LLXUSERS_TEST':{u'status':status,u'msg':msg}}