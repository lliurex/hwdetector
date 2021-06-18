#!/usr/bin/env python3
import hwdetector.Detector as Detector
import hwdetector.utils.log as log
import re
import os

log.debug(u'File '+__name__+u' loaded')

class LlxTime(Detector):

    _PROVIDES = [u'TIME',u'NTP_INFO']
    _NEEDS = [u'HELPER_UNCOMMENT',u'HELPER_EXECUTE']

    def run(self,*args,**kwargs):
        output={}

        timedatectl=self.execute(run=u'timedatectl',stderr=None)

        m=re.search(r'Local time:\s\w+ (?P<TIMESW>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\s\w+)',timedatectl)
        if m:
            output.update(m.groupdict())
        m = re.search(r'RTC time:\s\w+ (?P<TIMEHW>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', timedatectl)
        if m:
            output.update(m.groupdict())
        m = re.search(r'Time zone: (?P<TIMEZONE>.*)', timedatectl)
        if m:
            output.update(m.groupdict())
        m = re.search(r'System clock synchronized: (?P<NTPENABLED>yes|no)', timedatectl)
        if m:
            output.update(m.groupdict())
        m = re.search(r'NTP service: (?P<NTPSERVICE>[^ ]+)', timedatectl)
        if m:
            output.update(m.groupdict())
        m = re.search(r'RTC in local TZ: (?P<RTCLOCALTZ>yes|no)', timedatectl)
        if m:
            output.update(m.groupdict())

        synced = False
        ntp_st = False
        try:
            os.stat('/usr/bin/ntpq')
        except:
            ntp_st='Not using ntp'
        if not ntp_st:
            try:
                ntp_st = self.execute(run=u'ntpq -pn', stderr=None)
                for line in ntp_st.split(u'\n'):
                    m = re.search(r'^\*(?P<SYNCSERVER>\d+\.\d+\.\d+\.\d+)', line)
                    if m:
                        synced = True
                        output.update(m.groupdict())
                        break
            except Exception as e:
                ntp_st = str(e)

        return {u'TIME':output,u'NTP_INFO':{u'STATE':{u'synced':synced,u'status':ntp_st.strip()},u'CONFIG':self.uncomment(u'/etc/ntp.conf')}}
