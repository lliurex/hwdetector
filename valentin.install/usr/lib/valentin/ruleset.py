#!/usr/bin/env python3
from hwdetector.utils.log import log
import re

T_COMMENT='#'
T_MULTIPLE='*'
T_CAPTURE='()'
T_FIND='~'
T_REPLACE='{}'
T_SEP=','
T_SPLIT='->'
T_HINT='?'
T_CHILD='.'
T_EQUAL='='
T_NOT_EQUAL='!='
T_LIKE='%'
T_NOT_LIKE='!%'
T_GT='<'
T_LT='>'
T_CONTAIN='%'
T_EXISTENCE='@'
L_STR=['\'','"']
L_EMPTY=['\t',' ']

class ruleset:
    def __init__(self):
        self.l_spliters=[T_COMMENT,T_SEP,T_SPLIT,T_HINT]
        self.l_ops=[T_EQUAL,T_NOT_EQUAL,T_CAPTURE,T_EXISTENCE,T_LIKE,T_NOT_LIKE,T_LT,T_GT]
        self.l_template=[T_MULTIPLE,T_REPLACE]
        self.rules=[]
        self.data=None
        self.data_values={}
        pass

    def read_until(self,st,until,invert=False,*args,**kwargs):
        def first_in_until(st,combined):
            idxfirst=[]
            for t in combined:
                i=-1
                try:
                    i=st.index(t,i+1)
                except:
                    pass
                if i == -1:
                    i=9999
                idxfirst.append(i)
            midxfirst=min(idxfirst)
            if combined[idxfirst.index(midxfirst)] in until:
                return True
            return False

        idxs=[]
        start=-1
        if not first_in_until(st,L_STR+until):
            for s in L_STR:
                i=-1
                tmp=-1
                double=True
                try:
                    while True:
                        if double and first_in_until(st[tmp+1:],L_STR+until):
                            idxs.append(i)
                            break
                        tmp=st.index(s,tmp+1)
                        if st[tmp-1]!='\\':
                            double=not double
                            i=tmp
                except Exception as e:
                    if not double:
                        #raise Exception(u'Unbalanced quotes')
                        i=9999
                    idxs.append(i)

            start=min(idxs)
            if start==-1:
                start=max(idxs)
        idx=[]
        if invert:
            for u in until:
                if start != -1:
                    i=start+1
                else:
                    i=-1
                try:
                    while True:
                        i=st.index(u,i+1)
                except:
                    if i == -1:
                        i=len(st)
                idx.append(i)
        else:
            for u in until:
                if start != -1:
                    i=start+1
                else:
                    i=-1
                try:
                    i=st.index(u,i+1)
                except:
                    if i == -1:
                        i=len(st)
                idx.append(i)
        midx=min(idx)
        if invert:
            midx+=len(until[idx.index(midx)])
        return (st[:midx].strip(),st[midx:].strip())


    def clean_quotes(self,*args,**kwargs):
        v=args[0]
        if isinstance(v,str) or isinstance(v,str):
            return v.strip(''.join(L_STR))
        elif isinstance(v,dict):
            for v2 in v:
                v[v2]=self.clean_quotes(v[v2])
            return v

    def search_key_coincidence(self,search_on,key,fact,consequences,op,value,*args,**kwargs):
        #fact_key=[]
        done=False
        found=None
        key_split=key.split(T_CHILD)
        len_split=len(key_split)
        i=0
        for levelkey in key_split:
            i+=1
            if not done and isinstance(search_on,dict):
                #    raise Exception(u'Use of key \'{}\xu' isn\'t permitted, only dict keys are matched in rules'.format(levelkey))
                changed_key=None
                for lkey in list(search_on.keys()):
                    if lkey != levelkey and lkey.lower() == levelkey.lower():
                        changed_key=levelkey
                        levelkey=lkey

                if T_MULTIPLE in levelkey:
                    searched_keys=[x for x in list(search_on.keys()) if levelkey.replace(T_MULTIPLE,'') in x]
                    if searched_keys:
                        for r in searched_keys:
                            new_fact=fact.replace(levelkey,r).strip()
                            new_consequences=consequences.replace(T_REPLACE,r).strip()
                            try:
                                self.make_rule('{} -> {} '.format(new_fact,new_consequences))
                                log.debug('Rule repetat: Unrolling to: {} -> {}'.format(new_fact,new_consequences))
                            except:
                                log.debug('Rule repeat: Cannot unroll to: {} -> {}'.format(new_fact,new_consequences))
                        return None
                    else:
                        raise Exception('Can\'t apply template \'{}\''.format(levelkey))
                else:
                    if levelkey not in list(search_on.keys()):
                        raise Exception('Use of key \'{}\' not possible'.format(levelkey))
                    #fact_key.append(levelkey)
                    search_on=search_on[levelkey]
                    if i == len_split:
                        done=True

            elif not done and isinstance(search_on,list):
                for item in search_on:
                    if T_FIND in levelkey:
                        try:
                            search,val=levelkey.split(T_FIND)
                        except:
                            raise Exception('Incorrect use for find token')
                        lkeys=[key for key in item if search.lower() == key.lower()]
                        if lkeys:
                            search = lkeys[0]
                        if val not in item[search]:
                            found=False
                            continue
                        else:
                            levelkey=search
                            found=True

                    if not done:
                        try:
                            search_on=self.search_key_coincidence(item,levelkey,fact,consequences,op,value)
                            done=True
                            break
                        except:
                            pass
        if done:
            return search_on
        else:
            if found == False:
                return False
            else:
                return None



    def make_rule(self,*args,**kwargs):
        clean=lambda x: str(x).replace('\\','').strip()
        line=args[0]
        line=line.split(T_SPLIT)
        rule={'facts':[],'consequences':[],'hints':[]}
        if len(line) < 2:
            raise Exception('No consequences in rule')
        if len(line) > 2:
            raise Exception('Multiple consequences in rule')
        facts=line[0]
        consequences=line[1]
        if consequences.strip() == '':
            raise Exception('Empty consequences')
        if facts.strip() == '':
            raise Exception('Empty facts')
        fact_list=facts.split(T_SEP)
        for f in fact_list:
            if f:
                try:
                    ftmp,vtmp=self.read_until(f,self.l_ops)
                except Exception as e:
                    raise e

                #first read operation
                try:
                    op,vtmp=self.read_until(vtmp,self.l_ops,True)
                except:
                    raise e
                if op == '':
                    raise Exception('Missing op')
                if op not in self.l_ops:
                    raise Exception('Wrong op')

                #read value
                vtmp,end=self.read_until(vtmp,self.l_ops+self.l_spliters)
                if vtmp == '' and op != T_CAPTURE:
                    raise Exception('Wrong value')

                value=self.search_key_coincidence(self.data,ftmp,f,consequences,op,vtmp)
                if value == None:
                    return
                self.data_values[ftmp]=value

                if vtmp and op == T_CAPTURE:
                    log.debug('Capturing {} to {} '.format(value,vtmp))
                    self.data.setdefault(vtmp,value)

                rule['facts'].append({'key':ftmp,'op':op,'value':vtmp})
        try:
            try:
                consequences,hints=self.read_until(consequences,[T_HINT])
            except Exception as e:
                raise e
            lconsequences=[]
            end=True
            while end:
                ctmp,end=self.read_until(consequences,[T_SEP])
                lconsequences.append(clean(ctmp))

            for c in lconsequences:
                if c[0] != c[-1] and c[0] not in L_STR:
                    raise Exception('Consequences mus\'t be enclosed with quotes')
            rule['consequences']=lconsequences
            hints=hints[1:]
            try:
                if hints:
                    end=True
                    lhints=[]
                    while end:
                        htmp,end=self.read_until(hints,[T_SEP])
                        lhints.append(clean(htmp))
                        hints=end[1:]

                    #lhints=[clean(h) for h in hints.split(T_SEP)]
                    for h in lhints:
                        if h[0] != h[-1] and h[0] not in L_STR:
                            raise Exception('Hints mus\'t be enclosed with quotes')
                    rule['hints']=lhints
            except:
                pass #hints are optional
            for k in ['facts','consequences','hints']:
                for i in range(len(rule[k])):
                    rule[k][i] = self.clean_quotes(rule[k][i])
        except Exception as e:
            raise e

        self.rules.append(rule)

    def load_ruleset(self,*args,**kwargs):
        fileruleset=kwargs.get('fileruleset',None)
        if not fileruleset:
            raise Exception('No fileruleset in kwargs')
        self.data=kwargs.get('data',None)
        if not self.data:
            raise Exception('Empty data')
        try:
            with open(fileruleset,'r') as f:
                l=0
                for line in f:
                    l+=1
                    try:
                        if not line.strip().startswith('#'):
                            self.make_rule(line)
                    except Exception as e:
                        log.error('Rule: \'{}\' : {}'.format(line,e))
                log.info('{} lines processed, {} rules loaded'.format(l,len(self.rules)))
        except:
            raise Exception('Wrong file for ruleset')

    def make_tree(self,*args,**kwargs):
        lfacts=[fact for lfacts in [rule['facts'] for rule in self.rules] for fact in lfacts]
        count_facts={}
        for fact in lfacts:
            count_facts.setdefault(fact['key'],0)
            count_facts[fact['key']]+=1
            log.debug('Ordering key {} = {}'.format(fact['key'],count_facts[fact['key']]))
        self.keys_ordered=sorted(count_facts,key=count_facts.get,reverse=True)

        tmp_rules=[]
        for key in self.keys_ordered:
            for rule in self.rules:
                found=False
                for fact in rule['facts']:
                    if fact['key'] == key:
                        found=True
                        break
                if found:
                    tmp_rules.append(rule)
                    del self.rules[self.rules.index(rule)]

        self.rules=tmp_rules

        log.debug('Tree keys ordered: {}'.format(','.join(self.keys_ordered)))


    def apply_operation(self,fact):
        clean=lambda x: str(x).replace(' ','').strip()
        value=clean(fact.get('value')).lower()
        key=clean(fact.get('key'))
        op=clean(fact.get('op'))
        data_value=clean(self.data_values[key]).lower()
        ret=False
        if op == T_EQUAL:
            if value == data_value:
                ret=True
        elif op == T_NOT_EQUAL:
            if value != data_value:
                ret=True
        elif op == T_LIKE:
            if value in data_value:
                ret=True
        elif op == T_NOT_LIKE:
            if value not in data_value:
                ret=True
        elif op == T_CAPTURE:
            if self.data_values[key]:
                return True
        elif op == T_EXISTENCE:
            try:
                if self.data_values[key]:
                    ret=True
                else:
                    ret=False
            except:
                ret=False

            if value == 'exist':
                return ret
            else:
                return not ret

        return ret


    def make_suggestion(self,*args,**kwargs):
        def make_banner(st):
            return '{}\n{}'.format(st,'-'*len(st))

        for key in self.keys_ordered:
            rule_idx=0
            while rule_idx < len (self.rules):
                rule=self.rules[rule_idx]
                rulekeys=[fact['key'] for fact in rule['facts']]
                if key not in rulekeys:
                    rule_idx+=1
                else:
                    clean=None
                    for fact in rule['facts']:
                        if key == fact['key']:
                            if self.apply_operation(fact):
                                clean = False
                            else:
                                clean = True
                                break
                    if clean:
                        del self.rules[rule_idx]
                        #break
                        #rule_idx+=1
                    elif clean==False:
                        #break
                        rule_idx+=1
                        pass


        out={'banner':None,'c':[],'h':[]}
        if self.rules:
            out['banner']=make_banner('Detected:')

        for rule in self.rules:
            for c in rule['consequences']:
                key=rule['facts'][0].get('key','None')
                keyval=self.data_values.get(key,None)
                if keyval:
                    if T_REPLACE in c:
                        try:
                            for li in keyval:
                                out['c'].append('-{}!'.format(c.replace(T_REPLACE,str(li))))
                        except:
                            out['c'].append('-{}!'.format(c.replace(T_REPLACE,keyval)))
                    else:
                        out['c'].append('-{}!'.format(c))
                else:
                    out['c'].append('-{}!'.format(c))

            if rule['hints']:
                for suggestion in rule['hints']:
                    out['h'].append('-{}'.format(suggestion))

        if out['c']:
            print(out['banner'])
            for c in out['c']:
                print(c)

        if out['h']:
            print('\n'+make_banner('Things that you can do:'))
            for h in out['h']:
                print(h)
        else:
            if out['c']:
                print('\n'+make_banner('You don\'t need to do any actions'))
