"""Bounded transient jobs. Sensitive inputs/results are never persisted."""
from concurrent.futures import ThreadPoolExecutor
import threading
import time
import secrets
from .algorithms import digest, SUPPORTED
from .detector import analyze
from .dictionary import manager

class HashMatcher:
    def __init__(self):
        self.pool=ThreadPoolExecutor(max_workers=2,thread_name_prefix='local-hash')
        self.lock=threading.RLock();self.jobs={}
    def start(self,value,algorithms,dictionary='common',runner=None):
        result=analyze(value);target=result['normalized']
        if not algorithms or any(a not in SUPPORTED for a in algorithms):raise ValueError('请选择支持本地匹配的算法')
        if result['representation'] not in ('Hex 表示形式','Base64 表示形式') or any(a not in result['candidates'] for a in algorithms):raise ValueError('算法与输入长度不匹配')
        item,path=manager.selected(dictionary)
        with self.lock:
            now=time.monotonic()
            self.jobs={k:v for k,v in self.jobs.items() if v['status'] in ('queued','running') or now-v['updated']<900}
            if len(self.jobs)>=32 or sum(j['status'] in ('queued','running') for j in self.jobs.values())>=4:raise ValueError('本地任务已满，请等待或取消任务')
            key=secrets.token_urlsafe(24)
            job={'id':key,'status':'queued','tried':0,'hashes':0,'total':item['entries'],'elapsed':0,'speed':0,'result':None,'algorithms':algorithms,'dictionary':item['name'],'updated':now,'cancel':threading.Event()}
            self.jobs[key]=job
        self.pool.submit(self.run,job,target,algorithms,path,runner)
        return self.get(key)
    def run(self,job,target,algorithms,path,runner):
        start=time.monotonic();job['status']='running'
        try:
            if job['cancel'].is_set():job['status']='cancelled';return
            if runner:
                runner(job,target,algorithms,path)
            else:
                with path.open(encoding='utf-8-sig',newline='') as stream:
                    for line in stream:
                        if job['cancel'].is_set():job['status']='cancelled';return
                        password=line.rstrip('\r\n');job['tried']+=1
                        for algorithm in algorithms:
                            actual=digest(password,algorithm);job['hashes']+=1
                            if actual.lower()==target.lower():
                                job['result']={'algorithm':algorithm,'plaintext':password};job['status']='matched';return
                        job['elapsed']=time.monotonic()-start;job['speed']=job['hashes']/max(job['elapsed'],.001)
                job['status']='not_found'
        except Exception:
            job['status']='error';job['error']='本地任务失败，请检查字典是否存在及工具运行环境。'
        finally:
            job['elapsed']=time.monotonic()-start;job['speed']=job['hashes']/max(job['elapsed'],.001);job['updated']=time.monotonic()
    def get(self,key):
        with self.lock:
            job=self.jobs.get(key)
            if not job:raise ValueError('任务不存在或已清除')
            if job['status'] not in ('queued','running') and time.monotonic()-job['updated']>=900:
                del self.jobs[key];raise ValueError('任务已过期')
            return {k:v for k,v in job.items() if k not in ('cancel','updated')}
    def cancel(self,key):
        with self.lock:
            self.get(key);self.jobs[key]['cancel'].set()
    def clear(self,key):
        with self.lock:
            self.cancel(key)
            self.jobs.pop(key,None)
matcher=HashMatcher()
