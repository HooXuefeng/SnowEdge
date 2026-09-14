import json
import os
from pathlib import Path
import threading
import uuid

class DictionaryManager:
    def __init__(self,root=None):
        self.root=Path(root or Path(os.environ.get('SNOWEDGE_STATE_DIR','.runtime'))/'hash-dictionaries')
        self.common=Path(__file__).resolve().parents[3]/'data/passwords/common.txt'
        self.lock=threading.RLock()
    def metadata(self):
        path=self.root/'index.json'
        return json.loads(path.read_text(encoding='utf-8')) if path.exists() else {}
    def save(self,data):
        self.root.mkdir(parents=True,exist_ok=True)
        tmp=self.root/'index.tmp';tmp.write_text(json.dumps(data,ensure_ascii=False),encoding='utf-8');tmp.replace(self.root/'index.json')
    def items(self):
        with self.lock:
            data=self.metadata()
            common={'id':'common','name':'SnowEdge Common','enabled':data.get('common',{}).get('enabled',True),'entries':sum(1 for _ in self.common.open(encoding='utf-8')),'bytes':self.common.stat().st_size,'builtin':True}
            return [common]+[v for k,v in data.items() if k!='common']
    def path(self,key):
        if key=='common':return self.common
        if not __import__('re').fullmatch('[a-f0-9]{32}',key):raise ValueError('字典不存在')
        if key not in self.metadata():raise ValueError('字典不存在')
        return self.root/(key+'.txt')
    def selected(self,key):
        item=next((x for x in self.items() if x['id']==key),None)
        if not item or not item['enabled']:raise ValueError('请选择已启用的字典')
        return item,self.path(key)
    def import_file(self,file,name):
        if not name.lower().endswith('.txt'):raise ValueError('只支持 UTF-8 TXT 字典')
        self.root.mkdir(parents=True,exist_ok=True);key=uuid.uuid4().hex;path=self.root/(key+'.txt')
        total=count=0
        try:
            with path.open('xb') as output:
                while True:
                    line=file.readline(4098)
                    if not line:break
                    total+=len(line)
                    if total>256*1024*1024:raise ValueError('单个字典最多 256 MB')
                    if len(line)>4096:raise ValueError('每行密码最多 4096 字节')
                    line.decode('utf-8-sig')
                    if b'\0' in line:raise ValueError('字典不能含 NUL 字节')
                    output.write(line);count+=1
            if not count:raise ValueError('字典为空')
            item={'id':key,'name':Path(name.replace('\\','/')).name[:100],'enabled':False,'entries':count,'bytes':total,'builtin':False}
            with self.lock:
                data=self.metadata();data[key]=item;self.save(data)
            return item
        except Exception:
            path.unlink(missing_ok=True);raise ValueError('导入失败：请使用非空 UTF-8 TXT，单行不超过 4096 字节，总大小不超过 256 MB') from None
    def update(self,key,enabled=None,delete=False):
        with self.lock:
            path=self.path(key);data=self.metadata()
            if delete:
                if key=='common':raise ValueError('内置字典不能删除，可禁用')
                path.unlink(missing_ok=True);data.pop(key)
            else:
                data.setdefault(key,{'enabled':True})['enabled']=enabled
            self.save(data)

manager=DictionaryManager()
