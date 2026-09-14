from fastapi import APIRouter, HTTPException, UploadFile, File, Response
from pydantic import BaseModel, Field
from .services.hash_analysis.detector import analyze
from .services.hash_analysis.dictionary import manager
from .services.hash_analysis.matcher import matcher
from .services.hash_analysis import hashcat, providers

router=APIRouter(prefix='/api/hash',tags=['本地数据分析'])
class MatchInput(BaseModel):
    value:str=Field(min_length=1,max_length=32000)
    algorithms:list[str]=Field(min_length=1,max_length=12)
    dictionary:str='common'
    engine:str='local'
    attack:str='dictionary'
    confirmed:bool=False
class LookupInput(BaseModel):
    value:str=Field(min_length=1,max_length=32000)
    provider:str
    confirmed:bool=False
class Toggle(BaseModel):
    enabled:bool

def call(fn,*args):
    try:return fn(*args)
    except ValueError as exc:raise HTTPException(400,str(exc)) from None

@router.get('/dictionaries')
def dictionaries():return {'items':manager.items()}
@router.post('/dictionaries')
def upload(file:UploadFile=File(...)):
    try:return call(manager.import_file,file.file,file.filename or '')
    finally:file.file.close()
@router.patch('/dictionaries/{key}')
def toggle(key:str,data:Toggle):call(manager.update,key,data.enabled);return {'ok':True}
@router.delete('/dictionaries/{key}')
def delete_dictionary(key:str):
    with matcher.lock:
        if any(j['status'] in ('queued','running') for j in matcher.jobs.values()):raise HTTPException(409,'请先结束本地匹配任务再删除字典')
    call(manager.update,key,None,True);return {'ok':True}
@router.post('/jobs')
def start(data:MatchInput,response:Response):
    response.headers['Cache-Control']='no-store'
    if data.engine not in ('local','hashcat'):raise HTTPException(400,'未知执行引擎')
    runner=None
    if data.engine=='hashcat':
        if not data.confirmed or len(data.algorithms)!=1:raise HTTPException(400,'请确认授权并选择一个算法')
        runner=call(hashcat.runner,data.algorithms[0],data.attack)
    return call(matcher.start,data.value,data.algorithms,data.dictionary,runner)
@router.get('/jobs/{key}')
def job(key:str,response:Response):
    response.headers['Cache-Control']='no-store';return call(matcher.get,key)
@router.post('/jobs/{key}/cancel')
def cancel(key:str):call(matcher.cancel,key);return {'ok':True}
@router.delete('/jobs/{key}')
def clear(key:str):call(matcher.clear,key);return {'ok':True}
@router.get('/advanced')
def advanced():return {'hashcat':hashcat.available(),'providers':list(providers.providers),'online_default':False}
@router.post('/lookup')
def lookup(data:LookupInput,response:Response):
    response.headers['Cache-Control']='no-store'
    return call(providers.lookup,data.provider,data.value,data.confirmed)
