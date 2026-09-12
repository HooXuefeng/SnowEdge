from __future__ import annotations
import argparse,json,os,signal,subprocess,sys,time,urllib.request
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
RUNTIME=ROOT/".runtime"; STATE=RUNTIME/"state.json"; STOP=RUNTIME/"stop.signal"

def health()->bool:
    try:
        with urllib.request.urlopen("http://127.0.0.1:8000/api/health",timeout=.7) as r:return r.status==200
    except Exception:return False

def write_state(data):
    RUNTIME.mkdir(parents=True,exist_ok=True);STATE.write_text(json.dumps(data,ensure_ascii=False,indent=2),encoding="utf-8")

def child_flags():
    if os.name=="nt":return {"creationflags":getattr(subprocess,"CREATE_NO_WINDOW",0)|getattr(subprocess,"CREATE_NEW_PROCESS_GROUP",0)}
    return {"start_new_session":True}

def terminate(proc):
    if not proc or proc.poll() is not None:return
    try:
        if os.name=="nt" and hasattr(signal,"CTRL_BREAK_EVENT"):proc.send_signal(signal.CTRL_BREAK_EVENT)
        else:proc.terminate()
        proc.wait(timeout=5);return
    except Exception:pass
    try:proc.terminate();proc.wait(timeout=3);return
    except Exception:pass
    try:proc.kill()
    except Exception:pass

def serve():
    RUNTIME.mkdir(parents=True,exist_ok=True);STOP.unlink(missing_ok=True)
    launch_log=(RUNTIME/"launcher.log").open("a",encoding="utf-8")
    try:
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] supervisor start",file=launch_log,flush=True)
        restore=subprocess.run([sys.executable,str(ROOT/"scripts/apply-pending-restore.py")],cwd=ROOT,stdout=launch_log,stderr=launch_log,text=True)
        if restore.returncode!=0:raise RuntimeError("pending restore failed; see launcher.log")
        migrate=subprocess.run([sys.executable,str(ROOT/"scripts/db-upgrade.py")],cwd=ROOT,stdout=launch_log,stderr=launch_log,text=True)
        if migrate.returncode!=0:raise RuntimeError("database migration failed; see launcher.log")
        env=os.environ.copy();env["JOB_EMBEDDED_WORKERS"]="0";env["JOB_IMMEDIATE_ACCELERATOR"]="false"
        web_log=(RUNTIME/"web.log").open("ab");worker_log=(RUNTIME/"worker.log").open("ab")
        worker=subprocess.Popen([sys.executable,str(ROOT/"worker.py"),"--name","personal-worker"],cwd=ROOT,env=env,stdout=worker_log,stderr=worker_log,**child_flags())
        web=subprocess.Popen([sys.executable,str(ROOT/"run.py")],cwd=ROOT,env=env,stdout=web_log,stderr=web_log,**child_flags())
        write_state({"supervisor_pid":os.getpid(),"web_pid":web.pid,"worker_pid":worker.pid,"started_at":time.time(),"status":"running"})
        while not STOP.exists():
            if web.poll() is not None or worker.poll() is not None:break
            time.sleep(.5)
        terminate(web);terminate(worker)
        web_log.close();worker_log.close();write_state({"supervisor_pid":os.getpid(),"web_pid":web.pid,"worker_pid":worker.pid,"stopped_at":time.time(),"status":"stopped"})
        STOP.unlink(missing_ok=True);return 0
    except Exception as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}",file=launch_log,flush=True);write_state({"supervisor_pid":os.getpid(),"status":"error","error":f"{type(exc).__name__}: {exc}"});return 1
    finally:launch_log.close()

def start():
    if health():print(json.dumps({"ok":True,"already_running":True}));return 0
    RUNTIME.mkdir(parents=True,exist_ok=True);STOP.unlink(missing_ok=True)
    kwargs=child_flags();kwargs.update({"cwd":ROOT,"stdout":subprocess.DEVNULL,"stderr":subprocess.DEVNULL,"close_fds":True})
    subprocess.Popen([sys.executable,str(Path(__file__).resolve()),"--serve"],**kwargs)
    print(json.dumps({"ok":True,"started":True}));return 0

def stop():
    RUNTIME.mkdir(parents=True,exist_ok=True);STOP.write_text("stop",encoding="utf-8")
    deadline=time.time()+12
    while time.time()<deadline and health():time.sleep(.3)
    print(json.dumps({"ok":not health(),"stopped":not health()}));return 0 if not health() else 1

def status():
    data={}
    try:data=json.loads(STATE.read_text(encoding="utf-8"))
    except Exception:pass
    data["health"]=health();print(json.dumps(data,ensure_ascii=False));return 0

def main():
    mode=sys.argv[1] if len(sys.argv)>1 else "--status"
    fn={"--start":start,"--stop":stop,"--status":status,"--serve":serve}.get(mode)
    if not fn:print("Usage: personal-supervisor.py --start|--stop|--status|--serve");return 2
    return fn()
if __name__=="__main__":raise SystemExit(main())
