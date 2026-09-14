"""Optional local adapter, no shell invocation or automatic attacks."""
import json
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
MODES={'MD5':0,'MD4':900,'NTLM':1000,'SHA-1':100,'SHA-256':1400,'SHA-512':1700}
def available():return {'available':bool(shutil.which('hashcat') or shutil.which('hashcat.exe')),'modes':MODES,'attacks':['dictionary','lowercase-rule']}
def runner(algorithm,attack):
    exe=shutil.which('hashcat') or shutil.which('hashcat.exe')
    if not exe:raise ValueError('未找到 Hashcat，请安装后加入 PATH')
    if algorithm not in MODES or attack not in ('dictionary','lowercase-rule'):raise ValueError('不支持的 Hashcat 模式')
    def execute(job,target,algorithms,dictionary):
        with tempfile.TemporaryDirectory(prefix='snowedge-hashcat-') as directory:
            root=Path(directory);input_file=root/'input.hash';output=root/'result.txt'
            input_file.write_text(target+'\n',encoding='ascii')
            args=[exe,'-m',str(MODES[algorithm]),'-a','0',str(input_file),str(dictionary.resolve()),'--potfile-disable','--restore-disable','--logfile-disable','--outfile',str(output),'--outfile-format','2','--status','--status-json','--status-timer','1','--runtime','3600']
            if attack=='lowercase-rule':
                rules=root/'lower.rule';rules.write_text('l\n',encoding='ascii');args+=['-r',str(rules)]
            # Status output may contain the target: transient private file, never app logs.
            with (root/'status').open('w+b') as status:
                process=subprocess.Popen(args,stdout=status,stderr=subprocess.DEVNULL,cwd=directory,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
                try:
                    status_reader=(root/'status').open('rb')
                    while process.poll() is None:
                        if job['cancel'].wait(.25):
                            process.terminate();job['status']='cancelled';return
                        job['elapsed']+=.25
                        for line in status_reader:
                            try:
                                data=json.loads(line)
                                if 'progress' in data:job['hashes']=data['progress'][0];job['tried']=data['progress'][0];job['total']=data['progress'][1]
                                if 'devices' in data:job['speed']=sum(d.get('speed',0) for d in data['devices'])
                                if 'estimated_stop' in data:job['estimated_stop']=data['estimated_stop']
                            except (ValueError,TypeError):pass
                    if output.exists():
                        line=output.read_text(encoding='utf-8',errors='replace').splitlines()[0]
                        if line.startswith('$HEX[') and line.endswith(']'):line=bytes.fromhex(line[5:-1]).decode('utf-8',errors='replace')
                        job['result']={'algorithm':algorithm,'plaintext':line};job['status']='matched'
                    else:job['status']='not_found' if process.returncode==1 else 'error'
                    status.seek(0)
                    for line in status:
                        try:
                            data=json.loads(line)
                            if 'progress' in data:job['hashes']=data['progress'][0];job['tried']=data['progress'][0];job['total']=data['progress'][1]
                            if 'estimated_stop' in data:job['estimated_stop']=data['estimated_stop']
                        except (ValueError,TypeError):pass
                finally:
                    if 'status_reader' in locals():status_reader.close()
                    if process.poll() is None:
                        process.terminate()
                        try:process.wait(timeout=5)
                        except subprocess.TimeoutExpired:process.kill();process.wait()
    return execute
