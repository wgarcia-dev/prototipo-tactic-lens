"""Detach only the local development processes; keep logs outside Git."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]


def start(mode):
    directory=ROOT/'.local/run-local';directory.mkdir(parents=True,exist_ok=True)
    if mode=='backend':command=[sys.executable,'-m','scripts.local_server']
    elif mode=='frontend':
        node=shutil.which('node')
        if not node:raise RuntimeError('Falta Node en PATH')
        command=[node,str(ROOT/'frontend/node_modules/vite/bin/vite.js'),str(ROOT/'frontend'),
                 '--host','127.0.0.1','--port','5173','--strictPort']
    else:raise ValueError('Proceso no permitido')
    options={'creationflags':subprocess.DETACHED_PROCESS|subprocess.CREATE_NEW_PROCESS_GROUP} if os.name=='nt' else {'start_new_session':True}
    with (directory/(mode+'.out.log')).open('ab') as output,(directory/(mode+'.err.log')).open('ab') as error:
        process=subprocess.Popen(command,cwd=ROOT,stdin=subprocess.DEVNULL,stdout=output,stderr=error,
                                 close_fds=True,**options)
    return {'pid':process.pid}


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('mode',choices=('backend','frontend'));args=parser.parse_args()
    print(json.dumps(start(args.mode)))
