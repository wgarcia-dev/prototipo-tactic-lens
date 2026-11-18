"""Recover private configuration/cache into a clone without overwriting real files."""
import argparse,json,shutil
from pathlib import Path
from scripts.private_paths import protect

ROOT=Path(__file__).resolve().parents[1]


def recover(source,root=ROOT):
    source=Path(source).resolve();root=Path(root).resolve();planned=[]
    config=source/'config/.env'
    if not config.is_file():raise ValueError('Falta config/.env en el paquete recibido')
    planned.append((config,root/'.env',root/'.env.example'))
    front=source/'config/frontend'
    if front.exists():planned += [(p,root/'frontend'/p.name,root/'frontend/.env.example') for p in front.iterdir() if p.is_file()]
    state=source/'local-state'
    for file in state.rglob('*'):
        if file.is_file():
            relative=file.relative_to(state)
            if relative.parts[0] in {'run-local','migration'}:continue
            planned.append((file,root/'.local'/relative,None))
    conflicts=[];copy=[];unchanged=0
    for src,dst,example in planned:
        if dst.exists():
            if dst.read_bytes()==src.read_bytes():unchanged+=1;continue
            if dst==root/'.local/rag/backup-pointer.json':
                a=json.loads(src.read_text(encoding='utf-8'));b=json.loads(dst.read_text(encoding='utf-8'))
                def relative_pointer(value):return str(value).replace('\\','/').rsplit('/.local/',1)[-1]
                if {k:v for k,v in a.items() if k!='manifest'}=={k:v for k,v in b.items() if k!='manifest'} and relative_pointer(a.get('manifest'))==relative_pointer(b.get('manifest')):
                    unchanged+=1;continue
            if not example or not example.is_file() or dst.read_bytes()!=example.read_bytes():
                conflicts.append(str(dst.relative_to(root)));continue
        copy.append((src,dst))
    if conflicts:raise ValueError('No se sobrescriben archivos privados existentes: '+', '.join(conflicts[:10]))
    private=root/'.local';private.mkdir(parents=True,exist_ok=True);protect(private)
    for src,dst in copy:
        dst.parent.mkdir(parents=True,exist_ok=True)
        if dst.name.startswith('.env'):
            if not dst.exists():dst.touch()
            protect(dst)
        shutil.copy2(src,dst)
    # Relocate the known private backup pointer, never arbitrary paths/secrets.
    pointer=root/'.local/rag/backup-pointer.json'
    if pointer.exists():
        obj=json.loads(pointer.read_text(encoding='utf-8'));old=str(obj.get('manifest','')).replace('\\','/')
        if '/.local/' in old:
            target=root/'.local'/old.rsplit('/.local/',1)[1]
            if target.resolve().is_relative_to(root/'.local') and target.is_file():
                obj['manifest']=str(target);pointer.write_text(json.dumps(obj),encoding='utf-8')
    return {'copiados':len(copy),'ya_identicos':unchanged,'secretos_impresos':False,'base_modificada':False}


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source',type=Path,required=True);args=p.parse_args()
    print(json.dumps(recover(args.source),ensure_ascii=False))
