"""Authenticated encrypted transfer of private TacticLens state. No uploads."""
import argparse
from datetime import datetime,timezone
import hashlib
import io
import json
from pathlib import Path,PurePosixPath
import zipfile

from cryptography.fernet import Fernet
from scripts.private_paths import protect

ROOT=Path(__file__).resolve().parents[1]


def safe_member(name):
    path=PurePosixPath(name)
    if path.is_absolute() or '..' in path.parts or '\\' in name or ':' in name:
        raise ValueError('Ruta de archivo no permitida')
    return path


def unpack(token,key,destination):
    destination=Path(destination).resolve()
    if destination.exists():raise ValueError('El destino existe; no sobrescribir archivos privados')
    # Authentication is verified before any plaintext file is extracted.
    plaintext=Fernet(key).decrypt(token)
    with zipfile.ZipFile(io.BytesIO(plaintext)) as bundle:
        members=bundle.infolist()
        if sum(member.file_size for member in members)>2_000_000_000:raise ValueError('Paquete demasiado grande')
        for member in members:
            safe_member(member.filename)
            if (member.external_attr>>16)&0o170000==0o120000:raise ValueError('No se admiten enlaces simbolicos')
        manifest=json.loads(bundle.read('transfer-manifest.json'))
        expected=manifest['files']
        actual={m.filename for m in members if not m.is_dir()}-{'transfer-manifest.json'}
        if actual!=set(expected) or len(actual)+1!=sum(not m.is_dir() for m in members):raise ValueError('Inventario inconsistente o entradas duplicadas')
        for name,digest in expected.items():
            if hashlib.sha256(bundle.read(name)).hexdigest()!=digest:raise ValueError('Contenido no coincide con manifiesto')
        destination.mkdir(parents=True)
        protect(destination)
        for member in members:
            target=destination.joinpath(*safe_member(member.filename).parts)
            if not target.is_relative_to(destination):raise ValueError('Ruta fuera del destino')
            if member.is_dir():target.mkdir(parents=True,exist_ok=True)
            else:
                target.parent.mkdir(parents=True,exist_ok=True)
                with target.open('xb') as stream:stream.write(bundle.read(member))
    return {'archivos':len(actual),'destino':str(destination),'autenticidad_y_hashes_verificados':True}


def pack(directory,output,key_path):
    directory=Path(directory).resolve();output=Path(output).resolve();key_path=Path(key_path).resolve()
    private=(ROOT/'.local').resolve()
    if not all(path.is_relative_to(private) for path in (directory,output,key_path)):raise ValueError('Paquete y clave deben permanecer en .local/')
    if output.exists() or key_path.exists():raise ValueError('Ya existe paquete/clave; no sobrescribir')
    files=[(p,'database/'+p.name) for p in (directory/'database').iterdir() if p.is_file()]
    files += [(ROOT/'.env','config/.env')]
    files += [(p,'config/frontend/'+p.name) for p in (ROOT/'frontend').glob('.env*') if p.is_file() and p.name!='.env.example']
    # Keep all private development artifacts, cached model/STIX and past backups,
    # but never recursively pack this migration or process-generated dependencies.
    for path in (ROOT/'.local').rglob('*'):
        relative=path.relative_to(ROOT/'.local')
        if path.is_file() and relative.parts[0]!='migration':files.append((path,'local-state/'+relative.as_posix()))
    names=[name for _,name in files]
    if len(names)!=len(set(names)):raise ValueError('Nombres duplicados en paquete')
    manifest={'created_utc':datetime.now(timezone.utc).isoformat(),'files':{}}
    buffer=io.BytesIO()
    with zipfile.ZipFile(buffer,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=6) as bundle:
        for path,name in files:
            data=path.read_bytes();manifest['files'][name]=hashlib.sha256(data).hexdigest();bundle.writestr(name,data)
        bundle.writestr('transfer-manifest.json',json.dumps(manifest,ensure_ascii=False,indent=2))
    key=Fernet.generate_key();token=Fernet(key).encrypt(buffer.getvalue())
    output.parent.mkdir(parents=True,exist_ok=True);key_path.parent.mkdir(parents=True,exist_ok=True)
    protect(output.parent);protect(key_path.parent)
    with key_path.open('xb') as stream:stream.write(key)
    with output.open('xb') as stream:stream.write(token)
    return {'paquete':str(output),'bytes':len(token),'sha256':hashlib.sha256(token).hexdigest(),
            'clave_separada':str(key_path),'archivos':len(files),
            'advertencia':'Transferir la clave por un canal separado; no subir ninguno de estos archivos a GitHub'}


def main():
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='action',required=True)
    encrypt=sub.add_parser('pack');encrypt.add_argument('--directory',type=Path,required=True);encrypt.add_argument('--output',type=Path,required=True);encrypt.add_argument('--key-file',type=Path,required=True)
    decrypt=sub.add_parser('unpack');decrypt.add_argument('--input',type=Path,required=True);decrypt.add_argument('--key-file',type=Path,required=True);decrypt.add_argument('--destination',type=Path,required=True)
    args=parser.parse_args()
    if args.action=='pack':result=pack(args.directory,args.output,args.key_file)
    else:result=unpack(args.input.read_bytes(),args.key_file.read_bytes().strip(),args.destination)
    print(json.dumps(result,ensure_ascii=False,indent=2))


if __name__=='__main__':main()
