"""Check the frozen Python environment without importing optional packages."""
import importlib.metadata
from pathlib import Path
import re


def differences(path):
    missing=[]
    for line in Path(path).read_text(encoding='utf-8-sig').splitlines():
        line=line.strip()
        if not line or line.startswith('#'):continue
        match=re.fullmatch(r'([A-Za-z0-9_.-]+)==([^\s;]+)',line)
        if not match:raise ValueError('Formato de lock no permitido')
        name,expected=match.groups()
        try:actual=importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:actual=None
        if actual!=expected:missing.append({'paquete':name,'requerida':expected,'instalada':actual})
    return missing


if __name__=='__main__':
    import json
    result=differences(Path(__file__).resolve().parents[1]/'requirements-portable.lock.txt')
    print(json.dumps({'diferencias':result},ensure_ascii=False))
    raise SystemExit(bool(result))
