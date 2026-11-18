"""Pinned MiniLM ONNX on CPU. No remote inference or executable model code."""
from functools import lru_cache
import hashlib
import json
import os
from pathlib import Path
import re
from threading import Lock
import urllib.request

MODEL='sentence-transformers/all-MiniLM-L6-v2'
REVISION='1110a243fdf4706b3f48f1d95db1a4f5529b4d41'
DIMENSIONS=384
ARTIFACT='onnx/model_quint8_avx2.onnx'
ARTIFACT_SHA={
 'model_quint8_avx2.onnx':'b941bf19f1f1283680f449fa6a7336bb5600bdcd5f84d10ddc5cd72218a0fd21',
 'tokenizer.json':'be50c3628f2bf5bb5e3a7f17b1f74611b2561a3a27eeab05e5aa30f411572037',
 'tokenizer_config.json':'acb92769e8195aabd29b7b2137a9e6d6e25c476a4f15aa4355c233426c61576b',
 'config.json':'953f9c0d463486b10a6871cc2fd59f223b2c70184f49815e7efbcab5d8908b41',
}
ROOT=Path(__file__).resolve().parents[2]


def folder():
    return Path(os.getenv('RAG_MODEL_DIRECTORY',str(ROOT/'.local/rag/models/minilm'))).resolve()


def prepare_model():
    target=folder();target.mkdir(parents=True,exist_ok=True)
    manifest={'modelo':MODEL,'revision':REVISION,'dimension':DIMENSIONS,'licencia':'Apache-2.0',
              'artefacto':ARTIFACT,'pooling':'attention-mask-mean','normalizacion':'L2','max_tokens':256,'archivos':{}}
    for name in (ARTIFACT,'tokenizer.json','tokenizer_config.json','config.json'):
        path=target/Path(name).name
        if not path.exists():
            temporary=path.with_suffix('.part')
            try:
                with urllib.request.urlopen(f'https://huggingface.co/{MODEL}/resolve/{REVISION}/{name}',timeout=60) as response,temporary.open('wb') as stream:
                    total=0
                    while chunk:=response.read(1048576):
                        total+=len(chunk)
                        if total>120_000_000:raise ValueError('Artefacto excede el limite')
                        stream.write(chunk)
                temporary.replace(path)
            finally:temporary.unlink(missing_ok=True)
        manifest['archivos'][path.name]=hashlib.sha256(path.read_bytes()).hexdigest()
        if manifest['archivos'][path.name]!=ARTIFACT_SHA[path.name]:raise RuntimeError('Artefacto distinto de la revision verificada')
    (target/'manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    return manifest


def catalog_text(name,description):
    # Only official catalog text enters document embeddings. Never event payloads.
    clean=re.sub(r'\(Citation:[^)]*\)','',description or '')
    clean=re.sub(r'\[([^]]+)\]\([^)]+\)',r'\1',clean)
    clean=re.sub(r'<[^>]*>|[`#*]',' ',clean)
    return name+'. '+re.sub(r'\s+',' ',clean).strip()


class Encoder:
    def __init__(self):
        import numpy as np
        import onnxruntime as ort
        from tokenizers import Tokenizer
        self.np=np;self.lock=Lock();target=folder()
        if not (target/'manifest.json').is_file():raise RuntimeError('Prepare el modelo con python -m scripts.embed_mitre --preparar-modelo')
        self.manifest=json.loads((target/'manifest.json').read_text(encoding='utf-8'))
        if self.manifest.get('revision')!=REVISION or self.manifest.get('dimension')!=DIMENSIONS or self.manifest.get('archivos')!=ARTIFACT_SHA:
            raise RuntimeError('Modelo de embeddings incompatible')
        for name,digest in self.manifest['archivos'].items():
            if Path(name).name!=name or hashlib.sha256((target/name).read_bytes()).hexdigest()!=digest:
                raise RuntimeError('Checksum de modelo incorrecto')
        self.tokenizer=Tokenizer.from_file(str(target/'tokenizer.json'))
        self.tokenizer.enable_truncation(max_length=256)
        self.tokenizer.enable_padding(pad_id=0,pad_token='[PAD]')
        options=ort.SessionOptions();options.intra_op_num_threads=2;options.inter_op_num_threads=1
        self.session=ort.InferenceSession(str(target/Path(ARTIFACT).name),sess_options=options,providers=['CPUExecutionProvider'])

    def encode(self,texts):
        np=self.np
        with self.lock:
            tokens=self.tokenizer.encode_batch(texts)
            inputs={'input_ids':np.array([t.ids for t in tokens],dtype=np.int64),
                    'attention_mask':np.array([t.attention_mask for t in tokens],dtype=np.int64),
                    'token_type_ids':np.array([t.type_ids for t in tokens],dtype=np.int64)}
            outputs=self.session.run(None,{i.name:inputs[i.name] for i in self.session.get_inputs()})
        hidden=outputs[0]
        mask=inputs['attention_mask'][...,None].astype(np.float32)
        vectors=(hidden*mask).sum(axis=1)/np.maximum(mask.sum(axis=1),1) if hidden.ndim==3 else hidden
        vectors=vectors/np.maximum(np.linalg.norm(vectors,axis=1,keepdims=True),1e-12)
        if vectors.shape!=(len(texts),DIMENSIONS) or not np.isfinite(vectors).all():raise RuntimeError('Vector de embeddings invalido')
        return vectors.astype(np.float32).tolist()


@lru_cache(maxsize=1)
def encoder():return Encoder()
