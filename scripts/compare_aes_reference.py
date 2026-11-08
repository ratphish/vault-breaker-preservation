"""Compare synthetic-model writes against independent AES-128 counter-mode bytes."""
import argparse,collections,json
from pathlib import Path
from Crypto.Cipher import AES
p=argparse.ArgumentParser();p.add_argument('trace',type=Path);a=p.parse_args();x=json.loads(a.trace.read_text(encoding='utf-8-sig'));groups=collections.defaultdict(list)
for row in x['rdata_write_samples']:groups[row['transform_index']].append(row)
total=0;all_ok=True
for i,entry in enumerate(x['transform_entries']):
 rows=groups[i];stream=bytes(r['cl'] for r in rows);key=bytes.fromhex(entry['rcx_bytes'])[:16];counter=int.from_bytes(bytes.fromhex(entry['rdx_bytes'])[:16],'big');cipher=AES.new(key,AES.MODE_ECB);ref=b''.join(cipher.encrypt(((counter+j)%(1<<128)).to_bytes(16,'big')) for j in range((len(stream)+15)//16))[:len(stream)]
 key_matches=sum(u==v for u,v in zip(stream,ref));output_matches=sum(r.get('after')==(r.get('before',-1)^v) for r,v in zip(rows,ref));start=int(entry['r8'],16);contiguous=all(int(r['address'],16)==start+j for j,r in enumerate(rows));ok=key_matches==len(rows) and output_matches==len(rows) and contiguous;all_ok &= ok;total+=len(rows)
 print(json.dumps({'call':i,'declared_bytes':int(entry['r9'],16),'observed_bytes':len(rows),'keystream_matches':key_matches,'output_matches':output_matches,'addresses_contiguous':contiguous,'all_match':ok}))
print(json.dumps({'kind':'summary','calls':len(x['transform_entries']),'observed_bytes':total,'all_match':all_ok}))
if not all_ok:raise SystemExit(1)
