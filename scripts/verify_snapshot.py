"""Hash and compare a preserved directory to its source, without writing either."""
import argparse, hashlib, json, sys
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('snapshot',type=Path);p.add_argument('source',type=Path);a=p.parse_args()
def digest(path):
 h=hashlib.sha256()
 with path.open('rb') as f:
  for chunk in iter(lambda:f.read(4*1024*1024),b''):h.update(chunk)
 return h.hexdigest()
count=bad=0
for path in sorted(a.snapshot.rglob('*')):
 if not path.is_file() or path.is_symlink():continue
 rel=path.relative_to(a.snapshot);source=a.source/rel
 try:
  before=source.stat(); snap_hash=digest(path); src_hash=digest(source);after=source.stat(); stable=(before.st_size,before.st_mtime_ns)==(after.st_size,after.st_mtime_ns)
  ok=stable and snap_hash==src_hash
  row={'path':rel.as_posix(),'bytes':path.stat().st_size,'snapshot_sha256':snap_hash,'source_sha256':src_hash,'source_stable_during_read':stable,'equal':ok}
 except OSError as e:
  ok=False;row={'path':rel.as_posix(),'error':str(e),'equal':False}
 print(json.dumps(row),flush=True);count+=1;bad+=not ok
 if count%25==0:print(f'files={count} unequal_or_unverified={bad}',file=sys.stderr,flush=True)
print(f'TOTAL files={count} unequal_or_unverified={bad}',file=sys.stderr,flush=True)
sys.exit(1 if bad else 0)
