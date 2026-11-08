"""Summarize bounded other-type and oversized package scans without copying payloads."""
import argparse,collections,json,re
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('research',type=Path);a=p.parse_args();r=a.research
census=[json.loads(l) for l in (r/'package-entry-type-census.jsonl').read_text().splitlines() if l.startswith('{')];oversized=[json.loads(l) for l in (r/'package-oversized-entries.jsonl').read_text().splitlines() if l.startswith('{')];scanned=[json.loads(l) for l in (r/'vault-oversized-video-matches.jsonl').read_text(encoding='utf-16').splitlines() if l.startswith('{')];matches=[json.loads(l) for l in (r/'vault-other-types-matches.jsonl').read_text().splitlines() if l.startswith('{')]
if len(scanned)!=len(oversized) or len({x['tag'] for x in scanned})!=len(scanned):raise ValueError('missing or duplicate oversized results')
expected={x['tag']:x['size'] for x in oversized}
if {x['tag']:x['size'] for x in scanned}!=expected:raise ValueError('oversized entry/size mismatch')
if (r/'vault-oversized-video-errors.txt').stat().st_size:raise ValueError('oversized scan reported errors')
log=(r/'vault-other-types-scan.txt').read_text();m=re.search(r'TOTAL packages=(\d+) examined=(\d+) bytes=(\d+) errors=(\d+) oversized=(\d+) matches=(\d+)',log)
if not m:raise ValueError('missing final scan summary')
pkgs,entries,byte_count,errors,skipped,n=map(int,m.groups())
if errors or skipped!=len(oversized) or n!=len(matches):raise ValueError('inconsistent other-type scan')
nonzero=sum(z['entries'] for z in census if z['type'] not in (0,8,16));total_bytes=sum(z['bytes'] for z in census if z['type'] not in (0,8,16))
if entries+len(scanned)!=nonzero or byte_count+sum(z['size'] for z in scanned)!=total_bytes:raise ValueError('census mismatch')
counts=collections.Counter(z['target'] for z in matches)
for z in scanned:
 for q in z['matches']:counts[q['target']]+=len(q['offsets'])
print(json.dumps({'packages':pkgs,'other_type_entries_checked':nonzero,'decoded_bytes':total_bytes,'oversized_entries':len(scanned),'raw_match_counts':dict(counts),'warning':'Four-byte matches in binary media are not verified references. Nested or differently encoded content remains unsearched.'}))
