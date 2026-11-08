"""Verify the contiguous original PE transform descriptors against modeled events."""
import argparse
import hashlib
import json
import mmap
import struct
from pathlib import Path
import pefile

p=argparse.ArgumentParser()
p.add_argument('pe',type=Path)
p.add_argument('data_trace',type=Path)
p.add_argument('vmp_trace',type=Path)
a=p.parse_args()
with a.pe.open('rb') as f:
    if hashlib.file_digest(f,'sha256').hexdigest()!='d5c2fb538f4020a71060b553127259fcd5d3131beb89a4ec26a7d6ccfa9dfbfd':raise ValueError('wrong PE')
data=json.loads(a.data_trace.read_text(encoding='utf-8-sig'))['parent_data_events']
vmp=json.loads(a.vmp_trace.read_text(encoding='utf-8-sig'))['parent_vmp_events']
pe=pefile.PE(str(a.pe),fast_load=True)
sections={s.Name.rstrip(b'\0').decode():s for s in pe.sections}
offset=0x1f3b88;mask=0x4f56789a;out=[]
with a.pe.open('rb') as f,mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ) as image:
    for name,expected_events in [('.data',data),('.vmp0',vmp),('_RDATA',None)]:
        header=offset;rva,size,count=struct.unpack_from('<III',image,offset);offset+=12
        sec=sections[name]
        if rva!=sec.VirtualAddress or size!=sec.SizeOfRawData or count>200000:raise ValueError(f'unexpected section header {name}')
        if expected_events is not None and count!=len(expected_events):raise ValueError(f'event count mismatch {name}')
        last=0;total=0
        for i in range(count):
            begin,end=struct.unpack_from('<II',image,offset+8*i);begin^=mask;end^=mask
            if not rva<=begin<=end<rva+max(sec.SizeOfRawData,sec.Misc_VirtualSize) or begin<last:raise ValueError(f'bad range {name} {i}')
            if expected_events is not None:
                e=expected_events[i]
                if int(e['data'],16)!=pe.OPTIONAL_HEADER.ImageBase+begin or e['length']!=end-begin+1:raise ValueError(f'event mismatch {name} {i}')
            last=end+1;total+=end-begin+1
        offset+=8*count
        out.append({'section':name,'header_file_offset':hex(header),'rva':hex(rva),'raw_size':size,
                    'descriptors':count,'bytes_described':total,'observed_events_match':expected_events is not None})
print(json.dumps({'mask':hex(mask),'sections':out,'next_file_offset':hex(offset),
                  'warning':'Original table descriptors and synthetic event correspondence do not establish real execution.'},indent=2))
