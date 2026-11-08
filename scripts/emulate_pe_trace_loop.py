"""Run a bounded, synthetic Unicorn model of a PE entry; no host OS or network services."""
import argparse,collections,json,mmap,struct,sys,time,hashlib
from Crypto.Cipher import AES
from pathlib import Path
import pefile
from unicorn import Uc,UcError,UC_ARCH_X86,UC_MODE_64,UC_HOOK_CODE,UC_HOOK_INTR,UC_HOOK_MEM_INVALID,UC_HOOK_MEM_WRITE,UC_HOOK_MEM_READ,UC_PROT_ALL
from unicorn.x86_const import UC_X86_REG_RIP,UC_X86_REG_RSP,UC_X86_REG_GS_BASE,UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9,UC_X86_REG_RAX,UC_X86_REG_RBX,UC_X86_REG_RBP,UC_X86_REG_RSI,UC_X86_REG_RDI,UC_X86_REG_R10,UC_X86_REG_R11,UC_X86_REG_R12,UC_X86_REG_R13,UC_X86_REG_R14,UC_X86_REG_R15,UC_X86_REG_EFLAGS
p=argparse.ArgumentParser();p.add_argument('pe',type=Path);p.add_argument('--count',type=int,default=100000);p.add_argument('--timeout-ms',type=int,default=30000);p.add_argument('--intercept-imports',action='store_true');p.add_argument('--follow-thread',action='store_true');p.add_argument('--stub-virtualprotect',action='store_true');p.add_argument('--accelerate-aes',action='store_true');p.add_argument('--export-synthetic-rdata',type=Path);p.add_argument('--resume-parent',action='store_true');p.add_argument('--stub-parent-virtualprotect',action='store_true');p.add_argument('--allow-text-transforms',action='store_true');p.add_argument('--native-event',type=int);p.add_argument('--max-events',type=int,default=110000);p.add_argument('--output-report',type=Path);p.add_argument('--trace-after',type=int,required=True);a=p.parse_args()
if a.native_event is not None and (not a.accelerate_aes or a.native_event < 0):raise ValueError('--native-event requires acceleration and a nonnegative event index')
if a.follow_thread and not a.intercept_imports:raise ValueError('--follow-thread requires --intercept-imports')
if a.stub_virtualprotect and not a.follow_thread:raise ValueError('--stub-virtualprotect requires --follow-thread')
if a.accelerate_aes and not a.stub_virtualprotect:raise ValueError('--accelerate-aes requires --stub-virtualprotect')
if a.resume_parent and not a.accelerate_aes:raise ValueError('--resume-parent requires --accelerate-aes')
if a.stub_parent_virtualprotect and not a.resume_parent:raise ValueError('--stub-parent-virtualprotect requires --resume-parent')
if a.allow_text_transforms and not a.stub_parent_virtualprotect:raise ValueError('--allow-text-transforms requires --stub-parent-virtualprotect')
if a.output_report is not None:
 out_report=a.output_report.resolve()
 if out_report.is_relative_to(Path(__file__).resolve().parents[1]) or out_report.exists() or not out_report.parent.is_dir():raise ValueError('report must be a new file outside the repository')
if a.export_synthetic_rdata is not None:
 if not a.accelerate_aes:raise ValueError('export requires --accelerate-aes')
 out=a.export_synthetic_rdata.resolve()
 if out.is_relative_to(Path(__file__).resolve().parents[1]):raise ValueError('synthetic game-derived data must remain outside the repository')
 if out.exists():raise FileExistsError(out)
 if not out.parent.is_dir():raise ValueError('export parent directory must exist')
if not 1<=a.count<=100000000 or not 1<=a.timeout_ms<=1200000 or not 1<=a.max_events<=500000:raise ValueError('invalid limit')
with a.pe.open('rb') as identity_file: identity=hashlib.file_digest(identity_file,'sha256').hexdigest()
if identity!='d5c2fb538f4020a71060b553127259fcd5d3131beb89a4ec26a7d6ccfa9dfbfd':raise ValueError('unexpected executable SHA-256; fixed addresses require build 26136895')
pe=pefile.PE(str(a.pe),fast_load=True);base=pe.OPTIONAL_HEADER.ImageBase;entry=base+pe.OPTIONAL_HEADER.AddressOfEntryPoint
secs=[(s.VirtualAddress,max(s.Misc_VirtualSize,s.SizeOfRawData),s.PointerToRawData,s.SizeOfRawData,s.Name.rstrip(b'\0').decode('ascii','replace')) for s in pe.sections]
stack=0x700000000000;stack_size=0x200000;teb=0x710000000000;pages=set();early=[];recent=collections.deque(maxlen=40);writes=[];state={'instructions':0,'mapped_image_pages':0,'exec_writes':0,'rdata_writes':0,'rdata_write_bytes':0,'rdata_changed_writes':0,'rdata_compare_failures':0,'rdata_xor_checked':0,'rdata_xor_matched':0,'stop':None};rdata_pages=set();rdata_page_counts=collections.Counter();rdata_site_counts=collections.Counter();rdata_samples=[];rdata_min=None;rdata_max=None
imports={};slots={};stub_base=0x720000000000
if a.intercept_imports:
 pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
 for desc in pe.DIRECTORY_ENTRY_IMPORT:
  for item in desc.imports:
   address=stub_base+len(imports)*16;name=('#'+str(item.ordinal)) if item.import_by_ordinal else item.name.decode('ascii');imports[address]=desc.dll.decode('ascii')+'!'+name;slots[item.address]=address
uc=Uc(UC_ARCH_X86,UC_MODE_64);uc.mem_map(stack,stack_size);
if imports:
 stubsize=((len(imports)*16+4095)//4096)*4096;uc.mem_map(stub_base,stubsize);uc.mem_write(stub_base,b'\xc3'*stubsize)
uc.mem_map(teb,0x2000);uc.reg_write(UC_X86_REG_RSP,stack+stack_size-0x1000);uc.reg_write(UC_X86_REG_GS_BASE,teb);uc.mem_write(teb+0x60,struct.pack('<Q',teb+0x1000))
with a.pe.open('rb') as f, mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ) as image:
 def invalid(uc,access,addr,size,value,user):
  rva=addr-base;section=next((s for s in secs if s[0]<=rva<s[0]+s[1]),None)
  if section is None:
   state['stop']={'kind':'unmapped_access','access':access,'address':hex(addr),'size':size,'rip':hex(uc.reg_read(UC_X86_REG_RIP))};return False
  page=addr&~0xfff
  if page in pages:
   state['stop']={'kind':'mapped_access_failure','address':hex(addr)};return False
  uc.mem_map(page,0x1000,UC_PROT_ALL);pages.add(page);state['mapped_image_pages']+=1
  section_rva,_,raw,rawsize,_=section;page_rva=page-base;start=max(page_rva,section_rva);end=min(page_rva+4096,section_rva+rawsize)
  if end>start:uc.mem_write(base+start,image[raw+start-section_rva:raw+end-section_rva])
  for slot,marker in slots.items():
   if page<=slot and slot+8<=page+4096:uc.mem_write(slot,struct.pack('<Q',marker))
  return True
 def trace_read(uc,access,addr,size,value,user):
  if not state.get('loop_trace_active'):return
  reads=state.setdefault('loop_reads',[])
  if len(reads)>=1000:return
  try:v=bytes(uc.mem_read(addr,min(size,16))).hex()
  except UcError:v=None
  reads.append({'pc':hex(uc.reg_read(UC_X86_REG_RIP)),'addr':hex(addr),'size':size,'value':v})
 def code(uc,addr,size,user):
  state['instructions']+=1
  if state.get('loop_trace_active'):
   if addr==0x17004d360:
    state['loop_trace_active']=False;state['stop']={'kind':'loop_trace_complete','event':len(state.get('fast_transform_events',[]))};uc.emu_stop();return
   trace=state.setdefault('loop_trace',[])
   if len(trace)<2000:
    trace.append({'pc':hex(addr),'size':size,'regs':{name:hex(uc.reg_read(reg)) for name,reg in (('rax',UC_X86_REG_RAX),('rbx',UC_X86_REG_RBX),('rcx',UC_X86_REG_RCX),('rdx',UC_X86_REG_RDX),('r8',UC_X86_REG_R8),('r9',UC_X86_REG_R9),('r10',UC_X86_REG_R10),('r11',UC_X86_REG_R11),('rsi',UC_X86_REG_RSI),('rdi',UC_X86_REG_RDI),('rsp',UC_X86_REG_RSP))}})
  if addr in imports:
   regs={'rcx':hex(uc.reg_read(UC_X86_REG_RCX)),'rdx':hex(uc.reg_read(UC_X86_REG_RDX)),'r8':hex(uc.reg_read(UC_X86_REG_R8)),'r9':hex(uc.reg_read(UC_X86_REG_R9)),'rsp':hex(uc.reg_read(UC_X86_REG_RSP))}
   stop={'kind':'synthetic_import_intercept','import':imports[addr],'marker':hex(addr),'registers':regs}
   if imports[addr].lower()=='kernel32.dll!createthread':
    try:stop['thread_parameter_bytes']=bytes(uc.mem_read(uc.reg_read(UC_X86_REG_R9),48)).hex()
    except UcError:stop['thread_parameter_bytes']=None
   state['stop']=stop;uc.emu_stop();return
  if addr==0x17004d360:
   ctx={'rsp':hex(uc.reg_read(UC_X86_REG_RSP)),'rcx':hex(uc.reg_read(UC_X86_REG_RCX)),'rdx':hex(uc.reg_read(UC_X86_REG_RDX)),'r8':hex(uc.reg_read(UC_X86_REG_R8)),'r9':hex(uc.reg_read(UC_X86_REG_R9))}
   for reg,name in ((UC_X86_REG_RCX,'rcx_bytes'),(UC_X86_REG_RDX,'rdx_bytes')):
    try:ctx[name]=bytes(uc.mem_read(uc.reg_read(reg),32)).hex()
    except UcError:ctx[name]=None
   state.setdefault('transform_entries',[]).append(ctx)
   if 'transform_entry' not in state:state['transform_entry']=ctx
   if a.accelerate_aes:
    data=uc.reg_read(UC_X86_REG_R8);length=uc.reg_read(UC_X86_REG_R9);rsp=uc.reg_read(UC_X86_REG_RSP);rdata_start=base+0x32c84000;rdata_end=rdata_start+9107968
    events=state.setdefault('fast_transform_events',[]);total=state.get('fast_transform_bytes',0)
    text_start=base+0x1000;text_end=text_start+851977728
    in_rdata=rdata_start<=data and data+length<=rdata_end and rsp==0x7300001fef68
    in_text=a.allow_text_transforms and state.get('phase')=='synthetic-parent-resumed' and text_start<=data and data+length<=text_end and stack<=rsp<=stack+stack_size-8
    if not (0<length<=16*1024*1024 and (in_rdata or in_text) and total+length<=128*1024*1024 and len(events)<a.max_events):
     state['stop']={'kind':'aes_scope_or_stack_guard','data':hex(data),'length':length,'rsp':hex(rsp)};uc.emu_stop();return
    for page in range(data&~0xfff,(data+length+0xfff)&~0xfff,4096):
     if page not in pages and not invalid(uc,0,page,1,0,None):uc.emu_stop();return
    before=bytes(uc.mem_read(data,length))
    if len(events)==a.native_event and 'native_probe' not in state:
     state['native_probe']={'event':len(events),'data':hex(data),'length':length,'before_sha256':hashlib.sha256(before).hexdigest(),'entry':ctx}
     return
    key=bytes(uc.mem_read(uc.reg_read(UC_X86_REG_RCX),16));counter=bytes(uc.mem_read(uc.reg_read(UC_X86_REG_RDX),16));after=AES.new(key,AES.MODE_CTR,nonce=b'',initial_value=int.from_bytes(counter,'big')).encrypt(before);uc.mem_write(data,after)
    events.append({'region':'text' if in_text else 'rdata','data':hex(data),'length':length,'before_sha256':hashlib.sha256(before).hexdigest(),'after_sha256':hashlib.sha256(after).hexdigest()});state['fast_transform_bytes']=total+length
    if len(events)-1==a.trace_after:
     state['loop_trace_active']=True;uc.hook_add(UC_HOOK_MEM_READ,trace_read)
    ret=struct.unpack('<Q',uc.mem_read(rsp,8))[0];uc.reg_write(UC_X86_REG_RSP,rsp+8);uc.reg_write(UC_X86_REG_RAX,(length-1)%16);uc.reg_write(UC_X86_REG_RDX,((length-1)%16)+1);uc.reg_write(UC_X86_REG_RCX,0x2b992ddfa2320000);uc.reg_write(UC_X86_REG_R8,rsp-0xc8);uc.reg_write(UC_X86_REG_R9,4);uc.reg_write(UC_X86_REG_R10,0xac);uc.reg_write(UC_X86_REG_R11,rsp-8);uc.reg_write(UC_X86_REG_EFLAGS,0x246);uc.reg_write(UC_X86_REG_RIP,ret)
    return
  if addr==0x17004d64e:
   if 'native_probe' in state:
    probe=state['native_probe'];probe['after_sha256']=hashlib.sha256(bytes(uc.mem_read(int(probe['data'],16),probe['length']))).hexdigest();probe['instructions_at_return']=state['instructions'];state['stop']={'kind':'native_probe_complete','event':probe['event']};uc.emu_stop();return
   state.setdefault('transform_returns',[]).append({'rax':hex(uc.reg_read(UC_X86_REG_RAX)),'rcx':hex(uc.reg_read(UC_X86_REG_RCX)),'rdx':hex(uc.reg_read(UC_X86_REG_RDX)),'r8':hex(uc.reg_read(UC_X86_REG_R8)),'r9':hex(uc.reg_read(UC_X86_REG_R9)),'r10':hex(uc.reg_read(UC_X86_REG_R10)),'r11':hex(uc.reg_read(UC_X86_REG_R11)),'eflags':hex(uc.reg_read(UC_X86_REG_EFLAGS))})
  if len(early)<40:early.append(hex(addr))
  recent.append(hex(addr))
  op=bytes(uc.mem_read(addr,min(size,4)))
  if op.startswith((b'\x0f\x05',b'\x0f\x34',b'\xcd',b'\xcc')):
   state['stop']={'kind':'host_interface_instruction','address':hex(addr),'bytes':op.hex()};uc.emu_stop()
 def intr(uc,intno,user):state.update(stop={'kind':'interrupt','number':intno,'rip':hex(uc.reg_read(UC_X86_REG_RIP))});uc.emu_stop()
 def write(uc,access,addr,size,value,user):
  global rdata_min,rdata_max
  rva=addr-base
  if 0x32c84000<=rva<0x32c84000+9107968:
   state['rdata_writes']+=1;state['rdata_write_bytes']+=size;rdata_site_counts[uc.reg_read(UC_X86_REG_RIP)]+=1
   if len(rdata_samples)<20000:rdata_samples.append({'address':hex(addr),'size':size,'rip':hex(uc.reg_read(UC_X86_REG_RIP)),'cl':uc.reg_read(UC_X86_REG_RCX)&0xff,'transform_index':len(state.get('transform_entries',[]))-1})
   if state['rdata_writes']==1:
    state['first_rdata_write_context']={'preceding_pcs':list(recent),'rax':hex(uc.reg_read(UC_X86_REG_RAX)),'rbx':hex(uc.reg_read(UC_X86_REG_RBX)),'rcx':hex(uc.reg_read(UC_X86_REG_RCX)),'rdx':hex(uc.reg_read(UC_X86_REG_RDX)),'rsi':hex(uc.reg_read(UC_X86_REG_RSI)),'rdi':hex(uc.reg_read(UC_X86_REG_RDI)),'rbp':hex(uc.reg_read(UC_X86_REG_RBP))} 
   rdata_pages.add(addr&~0xfff);rdata_page_counts[addr&~0xfff]+=1;rdata_min=addr if rdata_min is None else min(rdata_min,addr);rdata_max=addr+size-1 if rdata_max is None else max(rdata_max,addr+size-1)
   try:
    before=int.from_bytes(uc.mem_read(addr,size),'little')
    if len(rdata_samples)==state['rdata_writes'] and rdata_samples:
     rdata_samples[-1]['before']=before;rdata_samples[-1]['after']=value & ((1<<(8*size))-1)
    if 0<size<=8 and before!=(value & ((1<<(8*size))-1)):state['rdata_changed_writes']+=1
    if size==1 and uc.reg_read(UC_X86_REG_RIP)==0x17004d61e:
     state['rdata_xor_checked']+=1
     if (before^(uc.reg_read(UC_X86_REG_RCX)&0xff))==(value&0xff):state['rdata_xor_matched']+=1
   except UcError:state['rdata_compare_failures']+=1
  if 0x1000<=rva<0x1000+851977728:
   state['exec_writes']+=1
   if len(writes)<30:writes.append({'address':hex(addr),'size':size,'rip':hex(uc.reg_read(UC_X86_REG_RIP))})
 uc.hook_add(UC_HOOK_MEM_INVALID,invalid);uc.hook_add(UC_HOOK_CODE,code);uc.hook_add(UC_HOOK_INTR,intr);uc.hook_add(UC_HOOK_MEM_WRITE,write)
 start=time.monotonic()
 try:uc.emu_start(entry,0,timeout=a.timeout_ms*1000,count=a.count)
 except UcError as ex:
  if state['stop'] is None:state['stop']={'kind':'unicorn_error','message':str(ex),'rip':hex(uc.reg_read(UC_X86_REG_RIP))}
 if state['stop'] is None:state['stop']={'kind':'budget_or_return','rip':hex(uc.reg_read(UC_X86_REG_RIP))}
 if a.follow_thread and state['stop'].get('import','').lower()=='kernel32.dll!createthread':
  initial={'instructions':state['instructions'],'stop':state['stop'],'exec_writes':state['exec_writes']};thread_start=uc.reg_read(UC_X86_REG_R8);thread_arg=uc.reg_read(UC_X86_REG_R9);parent_context=uc.context_save();parent_rsp=uc.reg_read(UC_X86_REG_RSP);parent_return=struct.unpack('<Q',uc.mem_read(parent_rsp,8))[0];parent_thread_id_ptr=struct.unpack('<Q',uc.mem_read(parent_rsp+0x30,8))[0]
  child_stack=0x730000000000;uc.mem_map(child_stack,stack_size);return_marker=stub_base+len(imports)*16
  if return_marker>=stub_base+stubsize:raise RuntimeError('no spare marker slot')
  imports[return_marker]='<synthetic-thread-return>'
  for reg in (UC_X86_REG_RAX,UC_X86_REG_RBX,UC_X86_REG_RBP,UC_X86_REG_RSI,UC_X86_REG_RDI,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9,UC_X86_REG_R10,UC_X86_REG_R11,UC_X86_REG_R12,UC_X86_REG_R13,UC_X86_REG_R14,UC_X86_REG_R15):uc.reg_write(reg,0)
  rsp=child_stack+stack_size-0x1008;uc.mem_write(rsp,struct.pack('<Q',return_marker));uc.reg_write(UC_X86_REG_RSP,rsp);uc.reg_write(UC_X86_REG_RCX,thread_arg);uc.reg_write(UC_X86_REG_EFLAGS,0x202)
  state.update(instructions=0,exec_writes=0,rdata_writes=0,rdata_write_bytes=0,rdata_changed_writes=0,rdata_compare_failures=0,rdata_xor_checked=0,rdata_xor_matched=0,stop=None);early.clear();recent.clear();writes.clear();rdata_pages.clear();rdata_page_counts.clear();rdata_site_counts.clear();rdata_samples.clear();rdata_min=None;rdata_max=None
  try:uc.emu_start(thread_start,0,timeout=a.timeout_ms*1000,count=a.count)
  except UcError as ex:
   if state['stop'] is None:state['stop']={'kind':'unicorn_error','message':str(ex),'rip':hex(uc.reg_read(UC_X86_REG_RIP))}
  if state['stop'] is None:state['stop']={'kind':'budget_or_return','rip':hex(uc.reg_read(UC_X86_REG_RIP))}
  stubbed=[];fast_events=[];fast_total=0
  while state['instructions']<a.count and time.monotonic()-start<a.timeout_ms/1000:
   event=state['stop'];kind=event.get('kind');imp=event.get('import','').lower();rsp=uc.reg_read(UC_X86_REG_RSP)
   if not child_stack<=rsp<=child_stack+stack_size-8:state['stop']={'kind':'unsafe_synthetic_stack','rsp':hex(rsp)};break
   if a.stub_virtualprotect and imp=='kernel32.dll!virtualprotect' and len(stubbed)<8:
    oldptr=uc.reg_read(UC_X86_REG_R9)
    if not child_stack<=oldptr<=child_stack+stack_size-4:state['stop']={'kind':'unsafe_synthetic_pointer','old_protection':hex(oldptr)};break
    ret=struct.unpack('<Q',uc.mem_read(rsp,8))[0];uc.mem_write(oldptr,struct.pack('<I',2));uc.reg_write(UC_X86_REG_RAX,1);uc.reg_write(UC_X86_REG_RSP,rsp+8);stubbed.append(event)
   elif a.accelerate_aes and kind=='synthetic_aes_intercept' and len(fast_events)<10000:
    data=uc.reg_read(UC_X86_REG_R8);length=uc.reg_read(UC_X86_REG_R9);rdata_start=base+0x32c84000;rdata_end=rdata_start+9107968
    if not (0<length<=16*1024*1024 and rdata_start<=data and data+length<=rdata_end and fast_total+length<=64*1024*1024):state['stop']={'kind':'aes_scope_guard','data':hex(data),'length':length};break
    if rsp!=0x7300001fef68:state['stop']={'kind':'aes_stack_guard','rsp':hex(rsp)};break
    for page in range(data&~0xfff,(data+length+0xfff)&~0xfff,4096):
     if page not in pages and not invalid(uc,0,page,1,0,None):raise RuntimeError('cannot map target page')
    key=bytes(uc.mem_read(uc.reg_read(UC_X86_REG_RCX),16));counter=bytes(uc.mem_read(uc.reg_read(UC_X86_REG_RDX),16));before=bytes(uc.mem_read(data,length));after=AES.new(key,AES.MODE_CTR,nonce=b'',initial_value=int.from_bytes(counter,'big')).encrypt(before);uc.mem_write(data,after)
    fast_events.append({'region':'text' if in_text else 'rdata','data':hex(data),'length':length,'before_sha256':hashlib.sha256(before).hexdigest(),'after_sha256':hashlib.sha256(after).hexdigest()});fast_total+=length
    ret=struct.unpack('<Q',uc.mem_read(rsp,8))[0];uc.reg_write(UC_X86_REG_RSP,rsp+8);uc.reg_write(UC_X86_REG_RAX,(length-1)%16);uc.reg_write(UC_X86_REG_RDX,((length-1)%16)+1);uc.reg_write(UC_X86_REG_RCX,0x2b992ddfa2320000);uc.reg_write(UC_X86_REG_R8,rsp-0xc8);uc.reg_write(UC_X86_REG_R9,4);uc.reg_write(UC_X86_REG_R10,0xac);uc.reg_write(UC_X86_REG_R11,rsp-8);uc.reg_write(UC_X86_REG_EFLAGS,0x246)
   else:break
   state['stop']=None;remaining=max(1,int((a.timeout_ms/1000-(time.monotonic()-start))*1000000))
   try:uc.emu_start(ret,0,timeout=remaining,count=a.count-state['instructions'])
   except UcError as ex:
    if state['stop'] is None:state['stop']={'kind':'unicorn_error','message':str(ex),'rip':hex(uc.reg_read(UC_X86_REG_RIP))}
   if state['stop'] is None:state['stop']={'kind':'budget_or_return','rip':hex(uc.reg_read(UC_X86_REG_RIP))}
  state['stubbed_virtualprotect']=stubbed;state.setdefault('fast_transform_events',fast_events);state.setdefault('fast_transform_bytes',fast_total)
  state['initial_stop']=initial;state['synthetic_function_start']=hex(thread_start);state['synthetic_function_argument']=hex(thread_arg);state['child_model']='fresh synthetic stack and zeroed integer registers, shared synthetic TEB and memory; no actual thread'
  if a.resume_parent and state['stop'].get('import')=='<synthetic-thread-return>':
   state['child_outcome']={'stop':state['stop'],'instructions':state['instructions'],'fast_transform_calls':len(state.get('fast_transform_events',[])),'fast_transform_bytes':state.get('fast_transform_bytes',0)}
   if parent_thread_id_ptr!=0:state['stop']={'kind':'unmodeled_thread_id_pointer','address':hex(parent_thread_id_ptr)}
   else:
    uc.context_restore(parent_context);uc.reg_write(UC_X86_REG_RAX,1);uc.reg_write(UC_X86_REG_RSP,parent_rsp+8);state['stop']=None;state['phase']='synthetic-parent-resumed';state['instructions']=0;early.clear();recent.clear()
    remaining=max(1,int((a.timeout_ms/1000-(time.monotonic()-start))*1000000))
    try:uc.emu_start(parent_return,0,timeout=remaining,count=a.count)
    except UcError as ex:
     if state['stop'] is None:state['stop']={'kind':'unicorn_error','message':str(ex),'rip':hex(uc.reg_read(UC_X86_REG_RIP))}
    if state['stop'] is None:state['stop']={'kind':'budget_or_return','rip':hex(uc.reg_read(UC_X86_REG_RIP))}
    if a.stub_parent_virtualprotect and state['stop'].get('import','').lower()=='kernel32.dll!virtualprotect':
     event=state['stop'];oldptr=uc.reg_read(UC_X86_REG_R9);rsp=uc.reg_read(UC_X86_REG_RSP)
     if not stack<=oldptr<=stack+stack_size-4 or not stack<=rsp<=stack+stack_size-8:state['stop']={'kind':'unsafe_parent_synthetic_pointer','old_protection':hex(oldptr),'rsp':hex(rsp)}
     else:
      ret=struct.unpack('<Q',uc.mem_read(rsp,8))[0];uc.mem_write(oldptr,struct.pack('<I',0x20));uc.reg_write(UC_X86_REG_RAX,1);uc.reg_write(UC_X86_REG_RSP,rsp+8);state['stubbed_parent_virtualprotect']=event;state['stop']=None
      remaining=max(1,int((a.timeout_ms/1000-(time.monotonic()-start))*1000000))
      try:uc.emu_start(ret,0,timeout=remaining,count=a.count-state['instructions'])
      except UcError as ex:
       if state['stop'] is None:state['stop']={'kind':'unicorn_error','message':str(ex),'rip':hex(uc.reg_read(UC_X86_REG_RIP))}
      if state['stop'] is None:state['stop']={'kind':'budget_or_return','rip':hex(uc.reg_read(UC_X86_REG_RIP))}
    state['parent_model']='worker simulated to completion before parent; fake CreateThread handle 1; no real thread or API call'

 state.update(rdata_write_samples=rdata_samples,rdata_site_counts={hex(k):v for k,v in sorted(rdata_site_counts.items())},rdata_touched_pages=len(rdata_pages),rdata_page_counts={hex(k):v for k,v in sorted(rdata_page_counts.items())},rdata_min_address=hex(rdata_min) if rdata_min is not None else None,rdata_max_address=hex(rdata_max) if rdata_max is not None else None,entry=hex(entry),elapsed_seconds=round(time.monotonic()-start,3),count_limit=a.count,timeout_ms=a.timeout_ms,first_pcs=early,last_pcs=list(recent),exec_write_samples=writes,model='synthetic stack and TEB; PE file pages and inert import markers; no host API execution, network, or target process' if imports else 'synthetic stack and TEB; PE file pages only; no OS, imports, network, or target process')
 if a.export_synthetic_rdata is not None:
  if state['stop'].get('import')!='<synthetic-thread-return>':state['export']={'status':'not_written','reason':'synthetic thread did not return'}
  else:
   region=next(s for s in secs if s[4]=='.rdata');rva,virtual_size,raw,raw_size,_=region
   original=bytes(image[raw:raw+raw_size]);result=bytearray(original);overlaid=0
   for page in sorted(pages):
    lo=max(page,base+rva);hi=min(page+4096,base+rva+raw_size)
    if hi>lo:result[lo-(base+rva):hi-(base+rva)]=uc.mem_read(lo,hi-lo);overlaid+=1
   differences=sum(x!=y for x,y in zip(original,result));markers=sum(1 for slot in slots if (slot&~0xfff) in pages and base+rva<=slot<base+rva+raw_size)
   with a.export_synthetic_rdata.open('xb') as out_file:out_file.write(result)
   state['export']={'status':'written','path':str(a.export_synthetic_rdata),'sha256':hashlib.sha256(result).hexdigest(),'bytes':len(result),'mapped_pages_overlaid':overlaid,'different_bytes_from_disk':differences,'synthetic_iat_marker_slots_in_mapped_pages':markers,'warning':'Synthetic partial data image, not a runnable executable; may contain inert import markers and untransformed ranges.'}
 if a.output_report is None:print(json.dumps(state,indent=2))
 else:
  with a.output_report.open('x',encoding='utf-8') as report:json.dump(state,report,separators=(',',':'))
  print(json.dumps({'status':'written','path':str(a.output_report),'events':len(state.get('fast_transform_events',[])),'stop':state['stop']}))
