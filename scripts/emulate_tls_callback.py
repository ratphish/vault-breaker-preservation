"""Probe one PE TLS callback against original image bytes in Unicorn; no host APIs."""
import argparse,bisect,collections,ctypes,hashlib,json,mmap,struct,time
from pathlib import Path
import pefile
from synthetic_avx import try_avx
from synthetic_checkpoint import save as save_checkpoint, restore as restore_checkpoint
from synthetic_watchpoints import group_ranges, intersections
from unicorn import Uc,UcError,UC_ARCH_X86,UC_MODE_64,UC_HOOK_CODE,UC_HOOK_INTR,UC_HOOK_MEM_INVALID,UC_HOOK_INSN_INVALID,UC_HOOK_MEM_READ,UC_HOOK_MEM_WRITE,UC_HOOK_BLOCK,UC_HOOK_INSN,UC_PROT_ALL,UC_PROT_READ,UC_PROT_WRITE,UC_MEM_READ_UNMAPPED,UC_MEM_WRITE_UNMAPPED,UC_MEM_FETCH_PROT
from unicorn.x86_const import *
p=argparse.ArgumentParser();p.add_argument('pe',type=Path);p.add_argument('--index',type=int,required=True);p.add_argument('--count',type=int,default=1000000);p.add_argument('--timeout-ms',type=int,default=20000);p.add_argument('--sparse',action='store_true');p.add_argument('--fast',action='store_true');p.add_argument('--fixed-tsc',action='store_true');p.add_argument('--eager-image',action='store_true');p.add_argument('--stub-veh',action='store_true');p.add_argument('--model-veh-exceptions',action='store_true');p.add_argument('--loader-sequence',action='store_true');p.add_argument('--entry-after-loader',action='store_true');p.add_argument('--follow-thread',action='store_true');p.add_argument('--resume-parent',action='store_true');p.add_argument('--stub-worker-wait',action='store_true');p.add_argument('--follow-second-thread',action='store_true');p.add_argument('--resume-second-parent',action='store_true');p.add_argument('--stub-worker-cache',action='store_true');p.add_argument('--stub-crt-clock',action='store_true');p.add_argument('--model-teb-stack',action='store_true');p.add_argument('--model-crt-initterm-e',action='store_true');p.add_argument('--checkpoint-at-constructor',type=int);p.add_argument('--save-checkpoint',type=Path);p.add_argument('--resume-checkpoint',type=Path);p.add_argument('--trace-second-image-writes',action='store_true');p.add_argument('--export-second-text',type=Path);p.add_argument('--stub-parent-virtualprotect',action='store_true');p.add_argument('--stop-at-parent-aes',action='store_true');p.add_argument('--parent-aes-reference',type=Path);p.add_argument('--parent-aes-stop-after',type=int);p.add_argument('--allow-parent-data',action='store_true');p.add_argument('--parent-data-stop-after',type=int);p.add_argument('--export-parent-data',type=Path);p.add_argument('--allow-parent-vmp',action='store_true');p.add_argument('--stop-after-vmp',action='store_true');p.add_argument('--export-parent-vmp',type=Path);p.add_argument('--export-parent-aux',type=Path);p.add_argument('--hash-parent-text',action='store_true');p.add_argument('--stub-virtualprotect',action='store_true');p.add_argument('--trace-aes',action='store_true');p.add_argument('--accelerate-worker-aes',action='store_true');p.add_argument('--native-final-aes',action='store_true');p.add_argument('--native-aes-at',type=int,default=0);p.add_argument('--native-aes-every',type=int,default=0);p.add_argument('--stop-after-aes',type=int);p.add_argument('--hash-worker-rdata',action='store_true');p.add_argument('--export-worker-stack',type=Path);p.add_argument('--trace-image-writes',action='store_true');p.add_argument('--watch-registry',type=Path);p.add_argument('--trace-dispatch',action='store_true');p.add_argument('--trace-range');p.add_argument('--trace-first',type=int,default=0);p.add_argument('--inline-dispatch',action='store_true');p.add_argument('--stop-after-dispatches',type=int);p.add_argument('--synthetic-system-peb',action='store_true');p.add_argument('--synthetic-peb-loader-lock',action='store_true');p.add_argument('--synthetic-user32-module',action='store_true');p.add_argument('--synthetic-user32-loader-entry',action='store_true');p.add_argument('--synthetic-loaded-module-images',action='store_true');p.add_argument('--synthetic-crypt32-dependency',action='store_true');p.add_argument('--synthetic-mitigation-failure',action='store_true');p.add_argument('--watch-stack-address',type=lambda x:int(x,0));p.add_argument('--save-at-stop',type=Path);p.add_argument('--trace-dynamic-worker',action='store_true');p.add_argument('--defer-dynamic-worker',action='store_true');p.add_argument('--virtual-sku-config',type=Path);p.add_argument('--virtual-steam-module',type=Path);p.add_argument('--assume-steam-no-restart',action='store_true');p.add_argument('--assume-steam-init-success',action='store_true');p.add_argument('--trace-steam-context-callback',action='store_true');p.add_argument('--trace-steam-interface',action='store_true');p.add_argument('--assume-not-steam-deck',action='store_true');p.add_argument('--synthetic-appdata-path',action='store_true');p.add_argument('--trace-suspended-worker',action='store_true');p.add_argument('--assume-worker-waits',action='store_true');p.add_argument('--watch-additional-registry',type=Path);p.add_argument('--resume-parent-context',type=Path);p.add_argument('--assume-no-catalog',action='store_true');p.add_argument('--run-deferred-worker-no-catalog',action='store_true');p.add_argument('--handoff-worker-release',action='store_true');p.add_argument('--virtual-oodle-module',type=Path);p.add_argument('--virtual-xinput-module',type=Path);p.add_argument('--assume-steam-user-handle',action='store_true');p.add_argument('--assume-input-init-success',action='store_true');p.add_argument('--resume-cached-steam-context',action='store_true');p.add_argument('--synthetic-input-actions',action='store_true');p.add_argument('--trace-dxgi-factory',action='store_true');p.add_argument('--trace-dxgi-factory6',action='store_true');p.add_argument('--trace-dxgi-adapter',action='store_true');p.add_argument('--assume-dxgi-no-output',action='store_true');p.add_argument('--synthetic-dxgi-descriptor',action='store_true');p.add_argument('--assume-nvapi-missing',action='store_true');p.add_argument('--assume-version-build-ge',action='store_true');p.add_argument('--assume-second-device-release',action='store_true');p.add_argument('--assume-second-shader-model',action='store_true');p.add_argument('--trace-second-d3d12-device',action='store_true');p.add_argument('--trace-d3d12-device',action='store_true');p.add_argument('--assume-d3d12-minimal-options',action='store_true');p.add_argument('--assume-d3d12-shader-model-6',action='store_true');p.add_argument('--assume-d3d12-unsupported-formats',action='store_true');p.add_argument('--assume-d3d12-release',action='store_true');p.add_argument('--assume-dxgi-factory-release',action='store_true');p.add_argument('--assume-dxgi-release',action='store_true');p.add_argument('--assume-dxgi-retained-release',action='store_true');p.add_argument('--assume-dxgi-addref',action='store_true');p.add_argument('--assume-dxgi-single-adapter',action='store_true');p.add_argument('--assume-en-us-locale',action='store_true');p.add_argument('--assume-en-us-lcid',action='store_true');p.add_argument('--assume-loadicon-success',action='store_true');p.add_argument('--assume-loadcursor-success',action='store_true');p.add_argument('--assume-stockobject-success',action='store_true');p.add_argument('--assume-registerclass-success',action='store_true');p.add_argument('--assume-window-without-callbacks',action='store_true');p.add_argument('--assume-window-userdata-two',action='store_true');p.add_argument('--assume-window-userdata-zero',action='store_true');p.add_argument('--assume-window-title-without-callback',action='store_true');p.add_argument('--assume-adjustrect-borderless',action='store_true');p.add_argument('--assume-adjustrect-small',action='store_true');p.add_argument('--assume-adjustrect',action='store_true');p.add_argument('--assume-windowpos-without-callbacks',action='store_true');p.add_argument('--assume-window-style',action='store_true');p.add_argument('--assume-window-rect',action='store_true');p.add_argument('--assume-getwindowuserdata',action='store_true');p.add_argument('--assume-client-rect',action='store_true');p.add_argument('--assume-clienttoscreen',action='store_true');p.add_argument('--assume-monitorfromwindow',action='store_true');p.add_argument('--fix-observed-vdivss',action='store_true');p.add_argument('--assume-modff-qnan',action='store_true');p.add_argument('--assume-monitorinfo',action='store_true');p.add_argument('--trace-getmonitorinfo',action='store_true');p.add_argument('--assume-window-style-zero',action='store_true');p.add_argument('--trace-setwindowlonga',action='store_true');p.add_argument('--trace-monitorfromwindow',action='store_true');p.add_argument('--trace-clienttoscreen',action='store_true');p.add_argument('--trace-getclientrect',action='store_true');p.add_argument('--trace-getwindowlongptr',action='store_true');p.add_argument('--trace-getwindowrect',action='store_true');p.add_argument('--trace-getwindowlong',action='store_true');p.add_argument('--trace-setwindowpos',action='store_true');p.add_argument('--trace-adjustrect',action='store_true');p.add_argument('--trace-setwindowtext',action='store_true');p.add_argument('--trace-setwindowlong',action='store_true');p.add_argument('--trace-createwindow',action='store_true');p.add_argument('--trace-registerclass',action='store_true');p.add_argument('--trace-stockobject',action='store_true');p.add_argument('--trace-loadcursor',action='store_true');p.add_argument('--trace-loadicon',action='store_true');p.add_argument('--trace-messagebox',action='store_true');p.add_argument('--assume-d3d12-supported-formats',action='store_true');p.add_argument('--assume-d3d12-capable-profile',action='store_true');p.add_argument('--assume-d3d12-buffer-formats',action='store_true');p.add_argument('--trace-dxgi-output',action='store_true');p.add_argument('--synthetic-dxgi-output-desc',action='store_true');p.add_argument('--synthetic-dxgi-one-mode',action='store_true');p.add_argument('--synthetic-dxgi-output-refcount',action='store_true');p.add_argument('--assume-dxgi-single-output',action='store_true');a=p.parse_args()
if not 0<=a.index<5 or not 1<=a.count<=10000000 or not 1<=a.timeout_ms<=180000:raise ValueError('invalid bound')
if a.loader_sequence and (a.index!=0 or a.stop_after_dispatches is not None):raise ValueError('loader sequence starts at callback 0 without a dispatch checkpoint')
if a.model_veh_exceptions and (not a.loader_sequence or not a.stub_veh or a.sparse):raise ValueError('exception modeling requires a full-hook loader sequence and fake registration')
if a.entry_after_loader and not a.loader_sequence:raise ValueError('entry-after-loader requires the callback sequence')
if a.follow_thread and not a.entry_after_loader:raise ValueError('follow-thread requires the modeled loader and entry')
if a.follow_thread and a.sparse:raise ValueError('worker tracing requires full instruction hooks')
if (a.stub_virtualprotect or a.trace_aes) and not a.follow_thread:raise ValueError('worker options require follow-thread')
if a.stop_after_aes is not None and (not a.trace_aes or not 1<=a.stop_after_aes<=70000):raise ValueError('AES checkpoint requires tracing and a bound of 1..70000')
if a.hash_worker_rdata and not (a.follow_thread and a.eager_image):raise ValueError('worker rdata hash requires an eager worker model')
if a.accelerate_worker_aes and not (a.eager_image and a.stub_virtualprotect and a.trace_aes):raise ValueError('worker AES shortcut requires eager worker, fake protection and tracing')
if a.native_final_aes and (not a.accelerate_worker_aes or a.stop_after_aes is None):raise ValueError('native final AES requires a bounded accelerated run')
if a.native_aes_every<0 or a.native_aes_every and not a.accelerate_worker_aes:raise ValueError('periodic native AES requires the worker shortcut')
if a.native_aes_at<0 or a.native_aes_at and not a.accelerate_worker_aes:raise ValueError('selected native AES requires the worker shortcut')
if a.resume_parent and not a.follow_thread:raise ValueError('parent resumption requires the fake worker')
if a.stub_worker_wait and not a.resume_parent:raise ValueError('worker wait stub requires parent resumption')
if a.follow_second_thread and not a.stub_worker_wait:raise ValueError('second worker requires the completed first-worker wait')
if a.resume_second_parent and not a.follow_second_thread:raise ValueError('second parent resumption requires the second worker')
if a.stub_worker_cache and not a.follow_second_thread:raise ValueError('cache API stubs require the second synthetic worker')
if a.stub_crt_clock and not a.resume_second_parent:raise ValueError('CRT clock stubs require the resumed second parent')
if a.model_crt_initterm_e and not (a.resume_second_parent and a.model_veh_exceptions):raise ValueError('initializer model requires resumed parent and exception memory')
if bool(a.checkpoint_at_constructor)!=bool(a.save_checkpoint) or a.checkpoint_at_constructor is not None and (not a.model_crt_initterm_e or not a.eager_image or not 1<=a.checkpoint_at_constructor<=20000):raise ValueError('checkpoint requires an eager CRT model, target and output')
if a.save_at_stop and not (a.model_crt_initterm_e and a.eager_image):raise ValueError('stop checkpoint requires eager CRT model')
if a.watch_stack_address is not None and not (0x700000000000<=a.watch_stack_address<=0x7000001ffff8 or 0x780000000000<=a.watch_stack_address<=0x7800001ffff8):raise ValueError('stack watch out of bounds')
if a.resume_checkpoint and not (a.model_crt_initterm_e and a.eager_image):raise ValueError('checkpoint resume requires eager CRT model')
identity_args={k:(str(v.resolve()) if isinstance(v,Path) else v) for k,v in vars(a).items() if k not in ('checkpoint_at_constructor','save_checkpoint','resume_checkpoint','count','timeout_ms','synthetic_system_peb','synthetic_peb_loader_lock','synthetic_user32_module','synthetic_user32_loader_entry','synthetic_loaded_module_images','synthetic_crypt32_dependency','synthetic_mitigation_failure','watch_stack_address','save_at_stop','trace_dynamic_worker','defer_dynamic_worker','virtual_sku_config','virtual_steam_module','assume_steam_no_restart','assume_steam_init_success','trace_steam_context_callback','trace_steam_interface','assume_not_steam_deck','synthetic_appdata_path','trace_suspended_worker','assume_worker_waits','watch_additional_registry','resume_parent_context','assume_no_catalog','run_deferred_worker_no_catalog','handoff_worker_release','virtual_oodle_module','virtual_xinput_module','assume_steam_user_handle','assume_input_init_success','resume_cached_steam_context','synthetic_input_actions','trace_dxgi_factory','trace_dxgi_factory6','trace_dxgi_adapter','assume_dxgi_no_output','synthetic_dxgi_descriptor','trace_d3d12_device','assume_nvapi_missing','assume_version_build_ge','assume_second_device_release','assume_second_shader_model','trace_second_d3d12_device','assume_d3d12_minimal_options','assume_d3d12_shader_model_6','assume_d3d12_unsupported_formats','assume_d3d12_release','assume_dxgi_factory_release','assume_dxgi_release','assume_dxgi_retained_release','assume_dxgi_addref','assume_dxgi_single_adapter','assume_en_us_locale','assume_en_us_lcid','assume_loadicon_success','assume_loadcursor_success','assume_stockobject_success','assume_registerclass_success','assume_window_without_callbacks','assume_window_userdata_two','assume_window_userdata_zero','assume_window_title_without_callback','assume_adjustrect','assume_adjustrect_borderless','assume_adjustrect_small','assume_windowpos_without_callbacks','assume_window_style','assume_window_rect','assume_client_rect','assume_clienttoscreen','assume_window_style_zero','trace_setwindowlonga','assume_monitorfromwindow','fix_observed_vdivss','assume_modff_qnan','assume_monitorinfo','trace_getmonitorinfo','trace_monitorfromwindow','trace_clienttoscreen','trace_getclientrect','assume_getwindowuserdata','trace_getwindowlongptr','trace_getwindowrect','trace_getwindowlong','trace_setwindowpos','trace_adjustrect','trace_setwindowtext','trace_setwindowlong','trace_createwindow','trace_registerclass','trace_stockobject','trace_loadcursor','trace_loadicon','trace_messagebox','assume_d3d12_supported_formats','assume_d3d12_capable_profile','assume_d3d12_buffer_formats','trace_dxgi_output','synthetic_dxgi_output_desc','synthetic_dxgi_one_mode','synthetic_dxgi_output_refcount','assume_dxgi_single_output')}
identity_args['trace_range']=None
if a.watch_registry:identity_args['watch_registry_sha256']=hashlib.sha256(a.watch_registry.read_bytes()).hexdigest()
checkpoint_identity=hashlib.sha256(json.dumps(identity_args,sort_keys=True).encode()).hexdigest()

if a.trace_second_image_writes and not a.follow_second_thread:raise ValueError('second-worker tracing requires the second worker')
if a.export_second_text:
 out=a.export_second_text.resolve()
 if not a.follow_second_thread or out.exists() or out.is_relative_to(Path(__file__).resolve().parents[1]) or not out.parent.is_dir():raise ValueError('second-worker text export requires a new private path')
if a.stub_parent_virtualprotect and not (a.resume_parent and a.stub_virtualprotect):raise ValueError('parent protection requires parent resumption and worker protection stub')
if a.stop_at_parent_aes and not a.stub_parent_virtualprotect:raise ValueError('parent AES checkpoint requires fake parent protection')
if a.parent_aes_reference and (not a.stub_parent_virtualprotect or not a.eager_image or a.stop_at_parent_aes):raise ValueError('parent AES replay requires eager parent protection and no first-call stop')
if a.parent_aes_stop_after is not None and (not a.parent_aes_reference or not 1<=a.parent_aes_stop_after<=173170):raise ValueError('invalid parent AES checkpoint')
if a.hash_parent_text and not (a.parent_aes_reference and a.eager_image):raise ValueError('text hash requires parent AES replay')
if a.allow_parent_data and not a.parent_aes_reference:raise ValueError('parent data transforms require checked text replay')
if a.parent_data_stop_after is not None and (not a.allow_parent_data or not 1<=a.parent_data_stop_after<=200000):raise ValueError('invalid parent data checkpoint')
if a.allow_parent_vmp and not a.allow_parent_data:raise ValueError('VMP transform requires the modeled data phase')
if a.stop_after_vmp and not a.allow_parent_vmp:raise ValueError('VMP checkpoint requires the VMP transform')
if a.export_parent_data:
 out=a.export_parent_data.resolve()
 if not a.allow_parent_data or out.exists() or out.is_relative_to(Path(__file__).resolve().parents[1]) or not out.parent.is_dir():raise ValueError('data export requires a new private path')
if a.export_parent_vmp:
 out=a.export_parent_vmp.resolve()
 if not a.allow_parent_vmp or out.exists() or out.is_relative_to(Path(__file__).resolve().parents[1]) or not out.parent.is_dir():raise ValueError('VMP export requires a new private path')
if a.export_parent_aux:
 out=a.export_parent_aux.resolve()
 if not a.allow_parent_vmp or out.exists() or out.is_relative_to(Path(__file__).resolve().parents[1]) or not out.parent.is_dir():raise ValueError('auxiliary section export requires a new private path')
parent_reference=[]
watch_points=[]
if a.watch_registry:
 reg=json.loads(a.watch_registry.read_text(encoding='utf-8-sig'));watch_points=sorted({int(c['pointer'],16) for row in reg['rows'] for c in row['registry_candidates']})
 if len(watch_points)>10000 or any(not 0x173534000<=v<0x1792a6be1 for v in watch_points):raise ValueError('invalid registry watchpoints')
if a.watch_additional_registry:
 extra=json.loads(a.watch_additional_registry.read_text(encoding='utf-8-sig'));watch_points=sorted(set(watch_points)|{int(c['pointer'],16) for row in extra['rows'] for c in row['registry_candidates']})
 if len(watch_points)>10000 or any(not 0x173534000<=v<0x1792a6be1 for v in watch_points):raise ValueError('invalid additional registry watchpoints')
if a.parent_aes_reference:
 prior=json.loads(a.parent_aes_reference.read_text(encoding='utf-8-sig'));ev=prior['fast_transform_events'];ctx=prior['transform_entries']
 if len(ev)!=len(ctx):raise ValueError('parent reference lengths differ')
 parent_reference=[(e,c) for e,c in zip(ev,ctx) if e.get('region')=='text']
 if len(parent_reference)!=173170:raise ValueError('unexpected parent reference count')
if a.export_worker_stack:
 out=a.export_worker_stack.resolve()
 if not a.follow_thread or out.exists() or out.is_relative_to(Path(__file__).resolve().parents[1]) or not out.parent.is_dir():raise ValueError('worker stack export requires a new private path')
with a.pe.open('rb') as f:
 if hashlib.file_digest(f,'sha256').hexdigest()!='d5c2fb538f4020a71060b553127259fcd5d3131beb89a4ec26a7d6ccfa9dfbfd':raise ValueError('wrong PE')
pe=pefile.PE(str(a.pe),fast_load=True);pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_TLS']]);base=pe.OPTIONAL_HEADER.ImageBase;t=pe.DIRECTORY_ENTRY_TLS.struct;callbacks=[0x15bd0b23b,0x14ba65e26,0x15bca890a,0x155d0dfca,0x15c6ba9c7];sections=[(s.VirtualAddress,max(s.Misc_VirtualSize,s.SizeOfRawData),s.PointerToRawData,s.SizeOfRawData,s.Name.rstrip(b'\0').decode()) for s in pe.sections];stub=0x720000000000;ret=0x730000000000;stack=0x700000000000;teb=0x710000000000;tls_table=0x740000000000;tls_block=0x750000000000;imports={};slots={};pages=set();state={'instructions':0,'stop':None,'image_writes':0,'stack_writes':0,'tls_writes':0};recent=collections.deque(maxlen=10000)
for desc in pe.DIRECTORY_ENTRY_IMPORT:
 for item in desc.imports:
  addr=stub+len(imports)*16;name=('#'+str(item.ordinal)) if item.import_by_ordinal else item.name.decode('ascii');imports[addr]=desc.dll.decode('ascii')+'!'+name;slots[item.address]=addr
slot_pages={}
for slot,marker in slots.items():slot_pages.setdefault(slot&~0xfff,[]).append((slot,marker))
if a.fast and not a.sparse:raise ValueError('--fast requires --sparse')
if (a.fixed_tsc or a.trace_dispatch or a.trace_range or a.trace_first or a.inline_dispatch or a.stop_after_dispatches is not None) and a.sparse:raise ValueError('fixed timestamps and tracing require instruction hooks')
if not 0<=a.trace_first<=50000:raise ValueError('invalid first-instruction trace bound')
if a.inline_dispatch and not a.fixed_tsc:raise ValueError('--inline-dispatch requires fixed timestamps')
if a.stop_after_dispatches is not None and not 1<=a.stop_after_dispatches<=10000:raise ValueError('invalid dispatch count')
trace_range=None
if a.trace_range:
 parts=a.trace_range.split(':')
 if len(parts)!=2:raise ValueError('trace range must be start:end')
 trace_range=tuple(int(z,0) for z in parts)
 if not 0x140001000<=trace_range[0]<trace_range[1]<=0x172c84000 or trace_range[1]-trace_range[0]>0x100000:raise ValueError('invalid trace range')
uc=Uc(UC_ARCH_X86,UC_MODE_64);uc.mem_map(stack,0x200000);uc.mem_map(teb,0x2000);uc.mem_map(stub,((len(imports)*16+4095)//4096)*4096);uc.mem_map(ret,0x1000);uc.mem_map(tls_table,0x10000);uc.mem_map(tls_block,0x100000);uc.mem_write(tls_table,struct.pack('<Q',tls_block)*8192);uc.mem_write(teb+0x58,struct.pack('<Q',tls_table));uc.mem_write(teb+0x60,struct.pack('<Q',teb+0x1000));uc.reg_write(UC_X86_REG_GS_BASE,teb);uc.reg_write(UC_X86_REG_RSP,stack+0x1feff8);uc.mem_write(stack+0x1feff8,struct.pack('<Q',ret));uc.reg_write(UC_X86_REG_RCX,base);uc.reg_write(UC_X86_REG_RDX,1);uc.reg_write(UC_X86_REG_R8,0);uc.reg_write(UC_X86_REG_R9,0);uc.reg_write(UC_X86_REG_EFLAGS,0x202)
exception_mem=0x770000000000;handler_ret=exception_mem+0x2000;child_stack=0x780000000000
def set_teb_stack(bottom):
 if a.model_teb_stack:
  uc.mem_write(teb+0x30,struct.pack('<Q',teb));uc.mem_write(teb+8,struct.pack('<QQ',bottom+0x200000,bottom))
set_teb_stack(stack)
if a.model_veh_exceptions:uc.mem_map(exception_mem,0x10000)
with a.pe.open('rb') as f,mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ) as image:
 if a.eager_image:
  headers=(pe.OPTIONAL_HEADER.SizeOfHeaders+4095)&~4095
  if headers>0x1000 or any(v%4096 for v,_,_,_,_ in sections):raise ValueError('unexpected image layout')
  uc.mem_map(base,headers,UC_PROT_ALL);uc.mem_write(base,image[:pe.OPTIONAL_HEADER.SizeOfHeaders])
  for v,n,raw,rawsize,name in sections:
   uc.mem_map(base+v,(n+4095)&~4095,UC_PROT_ALL)
   for offset in range(0,rawsize,8*1024*1024):
    size=min(8*1024*1024,rawsize-offset);uc.mem_write(base+v+offset,image[raw+offset:raw+offset+size])
  for address,value in slots.items():uc.mem_write(address,struct.pack('<Q',value))
 tlslen=t.EndAddressOfRawData-t.StartAddressOfRawData
 if not 0<=tlslen<=0x100000:raise ValueError('unexpected TLS size')
 tlsoff=pe.get_offset_from_rva(t.StartAddressOfRawData-base);uc.mem_write(tls_block,image[tlsoff:tlsoff+tlslen])
 def invalid(uc,access,addr,size,value,user):
  rva=addr-base;sec=next((s for s in sections if s[0]<=rva<s[0]+s[1]),None);page=addr&~0xfff
  if access==UC_MEM_FETCH_PROT and addr in (state.get('fake_heap_info_export'),state.get('fake_heap_create_export')):
   state['pending_fake_heap_call']='information' if addr==state.get('fake_heap_info_export') else 'create';return False
  if access==UC_MEM_FETCH_PROT and addr==state.get('fake_dll_notification_export'):
   state['pending_fake_dll_notification']=True;return False
  if access==UC_MEM_FETCH_PROT and addr==state.get('fake_ntquery_virtual_memory_export'):
   state['pending_fake_ntquery_virtual_memory']=True;return False
  if access==UC_MEM_FETCH_PROT and addr==state.get('fake_ntallocate_virtual_memory_export'):
   state['pending_fake_ntallocate_virtual_memory']=True;return False
  if access==UC_MEM_FETCH_PROT and addr==state.get('fake_ntprotect_virtual_memory_export'):
   state['pending_fake_ntprotect_virtual_memory']=True;return False
  if access==UC_MEM_FETCH_PROT and addr==state.get('fake_ntquery_system_information_export'):
   state['pending_fake_ntquery_system_information']=True;return False
  if access==UC_MEM_FETCH_PROT and addr==state.get('fake_loadlibraryexw_export'):
   state['pending_fake_loadlibraryexw']=True;return False
  if access==UC_MEM_FETCH_PROT and addr==state.get('fake_system_directory_export') and state.get('dynamic_worker_experiment'):
   state['pending_fake_system_directory']=True;return False
  if access==UC_MEM_FETCH_PROT and addr==0x7e0130003650 and state.get('synthetic_no_catalog'):
   state['pending_fake_catalog']=True;return False
  if access==UC_MEM_FETCH_PROT and any(lo<=addr<hi for lo,hi in state.get('fake_virtual_exec_requests',[])):
   state['stop']={'kind':'synthetic_private_code_execution_required','address':hex(addr)};return False
  if access==UC_MEM_FETCH_PROT and any(int(m['base'],16)<=addr<int(m['base'],16)+m['size'] for m in state.get('synthetic_peb_modules',[])):
   state['stop']={'kind':'system_export','address':hex(addr)};return False
  if access in (UC_MEM_READ_UNMAPPED,UC_MEM_WRITE_UNMAPPED) and any(start<=page and page+4096<=end for start,end in state.get('fake_virtual_commits',[])):
   if state.get('fake_virtual_pages',0)>=65536:state['stop']={'kind':'fake_virtual_page_limit'};return False
   if page in pages:state['stop']={'kind':'mapped_failure','address':hex(addr)};return False
   readonly=any(lo<=page and page+4096<=hi for lo,hi in state.get('fake_virtual_exec_requests',[]))
   uc.mem_map(page,4096,UC_PROT_READ if readonly else UC_PROT_READ|UC_PROT_WRITE);pages.add(page);state['fake_virtual_pages']=state.get('fake_virtual_pages',0)+1;return True
  if sec is None and not 0<=rva<pe.OPTIONAL_HEADER.SizeOfHeaders:
   state['stop']={'kind':'unmapped','address':hex(addr),'rip':hex(uc.reg_read(UC_X86_REG_RIP))}
   if a.model_veh_exceptions and state.get('fake_veh_registrations') and not state.get('handling_exception'):
    fault={'address':addr,'rip':uc.reg_read(UC_X86_REG_RIP),'access':access};signature=uc.reg_read(UC_X86_REG_RBX)^uc.reg_read(UC_X86_REG_RBP)^0xd5e1740f6aceb1bb
    if signature&0xffffffff!=0x4b8155a3:
     sp=uc.reg_read(UC_X86_REG_RSP);fault.update(registers={name:hex(uc.reg_read(reg)) for name,reg in (('rax',UC_X86_REG_RAX),('rbx',UC_X86_REG_RBX),('rcx',UC_X86_REG_RCX),('rdx',UC_X86_REG_RDX),('rsi',UC_X86_REG_RSI),('rdi',UC_X86_REG_RDI),('r8',UC_X86_REG_R8),('r9',UC_X86_REG_R9),('r10',UC_X86_REG_R10),('r11',UC_X86_REG_R11),('r12',UC_X86_REG_R12),('r13',UC_X86_REG_R13),('r14',UC_X86_REG_R14),('r15',UC_X86_REG_R15))},recent=list(recent))
     if stack<=sp<=stack+0x200000-0x1000:fault['stack_base']=hex(sp);fault['stack_hex']=bytes(uc.mem_read(sp,0x1000)).hex()
    state['pending_fault']=fault
   return False
  if page in pages:state['stop']={'kind':'mapped_failure','address':hex(addr)};return False
  uc.mem_map(page,4096,UC_PROT_ALL);pages.add(page)
  if sec is None:
   end=min(pe.OPTIONAL_HEADER.SizeOfHeaders,(page-base)+4096);uc.mem_write(page,image[page-base:end])
  else:
   v,_,raw,rawsize,name=sec;lo=max(page-base,v);hi=min(page-base+4096,v+rawsize)
   if hi>lo:uc.mem_write(base+lo,image[raw+lo-v:raw+hi-v])
   for slot,marker in slot_pages.get(page,[]):
    if slot+8<=page+4096:uc.mem_write(slot,struct.pack('<Q',marker))
  return True
 def code(uc,addr,size,user):
  if addr==0x16188f698 and state.get('synthetic_fix_observed_vdivss'):
   src0=uc.reg_read(UC_X86_REG_XMM0);src1=uc.reg_read(UC_X86_REG_XMM1)
   if bytes(uc.mem_read(addr,4))!=bytes.fromhex('c5f25ef0') or src0&0xffffffff!=0x44870000 or src1&0xffffffff!=0x44f00000:
    state['stop']={'kind':'unsupported_observed_vdivss_operands','address':hex(addr)};uc.emu_stop();return
   uc.reg_write(UC_X86_REG_YMM6,(src1&(((1<<128)-1)^0xffffffff))|0x3fe38e39);state.setdefault('synthetic_vdivss_fixes',[]).append({'address':hex(addr),'numerator_bits':'0x44f00000','denominator_bits':'0x44870000','result_bits':'0x3fe38e39','basis':'isolated Unicorn SSE comparison; only observed operands','host_api_called':False});uc.reg_write(UC_X86_REG_RIP,addr+4);return
  if addr==exception_mem+0x7200 and state.get('synthetic_getmonitorinfo_symbol'):
   state['stop']={'kind':'synthetic_getmonitorinfo_call','host_api_called':False};uc.emu_stop();return
  if addr==exception_mem+0x7210 and state.get('synthetic_setwindowlonga_symbol'):
   state['stop']={'kind':'synthetic_setwindowlonga_call','host_api_called':False};uc.emu_stop();return
  if addr==exception_mem+0x71f0 and state.get('synthetic_monitorfromwindow_symbol'):
   state['stop']={'kind':'synthetic_monitorfromwindow_call','host_api_called':False};uc.emu_stop();return
  if addr==exception_mem+0x71e0 and state.get('synthetic_clienttoscreen_symbol'):
   state['stop']={'kind':'synthetic_clienttoscreen_call','host_api_called':False};uc.emu_stop();return
  if addr==exception_mem+0x71d0 and state.get('synthetic_getclientrect_symbol'):
   state['stop']={'kind':'synthetic_getclientrect_call','host_api_called':False};uc.emu_stop();return
  if addr==exception_mem+0x71c0 and state.get('synthetic_getwindowuserdata_enabled'):
   sp=uc.reg_read(UC_X86_REG_RSP);window=state.get('synthetic_window',{})
   if uc.reg_read(UC_X86_REG_RCX)==0x7d5900000004 and uc.reg_read(UC_X86_REG_RDX)&0xffffffff==0xffffffeb and window.get('userdata') in ('0x0','0x2') and child_stack<=sp<=child_stack+0x200000-8:
    state['synthetic_getwindowuserdata_reads']=state.get('synthetic_getwindowuserdata_reads',0)+1;uc.reg_write(UC_X86_REG_RAX,int(window['userdata'],16));uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
  if addr==exception_mem+0x71c0 and state.get('synthetic_getwindowlongptr_symbol'):
   state['stop']={'kind':'synthetic_getwindowlongptr_call','host_api_called':False};uc.emu_stop();return
  if addr==exception_mem+0x71b0 and state.get('synthetic_window_rect_enabled'):
   sp=uc.reg_read(UC_X86_REG_RSP);out=uc.reg_read(UC_X86_REG_RDX);pos=state.get('synthetic_window',{}).get('position',{})
   if uc.reg_read(UC_X86_REG_RCX)==0x7d5900000004 and child_stack<=sp<=child_stack+0x200000-8 and child_stack<=out<=child_stack+0x200000-16 and (pos.get('x'),pos.get('y'),pos.get('width'),pos.get('height'))==(0,0,1296,759):
    uc.mem_write(out,struct.pack('<4i',0,0,1296,759));state['synthetic_window_rect_reads']=state.get('synthetic_window_rect_reads',0)+1;uc.reg_write(UC_X86_REG_RAX,1);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
  if addr==exception_mem+0x71b0 and state.get('synthetic_getwindowrect_symbol'):
   state['stop']={'kind':'synthetic_getwindowrect_call','host_api_called':False};uc.emu_stop();return
  if addr==exception_mem+0x71a0 and state.get('synthetic_window_style_enabled'):
   sp=uc.reg_read(UC_X86_REG_RSP);window=state.get('synthetic_window',{})
   if uc.reg_read(UC_X86_REG_RCX)==0x7d5900000004 and uc.reg_read(UC_X86_REG_RDX)&0xffffffff==0xfffffff0 and window.get('style') in ('0xcb0000','0x0') and child_stack<=sp<=child_stack+0x200000-8:
    state['synthetic_window_style_reads']=state.get('synthetic_window_style_reads',0)+1;uc.reg_write(UC_X86_REG_RAX,int(window['style'],16));uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
  if addr==exception_mem+0x71a0 and state.get('synthetic_getwindowlong_symbol'):
   state['stop']={'kind':'synthetic_getwindowlong_call','host_api_called':False};uc.emu_stop();return
  if addr==exception_mem+0x7190 and state.get('synthetic_setwindowpos_symbol'):
   state['stop']={'kind':'synthetic_setwindowpos_call','host_api_called':False};uc.emu_stop();return
  if addr==exception_mem+0x7180 and state.get('synthetic_adjustrect_symbol'):
   state['stop']={'kind':'synthetic_adjustrect_call','host_api_called':False};uc.emu_stop();return
  if addr==exception_mem+0x7170 and state.get('synthetic_setwindowtext_symbol'):
   state['stop']={'kind':'synthetic_setwindowtext_call','host_api_called':False};uc.emu_stop();return
  if addr==exception_mem+0x7160 and state.get('synthetic_setwindowlong_symbol'):
   state['stop']={'kind':'synthetic_setwindowlong_call','host_api_called':False};uc.emu_stop();return
  if addr==exception_mem+0x7150 and state.get('synthetic_createwindow_symbol'):
   state['stop']={'kind':'synthetic_createwindow_call','host_api_called':False};uc.emu_stop();return
  if addr==exception_mem+0x7140 and state.get('synthetic_registerclass_symbol'):
   state['stop']={'kind':'synthetic_registerclass_call','struct':hex(uc.reg_read(UC_X86_REG_RCX)),'host_api_called':False};uc.emu_stop();return
  if addr==exception_mem+0x7130 and state.get('synthetic_stockobject_symbol'):
   state['stop']={'kind':'synthetic_stockobject_call','index':hex(uc.reg_read(UC_X86_REG_RCX)),'host_api_called':False};uc.emu_stop();return
  if addr==exception_mem+0x7120 and state.get('synthetic_loadcursor_symbol'):
   state['stop']={'kind':'synthetic_loadcursor_call','instance':hex(uc.reg_read(UC_X86_REG_RCX)),'name_or_id':hex(uc.reg_read(UC_X86_REG_RDX)),'host_api_called':False};uc.emu_stop();return
  if addr==exception_mem+0x7110 and state.get('synthetic_loadicon_symbol'):
   state['stop']={'kind':'synthetic_loadicon_call','instance':hex(uc.reg_read(UC_X86_REG_RCX)),'name_or_id':hex(uc.reg_read(UC_X86_REG_RDX)),'host_api_called':False};uc.emu_stop();return
  if addr==exception_mem+0x7100 and state.get('synthetic_messagebox_symbol'):
   def read_wide(ptr):
    if not ptr:return None
    chars=[]
    for offset in range(0,4096,2):
     pair=bytes(uc.mem_read(ptr+offset,2))
     if pair==b'\0\0':return b''.join(chars).decode('utf-16le','replace')
     chars.append(pair)
    return '<unterminated>'
   state['stop']={'kind':'synthetic_messagebox_call','text':read_wide(uc.reg_read(UC_X86_REG_RDX)),'caption':read_wide(uc.reg_read(UC_X86_REG_R8)),'flags':hex(uc.reg_read(UC_X86_REG_R9)),'host_api_called':False};uc.emu_stop();return
  if addr==exception_mem+0x70f0 and state.get('fake_d3d12_create_device_symbol'):
   state['stop']={'kind':'synthetic_d3d12_create_device_call','address':hex(addr),'host_api_called':False};uc.emu_stop();return
  if addr==0x7d55000020d0 and state.get('synthetic_d3d12_capable_profile'):
   sp=uc.reg_read(UC_X86_REG_RSP);obj=uc.reg_read(UC_X86_REG_RCX);feature=uc.reg_read(UC_X86_REG_RDX);out=uc.reg_read(UC_X86_REG_R8);size=uc.reg_read(UC_X86_REG_R9);payload=None
   if obj==0x7d5500000000 and child_stack<=sp<=child_stack+0x200000-8 and child_stack<=out<=child_stack+0x200000-size:
    if (feature,size)==(0,60):payload=struct.pack('<15I',1,1,3,3,3,1,1,1,3,40,1,1,1,1,2)
    elif (feature,size)==(8,24):payload=struct.pack('<6I',1,32,32,1024,1,1)
    elif (feature,size)==(7,4) and bytes(uc.mem_read(out,4))==struct.pack('<I',0x60):payload=struct.pack('<I',0x60)
    elif (feature,size)==(3,12) and struct.unpack('<I',uc.mem_read(out,4))[0]<=191:payload=bytes(uc.mem_read(out,4))+struct.pack('<II',0x02004321 if state.get('synthetic_d3d12_buffer_formats') else 0x02004320,0xc0)
   if payload is not None:
    uc.mem_write(out,payload);state.setdefault('synthetic_d3d12_profile_queries',[]).append({'feature':feature,'size':size});uc.reg_write(UC_X86_REG_RAX,0);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
  if addr==0x7d55000020d0 and (state.get('synthetic_d3d12_unsupported_formats') or state.get('synthetic_d3d12_supported_formats')):
   sp=uc.reg_read(UC_X86_REG_RSP);obj=uc.reg_read(UC_X86_REG_RCX);feature=uc.reg_read(UC_X86_REG_RDX);out=uc.reg_read(UC_X86_REG_R8);size=uc.reg_read(UC_X86_REG_R9)
   if obj==0x7d5500000000 and feature==3 and size==12 and child_stack<=sp<=child_stack+0x200000-8 and child_stack<=out<=child_stack+0x200000-size:
    fmt=struct.unpack('<I',uc.mem_read(out,4))[0]
    if fmt<=191:
     uc.mem_write(out+4,struct.pack('<II',0x02004320,0xc0) if state.get('synthetic_d3d12_supported_formats') else b'\0'*8);state.setdefault('synthetic_d3d12_format_queries',[]).append(fmt);uc.reg_write(UC_X86_REG_RAX,0);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
  if addr in (0x7d5600002010,0x7d5600002020) and state.get('synthetic_dxgi_output_refcount_enabled'):
   sp=uc.reg_read(UC_X86_REG_RSP);obj=uc.reg_read(UC_X86_REG_RCX);refs=state.get('synthetic_dxgi_output_refs',1)+(1 if addr==0x7d5600002010 else -1)
   if obj==0x7d5600000000 and 0<=refs<=100 and child_stack<=sp<=child_stack+0x200000-8:
    state['synthetic_dxgi_output_refs']=refs;state.setdefault('synthetic_dxgi_output_refcalls',[]).append({'method':'AddRef' if addr==0x7d5600002010 else 'Release','refs':refs});uc.reg_write(UC_X86_REG_RAX,refs);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
  if 0x7d5600002000<=addr<0x7d5600003000 and state.get('synthetic_dxgi_output'):
   state['stop']={'kind':'dxgi_output_method_required','interface':'IDXGIOutput','slot':(addr-0x7d5600002000)//16,'host_api_called':False};uc.emu_stop();return
  if 0x7d5800002000<=addr<0x7d5800003000 and state.get('synthetic_second_d3d12_device'):
   state['stop']={'kind':'second_d3d12_device_method_required','interface':'ID3D12Device','slot':(addr-0x7d5800002000)//16,'host_api_called':False};uc.emu_stop();return
  if 0x7d5500002000<=addr<0x7d5500003000 and state.get('synthetic_d3d12_device'):
   state['stop']={'kind':'d3d12_device_method_required','interface':'ID3D12Device','slot':(addr-0x7d5500002000)//16,'host_api_called':False};uc.emu_stop();return
  if addr in (0x7d5400002020,0x7d5300002020) and state.get('synthetic_dxgi_release_enabled'):
   sp=uc.reg_read(UC_X86_REG_RSP);obj=uc.reg_read(UC_X86_REG_RCX);expected=0x7d5400000000 if addr==0x7d5400002020 else 0x7d5300000000
   if obj==expected and child_stack<=sp<=child_stack+0x200000-8:
    state.setdefault('synthetic_dxgi_release_calls',[]).append(hex(obj));uc.reg_write(UC_X86_REG_RAX,0);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
  if 0x7d5400002000<=addr<0x7d5400003000 and state.get('synthetic_dxgi_adapter'):
   state['stop']={'kind':'dxgi_adapter_method_required','interface':state['synthetic_dxgi_adapter']['interface'],'slot':(addr-0x7d5400002000)//16,'host_api_called':False};uc.emu_stop();return
  if 0x7d5300002000<=addr<0x7d5300003000 and state.get('synthetic_dxgi_factory'):
   state['stop']={'kind':'dxgi_interface_method_required','interface':state['synthetic_dxgi_factory'].get('interface','IDXGIFactory1'),'slot':(addr-0x7d5300002000)//16,'host_api_called':False};uc.emu_stop();return
  if addr==exception_mem+0x70e0 and state.get('fake_dxgi_factory_symbol'):
   state['stop']={'kind':'synthetic_dxgi_factory_call','address':hex(addr),'host_api_called':False};uc.emu_stop();return
  if addr in (0x7d5200002090,0x7d5200002100,0x7d5200002140) and state.get('synthetic_input_actions_enabled'):
   sp=uc.reg_read(UC_X86_REG_RSP);obj=uc.reg_read(UC_X86_REG_RCX);ptr=uc.reg_read(UC_X86_REG_RDX)
   if not stack<=sp<=stack+0x200000-8 or obj!=0x7d5200000000 or not base+0x32c84000<=ptr<=base+0x392a6be1-128:state['stop']={'kind':'unsupported_synthetic_action_set'};uc.emu_stop();return
   raw=bytes(uc.mem_read(ptr,128));end=raw.find(b'\0')
   if end<=0 or any(c<32 or c>126 for c in raw[:end]):state['stop']={'kind':'unsupported_synthetic_action_name'};uc.emu_stop();return
   name=raw[:end].decode('ascii');kind='set' if addr==0x7d5200002090 else 'digital' if addr==0x7d5200002100 else 'analog';method={'set':'GetActionSetHandle','digital':'GetDigitalActionHandle','analog':'GetAnalogActionHandle'}[kind];handles=state.setdefault('synthetic_action_'+kind+'_handles',{})
   if name not in handles and len(handles)>=1024:state['stop']={'kind':'synthetic_action_set_limit'};uc.emu_stop();return
   base_handle={'set':0x7d8000000000,'digital':0x7d8100000000,'analog':0x7d8200000000}[kind];result=handles.setdefault(name,base_handle+len(handles)*16);state.setdefault('synthetic_steam_assumptions',[]).append({'interface':'SteamInput006','method':method,'name':name,'handle':hex(result),'assumption':'arbitrary stable synthetic handle, no Steam manifest or device','host_api_called':False});uc.reg_write(UC_X86_REG_RAX,result);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
  if 0x7d5200002000<=addr<0x7d5200003000 and state.get('synthetic_steam_input'):
   state['stop']={'kind':'steam_interface_method_required','interface':state['synthetic_steam_input']['version'],'slot':(addr-0x7d5200002000)//16,'host_api_called':False};uc.emu_stop();return
  if 0x7d7100000000<=addr<0x7d7100001000 and state.get('virtual_xinput_markers'):
   symbol=state['virtual_xinput_markers'].get(hex(addr))
   if symbol:state['stop']={'kind':'xinput_api_call_required','symbol':symbol,'address':hex(addr),'host_api_called':False};uc.emu_stop();return
  if 0x7d7000000000<=addr<0x7d7000001000 and state.get('virtual_oodle_markers'):
   symbol=state['virtual_oodle_markers'].get(hex(addr))
   if symbol=='OodleLZDecoder_MemorySizeNeeded':
    sp=uc.reg_read(UC_X86_REG_RSP);compressor=uc.reg_read(UC_X86_REG_RCX)&0xffffffff;length=uc.reg_read(UC_X86_REG_RDX)
    if not stack<=sp<=stack+0x200000-8 or compressor!=8 or length!=0xffffffffffffffff:state['stop']={'kind':'unsupported_synthetic_oodle_size','compressor':compressor,'length':hex(length)};uc.emu_stop();return
    state.setdefault('synthetic_oodle_calls',[]).append({'symbol':symbol,'compressor':compressor,'length':-1,'result':0x6d0d8,'basis':'preserved DLL Unicorn probe and decompilation','host_api_called':False});uc.reg_write(UC_X86_REG_RAX,0x6d0d8);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if symbol:state['stop']={'kind':'oodle_api_call_required','symbol':symbol,'address':hex(addr),'host_api_called':False};uc.emu_stop();return
  if addr==exception_mem+0x70d0 and state.get('fake_coinitialize_symbol'):
   sp=uc.reg_read(UC_X86_REG_RSP);reserved=uc.reg_read(UC_X86_REG_RCX);flags=uc.reg_read(UC_X86_REG_RDX)
   if not state.get('dynamic_worker_experiment') or not child_stack<=sp<=child_stack+0x200000-8 or reserved!=0 or flags!=6:state['stop']={'kind':'unsupported_synthetic_com_init'};uc.emu_stop();return
   state.setdefault('synthetic_com_calls',[]).append({'operation':'CoInitializeEx','flags':flags,'result':0,'assumption':'synthetic apartment; no host COM or objects','host_api_called':False});uc.reg_write(UC_X86_REG_RAX,0);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
  if addr==exception_mem+0x70c0 and state.get('fake_processor_info_symbol'):
   sp=uc.reg_read(UC_X86_REG_RSP);out=uc.reg_read(UC_X86_REG_RCX);lengthptr=uc.reg_read(UC_X86_REG_RDX);needed=9*32
   if not stack<=sp<=stack+0x200000-8 or not stack<=lengthptr<=stack+0x200000-4:state['stop']={'kind':'unsupported_synthetic_processor_info'};uc.emu_stop();return
   capacity=struct.unpack('<I',uc.mem_read(lengthptr,4))[0];uc.mem_write(lengthptr,struct.pack('<I',needed))
   if not out or capacity<needed:
    uc.mem_write(teb+0x68,struct.pack('<I',122));result=0
   else:
    committed=any(lo<=out and out+needed<=hi for lo,hi in state.get('fake_virtual_commits',[]));heap=0x790000000000<=out<=0x790000000000+state.get('fake_heap_used',0)-needed
    if not (stack<=out<=stack+0x200000-needed or committed or heap):state['stop']={'kind':'unsupported_synthetic_processor_buffer','address':hex(out)};uc.emu_stop();return
    if committed:
     for page in range(out&~0xfff,(out+needed+4095)&~0xfff,4096):
      if page not in pages and not invalid(uc,UC_MEM_WRITE_UNMAPPED,page,1,0,None):uc.emu_stop();return
    payload=b''.join(struct.pack('<QIIQQ',1<<i,0,0,0,0) for i in range(8))+struct.pack('<QIIQQ',0xff,3,0,0,0);uc.mem_write(out,payload);result=1
   state.setdefault('synthetic_processor_queries',[]).append({'requested':capacity,'required':needed,'result':result,'assumption':'eight synthetic single-thread cores and one package','host_api_called':False});uc.reg_write(UC_X86_REG_RAX,result);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
  if addr==exception_mem+0x70b0 and state.get('fake_timer_begin_symbol'):
   sp=uc.reg_read(UC_X86_REG_RSP);period=uc.reg_read(UC_X86_REG_RCX)
   if not stack<=sp<=stack+0x200000-8 or not 1<=period<=1000:state['stop']={'kind':'unsupported_synthetic_timer_period','period':period};uc.emu_stop();return
   state.setdefault('synthetic_timer_queries',[]).append({'period_ms':period,'assumption':'request acknowledged only inside synthetic model','host_api_called':False});uc.reg_write(UC_X86_REG_RAX,0);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
  if addr==exception_mem+0x70a0 and state.get('fake_timer_caps_symbol'):
   sp=uc.reg_read(UC_X86_REG_RSP);out=uc.reg_read(UC_X86_REG_RCX);size=uc.reg_read(UC_X86_REG_RDX)
   if not stack<=sp<=stack+0x200000-8 or size!=8 or not stack<=out<=stack+0x200000-8:state['stop']={'kind':'unsupported_synthetic_timer_caps'};uc.emu_stop();return
   uc.mem_write(out,struct.pack('<II',1,1000));state.setdefault('synthetic_timer_queries',[]).append({'min_ms':1,'max_ms':1000,'assumption':'fixed synthetic capabilities','host_api_called':False});uc.reg_write(UC_X86_REG_RAX,0);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
  if addr==exception_mem+0x7090 and state.get('fake_shgetfolderpath_symbol'):
   state['stop']={'kind':'synthetic_shell_folder_call','address':hex(addr),'host_api_called':False};uc.emu_stop();return
  if 0x7d5000002000<=addr<0x7d5000003000 and state.get('synthetic_steam_interface'):
   state['stop']={'kind':'steam_interface_method_required','interface':state['synthetic_steam_interface']['version'],'slot':(addr-0x7d5000002000)//16,'host_api_called':False};uc.emu_stop();return
  if addr==exception_mem+0x8f00 and state.get('pending_steam_context_callback'):
   context=state.pop('pending_steam_context_callback');ptr=int(context['context'],16);slot=struct.unpack('<Q',uc.mem_read(ptr+16,8))[0]
   if slot:
    if any(ptr+8<point+0x40 and point<ptr+16 for point in watch_points):state['stop']={'kind':'watched_synthetic_steam_context','address':hex(ptr+8)};uc.emu_stop();return
    uc.mem_write(ptr+8,struct.pack('<Q',1));state.setdefault('synthetic_steam_contexts',{})[hex(ptr)]={'slot':hex(slot),'generation':1,'assumption':'synthetic cached interface; no Steam session'}
   uc.reg_write(UC_X86_REG_RAX,ptr+16);uc.reg_write(UC_X86_REG_RSP,int(context['parent_sp'],16)+8);uc.reg_write(UC_X86_REG_RIP,int(context['return'],16));return
  if exception_mem+0x9000<=addr<exception_mem+0x10000 and state.get('virtual_steam_markers'):
   symbol=state['virtual_steam_markers'].get(hex(addr))
   if symbol=='SteamInternal_ContextInit' and hex(uc.reg_read(UC_X86_REG_RCX)) in state.get('synthetic_steam_contexts',{}):
    sp=uc.reg_read(UC_X86_REG_RSP);ptr=uc.reg_read(UC_X86_REG_RCX);cached=state['synthetic_steam_contexts'][hex(ptr)]
    if not stack<=sp<=stack+0x200000-8 or struct.unpack('<QQ',uc.mem_read(ptr+8,16))!=(cached['generation'],int(cached['slot'],16)):state['stop']={'kind':'unsupported_cached_steam_context'};uc.emu_stop();return
    uc.reg_write(UC_X86_REG_RAX,ptr+16);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if symbol:state['stop']={'kind':'steam_api_call_required','symbol':symbol,'address':hex(addr),'host_api_called':False};uc.emu_stop();return
  state['instructions']+=1;recent.append(hex(addr))
  if 6000<=len(state.get('modeled_faults',[]))<6100:
   value=hex(uc.reg_read(UC_X86_REG_RAX));events=state.setdefault('late_rax_changes',[])
   if not events or events[-1]['value']!=value:
    if len(events)>=1000:del events[0]
    events.append({'rip':hex(addr),'value':value,'rsp':hex(uc.reg_read(UC_X86_REG_RSP))})
  if addr==0x1714e2875:state.setdefault('registry_call_site_hits',[]).append({'instruction':state['instructions'],'rcx':hex(uc.reg_read(UC_X86_REG_RCX))})
  if state.get('fake_crypt_symbols') and (addr in (exception_mem+0x7070,exception_mem+0x7080) or imports.get(addr,'').lower() in ('crypt32.dll!cryptprotectmemory','crypt32.dll!cryptunprotectmemory')):
   sp=uc.reg_read(UC_X86_REG_RSP);ptr=uc.reg_read(UC_X86_REG_RCX);n=uc.reg_read(UC_X86_REG_RDX);flags=uc.reg_read(UC_X86_REG_R8);protect=addr==exception_mem+0x7070 or imports.get(addr,'').lower()=='crypt32.dll!cryptprotectmemory';name='CryptProtectMemory' if protect else 'CryptUnprotectMemory';regions=state.setdefault('fake_crypt_regions',{});key=hex(ptr)
   committed=any(lo<=ptr and ptr+n<=hi for lo,hi in state.get('fake_virtual_commits',[]));image_data=base+0x33534000<=ptr<=base+0x392a6be1-n
   if not stack<=sp<=stack+0x200000-8 or not 16<=n<=0x100000 or n%16 or flags!=0 or not (committed or image_data):state['stop']={'kind':'unsupported_fake_crypt_memory','import':name,'address':key,'size':n,'flags':hex(flags)};uc.emu_stop();return
   if any(ptr<point+0x40 and point<ptr+n for point in watch_points):state['stop']={'kind':'watched_fake_crypt_memory','address':key,'size':n};uc.emu_stop();return
   if protect and key in regions or not protect and (key not in regions or regions[key]['size']!=n):state['stop']={'kind':'unexpected_fake_crypt_state','import':name,'address':key};uc.emu_stop();return
   if committed:
    for page in range(ptr&~0xfff,(ptr+n+4095)&~0xfff,4096):
     if page not in pages and not invalid(uc,UC_MEM_READ_UNMAPPED,page,1,0,None):uc.emu_stop();return
   original=bytes(uc.mem_read(ptr,n));digest=hashlib.sha256(original).hexdigest()
   if not protect and digest!=regions[key]['ciphertext_sha256']:state['stop']={'kind':'modified_fake_crypt_ciphertext','address':key};uc.emu_stop();return
   from Crypto.Cipher import AES
   cipher=AES.new(hashlib.sha256(b'isolated synthetic marathon crypt memory model').digest(),AES.MODE_ECB);result=cipher.encrypt(original) if protect else cipher.decrypt(original);uc.mem_write(ptr,result)
   if protect:regions[key]={'size':n,'ciphertext_sha256':hashlib.sha256(result).hexdigest(),'plaintext_sha256':digest}
   else:
    if hashlib.sha256(result).hexdigest()!=regions[key]['plaintext_sha256']:state['stop']={'kind':'fake_crypt_roundtrip_mismatch'};uc.emu_stop();return
    del regions[key]
   state.setdefault('fake_crypt_calls',[]).append({'import':name,'address':key,'size':n,'assumption':'deterministic reversible AES substitute, not Windows cryptography','host_api_called':False});uc.reg_write(UC_X86_REG_RAX,1);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
  if addr==0x171412716:
   events=state.setdefault('loader_name_branch_samples',[])
   if len(events)<100:events.append({'recent':list(recent),'rax':hex(uc.reg_read(UC_X86_REG_RAX)),'rcx':hex(uc.reg_read(UC_X86_REG_RCX)),'eflags':hex(uc.reg_read(UC_X86_REG_EFLAGS))})
  if addr==exception_mem+0x7060 and state.get('fake_mitigation_symbol'):
   sp=uc.reg_read(UC_X86_REG_RSP);policy=uc.reg_read(UC_X86_REG_RCX);buf=uc.reg_read(UC_X86_REG_RDX);length=uc.reg_read(UC_X86_REG_R8)
   if not stack<=sp<=stack+0x200000-8 or policy!=1 or length!=4 or not stack<=buf<=stack+0x200000-4:state['stop']={'kind':'unsupported_fake_mitigation'};uc.emu_stop();return
   value=struct.unpack('<I',bytes(uc.mem_read(buf,4)))[0]
   if value!=15:state['stop']={'kind':'unsupported_fake_mitigation','value':hex(value)};uc.emu_stop();return
   result=0 if a.synthetic_mitigation_failure else 1;state.setdefault('fake_mitigation_calls',[]).append({'policy':policy,'flags':hex(value),'assumed_result':'failure' if not result else 'success','host_api_called':False});uc.reg_write(UC_X86_REG_RAX,result);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
  if (trace_range and trace_range[0]<=addr<trace_range[1]) or state['instructions']<=a.trace_first:
   ev=state.setdefault('range_events',[])
   if len(ev)<50000:
    try:raw=bytes(uc.mem_read(addr,min(size,15))).hex()
    except UcError:raw=None
    ev.append({'instruction':state['instructions'],'pc':hex(addr),'bytes':raw,'regs':{name:hex(uc.reg_read(reg)) for name,reg in (('rax',UC_X86_REG_RAX),('rbx',UC_X86_REG_RBX),('rcx',UC_X86_REG_RCX),('rdx',UC_X86_REG_RDX),('rsp',UC_X86_REG_RSP),('r8',UC_X86_REG_R8),('r9',UC_X86_REG_R9),('r10',UC_X86_REG_R10),('r11',UC_X86_REG_R11),('rsi',UC_X86_REG_RSI),('rdi',UC_X86_REG_RDI),('rbp',UC_X86_REG_RBP),('r12',UC_X86_REG_R12),('r13',UC_X86_REG_R13),('r14',UC_X86_REG_R14),('r15',UC_X86_REG_R15),('eflags',UC_X86_REG_EFLAGS))}})
    if addr==0x159df64be:
     sp=uc.reg_read(UC_X86_REG_RSP);ev[-1]['division_operands']={'xmm0_low32':hex(uc.reg_read(UC_X86_REG_XMM0)&0xffffffff),'stack_20_bits':hex(struct.unpack('<I',uc.mem_read(sp+0x20,4))[0])}
    if addr==0x14970e5ff:
     ev[-1]['float_inputs']={name:hex(uc.reg_read(reg)&0xffffffff) for name,reg in (('xmm4',UC_X86_REG_XMM4),('xmm5',UC_X86_REG_XMM5),('xmm6',UC_X86_REG_XMM6),('xmm7',UC_X86_REG_XMM7),('xmm9',UC_X86_REG_XMM9))}
    if addr==0x16188f698:
     ev[-1]['float_inputs']={name:hex(uc.reg_read(reg)&0xffffffff) for name,reg in (('xmm0',UC_X86_REG_XMM0),('xmm1',UC_X86_REG_XMM1))}
  if a.trace_dispatch:
   pending=state.get('pending_dispatch')
   if pending is not None and pending.get('armed'):
    pending['actual_next']=hex(addr);pending['matched']=addr==int(pending['continuation'],16);pending.pop('armed');state.pop('pending_dispatch')
   if addr==0x162478566 and state.get('pending_dispatch') is not None:state['pending_dispatch']['armed']=True
   if addr==0x162478533:
    events=state.setdefault('dispatch_events',[])
    if len(events)<10000:
     continuation=struct.unpack('<Q',uc.mem_read(tls_block+0x1210,8))[0];event={'source':list(recent)[-2] if len(recent)>1 else None,'dispatcher':hex(addr),'continuation':hex(continuation),'instruction':state['instructions']};events.append(event);state['pending_dispatch']=event
  if addr==0x162478533 and (a.inline_dispatch or a.stop_after_dispatches is not None):
   state['dispatch_seen']=state.get('dispatch_seen',0)+1
   if a.stop_after_dispatches is not None and state['dispatch_seen']>a.stop_after_dispatches:
    state['stop']={'kind':'dispatch_checkpoint','completed':a.stop_after_dispatches,'rip':hex(addr)};uc.emu_stop();return
   if a.inline_dispatch:
    sp=uc.reg_read(UC_X86_REG_RSP)
    if not (stack+88<=sp<=stack+0x200000-8 or a.follow_thread and child_stack+88<=sp<=child_stack+0x200000-8):state['stop']={'kind':'unsafe_inline_stack'};uc.emu_stop();return
    target=struct.unpack('<Q',uc.mem_read(tls_block+0x1210,8))[0]
    writes=[(sp-8,target),(sp-16,uc.reg_read(UC_X86_REG_RAX)),(sp-24,0x162478547),(sp-32,uc.reg_read(UC_X86_REG_EFLAGS)),(sp-40,uc.reg_read(UC_X86_REG_RCX)),(sp-48,uc.reg_read(UC_X86_REG_RDX)),(sp-88,0x171a1191c)]
    for address,value in writes:uc.mem_write(address,struct.pack('<Q',value))
    state['stack_writes']+=8;uc.reg_write(UC_X86_REG_RIP,target);return
  if addr==exception_mem+0x3000 and state.get('active_crt_initializer'):
   pending=state['active_crt_initializer'];result=uc.reg_read(UC_X86_REG_RAX)&0xffffffff
   pending['returns'].append(result)
   if (pending['mode']=='_initterm_e' and result) or not pending['remaining']:
    uc.reg_write(UC_X86_REG_RSP,pending['sp']+8);uc.reg_write(UC_X86_REG_RAX,result);uc.reg_write(UC_X86_REG_RIP,pending['return_address']);state.setdefault('modeled_crt_initializers',[]).append(pending);del state['active_crt_initializer'];return
   target=pending['remaining'].pop(0);pending['called'].append(hex(target));uc.reg_write(UC_X86_REG_RSP,pending['sp']-0x30);uc.mem_write(pending['sp']-0x30,struct.pack('<Q',exception_mem+0x3000));uc.reg_write(UC_X86_REG_RIP,target)
   if pending['mode']=='_initterm' and a.checkpoint_at_constructor==len(pending['called']):state['stop']={'kind':'constructor_checkpoint','number':len(pending['called']),'next':hex(target)};uc.emu_stop()
   return
  if a.model_crt_initterm_e and state.get('active_crt_initializer') and addr in (0x16ef75d84,0x16ef75d88):
   expected=b'\xc5\xfc\x11\x01' if addr==0x16ef75d84 else b'\xc5\xfc\x11\x41\x20';ptr=uc.reg_read(UC_X86_REG_RCX)+(0 if addr==0x16ef75d84 else 32)
   if bytes(uc.mem_read(addr,len(expected)))!=expected or uc.reg_read(UC_X86_REG_YMM0)!=0 or not stack<=ptr<=stack+0x200000-32:state['stop']={'kind':'unsafe_fake_ymm_store','address':hex(addr)};uc.emu_stop();return
   uc.mem_write(ptr,bytes(32));state.setdefault('fake_zero_vector_stores',[]).append({'rip':hex(addr),'address':hex(ptr)});uc.reg_write(UC_X86_REG_RIP,addr+len(expected));return
  if a.model_crt_initterm_e and state.get('active_crt_initializer') and addr==0x1574d5ea7:
   expected=b'\xc5\xfc\x11\x44\x24\x50';ptr=uc.reg_read(UC_X86_REG_RSP)+0x50
   if bytes(uc.mem_read(addr,len(expected)))!=expected or uc.reg_read(UC_X86_REG_YMM0)!=0 or not stack<=ptr<=stack+0x200000-32:state['stop']={'kind':'unsafe_fake_ymm_store','address':hex(addr)};uc.emu_stop();return
   uc.mem_write(ptr,bytes(32));state.setdefault('fake_zero_vector_stores',[]).append({'rip':hex(addr),'address':hex(ptr)});uc.reg_write(UC_X86_REG_RIP,addr+len(expected));return
  if a.model_crt_initterm_e and state.get('active_crt_initializer') and addr in (0x15efdc261,0x15efdc267,0x15efdc26c):
   specs={0x15efdc261:(b'\xc5\xfc\x11\x44\x24\x60',UC_X86_REG_RSP,0x60),0x15efdc267:(b'\xc5\xfc\x11\x45\x80',UC_X86_REG_RBP,-0x80),0x15efdc26c:(b'\xc5\xfc\x11\x45\xa0',UC_X86_REG_RBP,-0x60)};expected,reg,offset=specs[addr];ptr=uc.reg_read(reg)+offset
   if bytes(uc.mem_read(addr,len(expected)))!=expected or uc.reg_read(UC_X86_REG_YMM0)!=0 or not stack<=ptr<=stack+0x200000-32:state['stop']={'kind':'unsafe_fake_ymm_store','address':hex(addr)};uc.emu_stop();return
   uc.mem_write(ptr,bytes(32));state.setdefault('fake_zero_vector_stores',[]).append({'rip':hex(addr),'address':hex(ptr)});uc.reg_write(UC_X86_REG_RIP,addr+len(expected));return
  if a.model_crt_initterm_e and state.get('active_crt_initializer') and addr==0x16ef80ac4:
   expected=b'\xc5\xfc\x11\x01';ptr=uc.reg_read(UC_X86_REG_RCX)
   if bytes(uc.mem_read(addr,len(expected)))!=expected or uc.reg_read(UC_X86_REG_YMM0)!=0 or not 0x173534000<=ptr<=0x1792a6be1-32:state['stop']={'kind':'unsafe_fake_ymm_store','address':hex(addr)};uc.emu_stop();return
   uc.mem_write(ptr,bytes(32));state.setdefault('fake_zero_vector_stores',[]).append({'rip':hex(addr),'address':hex(ptr)});uc.reg_write(UC_X86_REG_RIP,addr+len(expected));return
  if a.model_crt_initterm_e and state.get('active_crt_initializer') and addr in (0x157e2ca31,0x157e2ca36):
   expected=b'\xc5\xfc\x11\x40\x20' if addr==0x157e2ca31 else b'\xc5\xfc\x11\x40\x40';ptr=uc.reg_read(UC_X86_REG_RAX)+(0x20 if addr==0x157e2ca31 else 0x40)
   if bytes(uc.mem_read(addr,len(expected)))!=expected or uc.reg_read(UC_X86_REG_YMM0)!=0 or not 0x790000000000<=ptr<=0x790000000000+state.get('fake_heap_used',0)-32:state['stop']={'kind':'unsafe_fake_ymm_store','address':hex(addr)};uc.emu_stop();return
   uc.mem_write(ptr,bytes(32));state.setdefault('fake_zero_vector_stores',[]).append({'rip':hex(addr),'address':hex(ptr)});uc.reg_write(UC_X86_REG_RIP,addr+len(expected));return
  if a.model_crt_initterm_e and state.get('active_crt_initializer') and addr in (0x14aed5c3f,0x14aed5c44,0x14aed5c49,0x14aed5c4e):
   specs={0x14aed5c3f:(b'\xc5\xfc\x11\x43\x20',0x20),0x14aed5c44:(b'\xc5\xfc\x11\x43\x40',0x40),0x14aed5c49:(b'\xc5\xfc\x11\x43\x60',0x60),0x14aed5c4e:(b'\xc5\xfc\x11\x83\x80\x00\x00\x00',0x80)};expected,offset=specs[addr];ptr=uc.reg_read(UC_X86_REG_RBX)+offset
   if bytes(uc.mem_read(addr,len(expected)))!=expected or uc.reg_read(UC_X86_REG_YMM0)!=0 or not 0x790000000000<=ptr<=0x790000000000+state.get('fake_heap_used',0)-32:state['stop']={'kind':'unsafe_fake_ymm_store','address':hex(addr)};uc.emu_stop();return
   uc.mem_write(ptr,bytes(32));state.setdefault('fake_zero_vector_stores',[]).append({'rip':hex(addr),'address':hex(ptr)});uc.reg_write(UC_X86_REG_RIP,addr+len(expected));return
  if a.model_crt_initterm_e and state.get('active_crt_initializer') and addr==0x15175f9cc:
   expected=b'\xc5\xfc\x11\x45\xef';ptr=uc.reg_read(UC_X86_REG_RBP)-0x11
   if bytes(uc.mem_read(addr,len(expected)))!=expected or uc.reg_read(UC_X86_REG_YMM0)!=0 or not stack<=ptr<=stack+0x200000-32:state['stop']={'kind':'unsafe_fake_ymm_store','address':hex(addr)};uc.emu_stop();return
   uc.mem_write(ptr,bytes(32));state.setdefault('fake_zero_vector_stores',[]).append({'rip':hex(addr),'address':hex(ptr)});uc.reg_write(UC_X86_REG_RIP,addr+len(expected));return
  if a.model_crt_initterm_e and state.get('active_crt_initializer') and addr in (0x151dd8b17,0x151dd8b1e):
   loading=addr==0x151dd8b17;expected=b'\xc4\xc1\x7c\x10\x44\x24\x10' if loading else b'\xc4\xc1\x7c\x11\x46\x10';ptr=uc.reg_read(UC_X86_REG_R12 if loading else UC_X86_REG_R14)+0x10
   if bytes(uc.mem_read(addr,len(expected)))!=expected or not (stack<=ptr<=stack+0x200000-32 if loading else 0x790000000000<=ptr<=0x790000000000+state.get('fake_heap_used',0)-32):state['stop']={'kind':'unsafe_fake_ymm_copy','address':hex(addr)};uc.emu_stop();return
   if loading:uc.reg_write(UC_X86_REG_YMM0,int.from_bytes(uc.mem_read(ptr,32),'little'))
   else:uc.mem_write(ptr,uc.reg_read(UC_X86_REG_YMM0).to_bytes(32,'little'))
   state.setdefault('fake_vector_copies',[]).append({'rip':hex(addr),'address':hex(ptr)});uc.reg_write(UC_X86_REG_RIP,addr+len(expected));return
  if a.model_crt_initterm_e and state.get('active_crt_initializer') and addr in (0x152665f38,0x152665f3c):
   loading=addr==0x152665f38;expected=b'\xc5\xfc\x10\x07' if loading else b'\xc5\xfc\x11\x03';ptr=uc.reg_read(UC_X86_REG_RDI if loading else UC_X86_REG_RBX)
   if bytes(uc.mem_read(addr,4))!=expected or not (stack<=ptr<=stack+0x200000-32 if loading else 0x790000000000<=ptr<=0x790000000000+state.get('fake_heap_used',0)-32):state['stop']={'kind':'unsafe_fake_ymm_copy','address':hex(addr)};uc.emu_stop();return
   if loading:uc.reg_write(UC_X86_REG_YMM0,int.from_bytes(uc.mem_read(ptr,32),'little'))
   else:uc.mem_write(ptr,uc.reg_read(UC_X86_REG_YMM0).to_bytes(32,'little'))
   state.setdefault('fake_vector_copies',[]).append({'rip':hex(addr),'address':hex(ptr)});uc.reg_write(UC_X86_REG_RIP,addr+4);return
  if a.model_crt_initterm_e and state.get('active_crt_initializer') and addr in (0x160679c33,0x160679c38):
   offset=0x50 if addr==0x160679c33 else 0x70;expected=bytes.fromhex('c5fc114350' if offset==0x50 else 'c5fc114370');ptr=uc.reg_read(UC_X86_REG_RBX)+offset
   if bytes(uc.mem_read(addr,5))!=expected or uc.reg_read(UC_X86_REG_YMM0)!=0 or not 0x790000000000<=ptr<=0x790000000000+state.get('fake_heap_used',0)-32:state['stop']={'kind':'unsafe_fake_ymm_store','address':hex(addr)};uc.emu_stop();return
   uc.mem_write(ptr,bytes(32));state.setdefault('fake_zero_vector_stores',[]).append({'rip':hex(addr),'address':hex(ptr)});uc.reg_write(UC_X86_REG_RIP,addr+5);return
  if a.model_crt_initterm_e and state.get('active_crt_initializer') and addr in (0x16ef75d80,0x1574d5ea3,0x16ef80ac0,0x157e2ca1e,0x15175f9c8,0x160679c2f):
   if bytes(uc.mem_read(addr,4))!=b'\xc5\xf9\xef\xc0':state['stop']={'kind':'unsafe_fake_vpxor','address':hex(addr)};uc.emu_stop();return
   uc.reg_write(UC_X86_REG_YMM0,0);state.setdefault('fake_vector_zeroes',[]).append(hex(addr));uc.reg_write(UC_X86_REG_RIP,addr+4);return
  if a.model_crt_initterm_e and state.get('active_crt_initializer') and addr in (0x172c53a61,0x172c53a67):
   loading=addr==0x172c53a61;expected=bytes.fromhex('c4c17c1040b8' if loading else 'c4817c114402b8');ptr=uc.reg_read(UC_X86_REG_R8)-0x48+(0 if loading else uc.reg_read(UC_X86_REG_R10))
   if bytes(uc.mem_read(addr,len(expected)))!=expected or not 0x790000000000<=ptr<=0x790000000000+state.get('fake_heap_used',0)-32:state['stop']={'kind':'unsafe_fake_ymm_copy','address':hex(addr)};uc.emu_stop();return
   if loading:uc.reg_write(UC_X86_REG_YMM0,int.from_bytes(uc.mem_read(ptr,32),'little'))
   else:uc.mem_write(ptr,uc.reg_read(UC_X86_REG_YMM0).to_bytes(32,'little'))
   state.setdefault('fake_vector_copies',[]).append({'rip':hex(addr),'address':hex(ptr)});uc.reg_write(UC_X86_REG_RIP,addr+len(expected));return
  if a.model_crt_initterm_e and state.get('active_crt_initializer') and addr in (0x16f9507ff,0x16f95081f,0x16f95083f,0x16f95085f,0x16f95087f):
   index=(addr-0x16f9507ff)//0x20;expected=bytes.fromhex('c5fc1005')+struct.pack('<I',0x4b61709+index*0x10);ptr=0x1744b1f10+index*0x30
   if bytes(uc.mem_read(addr,8))!=expected:state['stop']={'kind':'unsafe_fake_ymm_copy','address':hex(addr)};uc.emu_stop();return
   uc.reg_write(UC_X86_REG_YMM0,int.from_bytes(uc.mem_read(ptr,32),'little'));state.setdefault('fake_vector_copies',[]).append({'rip':hex(addr),'address':hex(ptr)});uc.reg_write(UC_X86_REG_RIP,addr+8);return
  if a.model_crt_initterm_e and state.get('active_crt_initializer') and addr in (0x161addc2e,0x161e2e3ec,0x14e805be1,0x15b4ca09f,0x14fee27b8):
   offsets={0x161addc2e:0xb0,0x161e2e3ec:0xe0,0x14e805be1:0x110,0x15b4ca09f:0x140,0x14fee27b8:0x170};offset=offsets[addr];expected=bytes.fromhex('c5fc1181')+struct.pack('<I',offset);ptr=uc.reg_read(UC_X86_REG_RCX)+offset
   if bytes(uc.mem_read(addr,8))!=expected or not stack<=ptr<=stack+0x200000-32:state['stop']={'kind':'unsafe_fake_ymm_copy','address':hex(addr)};uc.emu_stop();return
   uc.mem_write(ptr,uc.reg_read(UC_X86_REG_YMM0).to_bytes(32,'little'));state.setdefault('fake_vector_copies',[]).append({'rip':hex(addr),'address':hex(ptr)});uc.reg_write(UC_X86_REG_RIP,addr+8);return
  if a.model_crt_initterm_e and state.get('active_crt_initializer') and addr in (0x15008a8a0,0x15008a8ab):
   loading=addr==0x15008a8a0;expected=bytes.fromhex('c5fc1045e7' if loading else 'c5fc114210');ptr=(uc.reg_read(UC_X86_REG_RBP)-0x19) if loading else (uc.reg_read(UC_X86_REG_RDX)+0x10)
   if bytes(uc.mem_read(addr,5))!=expected or not (stack<=ptr<=stack+0x200000-32 if loading else 0x790000000000<=ptr<=0x790000000000+state.get('fake_heap_used',0)-32):state['stop']={'kind':'unsafe_fake_ymm_copy','address':hex(addr)};uc.emu_stop();return
   if loading:uc.reg_write(UC_X86_REG_YMM0,int.from_bytes(uc.mem_read(ptr,32),'little'))
   else:uc.mem_write(ptr,uc.reg_read(UC_X86_REG_YMM0).to_bytes(32,'little'))
   state.setdefault('fake_vector_copies',[]).append({'rip':hex(addr),'address':hex(ptr)});uc.reg_write(UC_X86_REG_RIP,addr+5);return
  if a.model_crt_initterm_e and state.get('active_crt_initializer') and addr==0x7b0000001000 and state.get('fake_cpu_query_mapped'):
   sp=uc.reg_read(UC_X86_REG_RSP)
   if not stack<=sp<=stack+0x200000-8:state['stop']={'kind':'unsafe_fake_cpu_query'};uc.emu_stop();return
   buffer=uc.reg_read(UC_X86_REG_RCX);length_ptr=uc.reg_read(UC_X86_REG_RDX);required=8*32
   if not stack<=length_ptr<=stack+0x200000-4:state['stop']={'kind':'unsafe_fake_cpu_query_length'};uc.emu_stop();return
   capacity=struct.unpack('<I',bytes(uc.mem_read(length_ptr,4)))[0];uc.mem_write(length_ptr,struct.pack('<I',required))
   if not buffer or capacity<required:result=0;error=122
   elif 0x790000000000<=buffer<=0x790000000000+state.get('fake_heap_used',0)-required or stack<=buffer<=stack+0x200000-required:
    for i in range(8):uc.mem_write(buffer+i*32,struct.pack('<QI4x16s',1<<i,0,bytes(16)))
    result=1;error=0
   else:state['stop']={'kind':'unsafe_fake_cpu_query_buffer','buffer':hex(buffer),'capacity':capacity};uc.emu_stop();return
   uc.mem_write(teb+0x68,struct.pack('<I',error));state.setdefault('fake_cpu_queries',[]).append({'buffer':hex(buffer),'capacity':capacity,'result':result,'synthetic_cores':8});uc.reg_write(UC_X86_REG_RAX,result);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
  if a.model_crt_initterm_e and state.get('active_crt_initializer') and addr in (0x7b0000001010,0x7b0000001020) and state.get('fake_cpu_query_mapped'):
   state['stop']={'kind':'dynamic_call_required','library':'kernel32.dll','symbol':'RtlCaptureContext' if addr==0x7b0000001010 else 'RtlCaptureStackBackTrace'};uc.emu_stop();return
  if a.model_crt_initterm_e and state.get('active_crt_initializer') and addr in (0x15daf617c,0x15daf6182,0x15daf6195,0x15daf619d):
   specs={0x15daf617c:(bytes.fromhex('c5fc10442438'),UC_X86_REG_YMM0,uc.reg_read(UC_X86_REG_RSP)+0x38,True),0x15daf6182:(bytes.fromhex('c5fc104c2458'),UC_X86_REG_YMM1,uc.reg_read(UC_X86_REG_RSP)+0x58,True),0x15daf6195:(bytes.fromhex('c5fc110508ce9b16'),UC_X86_REG_YMM0,0x1744b2fa5,False),0x15daf619d:(bytes.fromhex('c5fc110d20ce9b16'),UC_X86_REG_YMM1,0x1744b2fc5,False)};expected,reg,ptr,loading=specs[addr]
   if bytes(uc.mem_read(addr,len(expected)))!=expected or not (stack<=ptr<=stack+0x200000-32 if loading else 0x173534000<=ptr<=0x1792a6be1-32):state['stop']={'kind':'unsafe_fake_ymm_copy','address':hex(addr)};uc.emu_stop();return
   if loading:uc.reg_write(reg,int.from_bytes(uc.mem_read(ptr,32),'little'))
   else:uc.mem_write(ptr,uc.reg_read(reg).to_bytes(32,'little'))
   state.setdefault('fake_vector_copies',[]).append({'rip':hex(addr),'address':hex(ptr)});uc.reg_write(UC_X86_REG_RIP,addr+len(expected));return
  if a.model_crt_initterm_e and state.get('active_crt_initializer') and addr==0x16ee390ba:
   expected=bytes.fromhex('c5fc10442438');ptr=uc.reg_read(UC_X86_REG_RSP)+0x38
   if bytes(uc.mem_read(addr,6))!=expected or not stack<=ptr<=stack+0x200000-32:state['stop']={'kind':'unsafe_fake_ymm_copy','address':hex(addr)};uc.emu_stop();return
   uc.reg_write(UC_X86_REG_YMM0,int.from_bytes(uc.mem_read(ptr,32),'little'));state.setdefault('fake_vector_copies',[]).append({'rip':hex(addr),'address':hex(ptr)});uc.reg_write(UC_X86_REG_RIP,addr+6);return
  if a.model_crt_initterm_e and addr==0x7b0000001030 and state.get('fake_winmm_symbol'):
   sp=uc.reg_read(UC_X86_REG_RSP)
   if not stack<=sp<=stack+0x200000-8:state['stop']={'kind':'unsafe_fake_timegettime'};uc.emu_stop();return
   value=(state.get('fake_timegettime',100000)+1)&0xffffffff;state['fake_timegettime']=value;uc.reg_write(UC_X86_REG_RAX,value);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
  if a.model_crt_initterm_e and addr==exception_mem+0x7000 and state.get('fake_window_message_symbol'):
   sp=uc.reg_read(UC_X86_REG_RSP);ptr=uc.reg_read(UC_X86_REG_RCX)
   if not stack<=sp<=stack+0x200000-8 or not 0x172c84000<=ptr<0x173534000-128:state['stop']={'kind':'unsafe_fake_window_message'};uc.emu_stop();return
   state.setdefault('fake_constructor_api_calls',[]).append({'import':'user32.dll!RegisterWindowMessageW','name_pointer':hex(ptr),'result':0xc000});uc.reg_write(UC_X86_REG_RAX,0xc000);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
  if a.model_crt_initterm_e and addr==exception_mem+0x7010 and state.get('fake_path_remove_symbol'):
   sp=uc.reg_read(UC_X86_REG_RSP);ptr=uc.reg_read(UC_X86_REG_RCX)
   if not stack<=sp<=stack+0x200000-8 or not stack<=ptr<=stack+0x200000-1024:state['stop']={'kind':'unsafe_fake_path_remove'};uc.emu_stop();return
   raw=bytes(uc.mem_read(ptr,1024));end=next((i for i in range(0,len(raw)-1,2) if raw[i:i+2]==b'\0\0'),-1)
   if end<0:state['stop']={'kind':'unterminated_fake_path'};uc.emu_stop();return
   path=raw[:end].decode('utf-16le');cut=max(path.rfind('\\'),path.rfind('/'))
   if cut<0:result=0
   else:uc.mem_write(ptr,(path[:cut]+'\0').encode('utf-16le'));result=1
   state.setdefault('fake_constructor_api_calls',[]).append({'import':'shlwapi.dll!PathRemoveFileSpecW','result':result});uc.reg_write(UC_X86_REG_RAX,result);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
  if a.model_crt_initterm_e and addr==exception_mem+0x7020 and state.get('fake_file_operation_symbol'):
   ptr=uc.reg_read(UC_X86_REG_RCX);sp=uc.reg_read(UC_X86_REG_RSP)
   if not stack<=sp<=stack+0x200000-8 or not stack<=ptr<=stack+0x200000-64:state['stop']={'kind':'unsafe_fake_file_operation'};uc.emu_stop();return
   b=bytes(uc.mem_read(ptr,64));op=struct.unpack_from('<I',b,8)[0];src=struct.unpack_from('<Q',b,16)[0];flags=struct.unpack_from('<H',b,32)[0]
   if op!=3 or not stack<=src<=stack+0x200000-2048:state['stop']={'kind':'unsupported_fake_file_operation'};uc.emu_stop();return
   raw=bytes(uc.mem_read(src,2048));end=next((i for i in range(0,len(raw)-3,2) if raw[i:i+4]==b'\0\0\0\0'),-1)
   if end<0 or flags!=20 or raw[:end].decode('utf-16le').split('\0')!=['C:\\Temp\\Marathon\\*.*']:state['stop']={'kind':'unsupported_fake_file_operation'};uc.emu_stop();return
   uc.mem_write(ptr+36,struct.pack('<I',0));state.setdefault('fake_file_operations',[]).append({'operation':'delete','result':'empty synthetic directory','host_filesystem_access':False});uc.reg_write(UC_X86_REG_RAX,0);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
  if a.model_crt_initterm_e and addr==exception_mem+0x7030 and state.get('fake_known_folder_symbol'):
   guid=uc.reg_read(UC_X86_REG_RCX);sp=uc.reg_read(UC_X86_REG_RSP);flags=uc.reg_read(UC_X86_REG_RDX);token=uc.reg_read(UC_X86_REG_R8);out=uc.reg_read(UC_X86_REG_R9)
   worker=bool(state.get('dynamic_worker_experiment'))
   if not 0x172c84000<=guid<=0x173534000-16 or token!=0 or not (stack<=out<=stack+0x200000-8 or worker and child_stack<=out<=child_stack+0x200000-8) or not (stack<=sp<=stack+0x200000-8 or worker and child_stack<=sp<=child_stack+0x200000-8):state['stop']={'kind':'unsafe_fake_known_folder'};uc.emu_stop();return
   key=bytes(uc.mem_read(guid,16)).hex()
   if (key,flags) not in (('d09ad3fd8f23af46adb46c85480369c7',0x8000),('825dab62c1fdc34da9dd070d1d495d97',0),('b6635e90bfc14e49b29c65b732d3d21a',0)):state['stop']={'kind':'unsupported_fake_known_folder','guid':key,'flags':hex(flags)};uc.emu_stop();return
   buf=exception_mem+0x8000;folder='Documents' if key.startswith('d09a') else 'ProgramFiles' if key.startswith('b663') else 'ProgramData';uc.mem_write(buf,('C:\\Preservation\\'+folder+'\0').encode('utf-16le'));uc.mem_write(out,struct.pack('<Q',buf));state.setdefault('fake_known_folder_calls',[]).append({'guid':key,'path':'synthetic'});uc.reg_write(UC_X86_REG_RAX,0);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
  if a.model_crt_initterm_e and addr==exception_mem+0x7040 and state.get('fake_cotaskfree_symbol'):
   sp=uc.reg_read(UC_X86_REG_RSP);ptr=uc.reg_read(UC_X86_REG_RCX)
   if not (stack<=sp<=stack+0x200000-8 or state.get('dynamic_worker_experiment') and child_stack<=sp<=child_stack+0x200000-8) or ptr!=exception_mem+0x8000:state['stop']={'kind':'unsafe_fake_cotaskmemfree'};uc.emu_stop();return
   state['fake_known_folder_freed']=True;uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
  if a.model_crt_initterm_e and imports.get(addr,'').lower()=='kernel32.dll!interlockedpushentryslist':
   sp=uc.reg_read(UC_X86_REG_RSP);head=uc.reg_read(UC_X86_REG_RCX);entry=uc.reg_read(UC_X86_REG_RDX);heap=0x790000000000;used=state.get('fake_heap_used',0)
   initialized=hex(head) in state.get('fake_slist_heads',[]) or any(c.get('import','').lower()=='kernel32.dll!initializeslisthead' and c.get('arg')==hex(head) for c in state.get('fake_crt_basic_calls',[]))
   def valid_slist_ptr(ptr):return heap<=ptr<=heap+used-16 or base+0x33534000<=ptr<=base+0x392a6be1-16
   if not stack<=sp<=stack+0x200000-8 or head%16 or entry%16 or not valid_slist_ptr(head) or not valid_slist_ptr(entry) or not initialized:state['stop']={'kind':'unsupported_fake_slist_push','head':hex(head),'entry':hex(entry)};uc.emu_stop();return
   if any(head<point+0x40 and point<head+16 or entry<point+0x40 and point<entry+8 for point in watch_points):state['stop']={'kind':'watched_fake_slist_push','head':hex(head),'entry':hex(entry)};uc.emu_stop();return
   first,second=struct.unpack('<QQ',bytes(uc.mem_read(head,16)));previous=second&~15;depth=first&0xffff;sequence=first>>16
   if depth==0xffff or previous and not valid_slist_ptr(previous):state['stop']={'kind':'unsafe_fake_slist_state'};uc.emu_stop();return
   uc.mem_write(entry,struct.pack('<Q',previous));uc.mem_write(head,struct.pack('<QQ',(((sequence+1)&((1<<48)-1))<<16)|(depth+1),entry));state.setdefault('fake_slist_operations',[]).append({'operation':'push','head':hex(head),'entry':hex(entry),'previous':hex(previous),'single_thread_assumption':True});uc.reg_write(UC_X86_REG_RAX,previous);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
  if a.model_crt_initterm_e and ((addr==exception_mem+0x7050 and state.get('fake_system_heap_alloc_symbol')) or (imports.get(addr,'').lower()=='kernel32.dll!heapalloc' and state.get('synthetic_peb_modules'))):
   sp=uc.reg_read(UC_X86_REG_RSP);handle=uc.reg_read(UC_X86_REG_RCX);flags=uc.reg_read(UC_X86_REG_RDX);n=uc.reg_read(UC_X86_REG_R8);heap=0x790000000000
   if not stack<=sp<=stack+0x200000-8 or handle!=0x7d0000001000 or flags not in (0,8) or not 1<=n<=0x1000000:state['stop']={'kind':'unsupported_fake_system_heap_alloc'};uc.emu_stop();return
   if 'fake_heap_used' not in state:uc.mem_map(heap,0x1000000);state['fake_heap_used']=0
   off=(state['fake_heap_used']+15)&~15;end=off+n
   if end>0x1000000:state['stop']={'kind':'fake_heap_exhausted'};uc.emu_stop();return
   state['fake_heap_used']=end;result=heap+off;state.setdefault('fake_heap_allocations',{})[hex(result)]=n;state.setdefault('fake_system_heap_allocs',[]).append({'size':n,'flags':flags,'result':hex(result),'host_api_called':False});uc.reg_write(UC_X86_REG_RAX,result);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
  if imports.get(addr,'').lower()=='api-ms-win-crt-math-l1-1-0.dll!modff' and state.get('synthetic_second_d3d12_device'):
   import math
   sp=uc.reg_read(UC_X86_REG_RSP);out=uc.reg_read(UC_X86_REG_RDX);raw=uc.reg_read(UC_X86_REG_XMM0);value=struct.unpack('<f',struct.pack('<I',raw&0xffffffff))[0]
   if child_stack<=sp<=child_stack+0x200000-8 and child_stack<=out<=child_stack+0x200000-4 and state.get('synthetic_modff_qnan_enabled') and raw&0xffffffff==0xffc00000:
    uc.mem_write(out,struct.pack('<I',0xffc00000));state.setdefault('synthetic_modff_calls',[]).append({'input_bits':'0xffc00000','result_bits':'0xffc00000','integer_bits':'0xffc00000','assumption':'quiet NaN propagated to both outputs; native CRT behavior unverified','host_api_called':False});uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if child_stack<=sp<=child_stack+0x200000-8 and child_stack<=out<=child_stack+0x200000-4 and math.isfinite(value):
    frac,whole=math.modf(value);uc.mem_write(out,struct.pack('<f',whole));bits=struct.unpack('<I',struct.pack('<f',frac))[0];uc.reg_write(UC_X86_REG_XMM0,(raw&~0xffffffff)|bits);state.setdefault('synthetic_modff_calls',[]).append({'input':value,'fraction':frac,'integer':whole,'host_api_called':False});uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
  if imports.get(addr,'').lower()=='kernel32.dll!localfree' and state.get('synthetic_second_d3d12_device'):
   sp=uc.reg_read(UC_X86_REG_RSP)
   if uc.reg_read(UC_X86_REG_RCX)==0 and child_stack<=sp<=child_stack+0x200000-8:
    state.setdefault('synthetic_localfree_calls',[]).append({'handle':'0x0','result':'0x0','host_api_called':False});uc.reg_write(UC_X86_REG_RAX,0);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
  if imports.get(addr,'').lower()=='kernel32.dll!versetconditionmask' and state.get('synthetic_second_d3d12_device'):
   sp=uc.reg_read(UC_X86_REG_RSP);mask=uc.reg_read(UC_X86_REG_RCX);kind=uc.reg_read(UC_X86_REG_RDX);condition=uc.reg_read(UC_X86_REG_R8)
   if child_stack<=sp<=child_stack+0x200000-8 and kind in (1,2,4,8,16,32,64,128) and 1<=condition<=7:
    shift={1:0,2:3,4:6,8:9,16:12,32:15,64:18,128:21}[kind];result=mask|(condition<<shift);state.setdefault('synthetic_version_mask_calls',[]).append({'mask':hex(mask),'type':hex(kind),'condition':condition,'result':hex(result),'basis':'Wine VerSetConditionMask algorithm; synthetic, no host API','host_api_called':False});uc.reg_write(UC_X86_REG_RAX,result);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
  if addr in imports:
   if a.model_crt_initterm_e and imports[addr].lower()=='kernel32.dll!setthreadidealprocessor' and any(t['handle']==hex(uc.reg_read(UC_X86_REG_RCX)) for t in state.get('synthetic_suspended_threads',[])):
    sp=uc.reg_read(UC_X86_REG_RSP);handle=hex(uc.reg_read(UC_X86_REG_RCX));ideal=uc.reg_read(UC_X86_REG_RDX)
    if not stack<=sp<=stack+0x200000-8 or not 0<=ideal<8:state['stop']={'kind':'unsupported_synthetic_ideal_processor'};uc.emu_stop();return
    thread=next(t for t in state['synthetic_suspended_threads'] if t['handle']==handle);previous=thread.get('ideal_processor',0);thread['ideal_processor']=ideal;thread['ideal_processor_assumption']='previous ideal defaults to synthetic processor 0';uc.reg_write(UC_X86_REG_RAX,previous);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and imports[addr].lower()=='kernel32.dll!setthreadpriorityboost' and any(t['handle']==hex(uc.reg_read(UC_X86_REG_RCX)) for t in state.get('synthetic_suspended_threads',[])):
    sp=uc.reg_read(UC_X86_REG_RSP);handle=hex(uc.reg_read(UC_X86_REG_RCX));disable=uc.reg_read(UC_X86_REG_RDX)
    if not stack<=sp<=stack+0x200000-8 or disable not in (0,1):state['stop']={'kind':'unsupported_synthetic_thread_boost'};uc.emu_stop();return
    thread=next(t for t in state['synthetic_suspended_threads'] if t['handle']==handle);thread['priority_boost_disabled']=bool(disable);uc.reg_write(UC_X86_REG_RAX,1);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and imports[addr].lower()=='kernel32.dll!setthreadpriority' and any(t['handle']==hex(uc.reg_read(UC_X86_REG_RCX)) for t in state.get('synthetic_suspended_threads',[])):
    sp=uc.reg_read(UC_X86_REG_RSP);handle=hex(uc.reg_read(UC_X86_REG_RCX));priority=uc.reg_read(UC_X86_REG_RDX)&0xffffffff
    if not stack<=sp<=stack+0x200000-8 or priority not in (0xffffffff,0,1,2):state['stop']={'kind':'unsupported_synthetic_thread_priority'};uc.emu_stop();return
    thread=next(t for t in state['synthetic_suspended_threads'] if t['handle']==handle);thread['priority']=priority;uc.reg_write(UC_X86_REG_RAX,1);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and state.get('virtual_sku_config') and imports[addr].lower()=='kernel32.dll!createthread':
    sp=uc.reg_read(UC_X86_REG_RSP);security=uc.reg_read(UC_X86_REG_RCX);size=uc.reg_read(UC_X86_REG_RDX);entry=uc.reg_read(UC_X86_REG_R8);arg=uc.reg_read(UC_X86_REG_R9)
    if not stack<=sp<=stack+0x200000-0x38:state['stop']={'kind':'unsupported_synthetic_suspended_thread'};uc.emu_stop();return
    flags=struct.unpack('<I',uc.mem_read(sp+0x28,4))[0];tidptr=struct.unpack('<Q',uc.mem_read(sp+0x30,8))[0]
    if security or size>0x1000000 or entry not in (0x171b86650,0x170c151a0) or flags!=4 or not stack<=tidptr<=stack+0x200000-4:state['stop']={'kind':'unsupported_synthetic_suspended_thread','entry':hex(entry),'flags':hex(flags)};uc.emu_stop();return
    threads=state.setdefault('synthetic_suspended_threads',[]);handle=0x7d6000000000+16*len(threads);tid=100+len(threads);uc.mem_write(tidptr,struct.pack('<I',tid));threads.append({'handle':hex(handle),'id':tid,'entry':hex(entry),'argument':arg,'stack_size':size,'suspend_count':1,'assumption':'suspended thread not executed','host_api_called':False});uc.reg_write(UC_X86_REG_RAX,handle);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and state.get('in_fake_parent') and imports[addr].lower().endswith(('!_initterm_e','!_initterm')):
    start=uc.reg_read(UC_X86_REG_RCX);end=uc.reg_read(UC_X86_REG_RDX);sp=uc.reg_read(UC_X86_REG_RSP)
    if state.get('active_crt_initializer') or not base+0x32c84000<=start<=end<=base+0x33534000 or (end-start)%8 or end-start>0x40000 or not stack+0x30<=sp<=stack+0x200000-8:
     state['stop']={'kind':'unsafe_crt_initializer'};uc.emu_stop();return
    values=list(struct.unpack('<'+'Q'*((end-start)//8),bytes(uc.mem_read(start,end-start))));targets=[x for x in values if x]
    if any(not base+0x1000<=x<base+0x32c84000 for x in targets):state['stop']={'kind':'invalid_crt_callback'};uc.emu_stop();return
    retaddr=struct.unpack('<Q',uc.mem_read(sp,8))[0]
    pending={'mode':imports[addr].lower().split('!')[-1],'start':hex(start),'end':hex(end),'sp':sp,'return_address':retaddr,'remaining':targets,'called':[],'returns':[]};state['active_crt_initializer']=pending
    if not targets:uc.reg_write(UC_X86_REG_RAX,0);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,retaddr);state.setdefault('modeled_crt_initializers',[]).append(pending);del state['active_crt_initializer'];return
    target=targets.pop(0);pending['called'].append(hex(target));uc.mem_write(sp-0x30,struct.pack('<Q',exception_mem+0x3000));uc.reg_write(UC_X86_REG_RSP,sp-0x30);uc.reg_write(UC_X86_REG_RIP,target)
    if pending['mode']=='_initterm' and a.checkpoint_at_constructor==len(pending['called']):state['stop']={'kind':'constructor_checkpoint','number':len(pending['called']),'next':hex(target)};uc.emu_stop()
    return
   if a.model_crt_initterm_e and state.get('active_crt_initializer') and imports[addr].lower().endswith('!_set_app_type'):
    sp=uc.reg_read(UC_X86_REG_RSP);value=uc.reg_read(UC_X86_REG_RCX)
    if not stack<=sp<=stack+0x200000-8 or value not in (1,2):state['stop']={'kind':'unsafe_crt_app_type'};uc.emu_stop();return
    state.setdefault('fake_crt_app_type',[]).append(value);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and state.get('active_crt_initializer') and imports[addr].lower().endswith('!_set_fmode'):
    sp=uc.reg_read(UC_X86_REG_RSP);value=uc.reg_read(UC_X86_REG_RCX)
    if not stack<=sp<=stack+0x200000-8 or value not in (0x4000,0x8000):state['stop']={'kind':'unsafe_crt_fmode'};uc.emu_stop();return
    state.setdefault('fake_crt_fmode',[]).append(hex(value));uc.reg_write(UC_X86_REG_RAX,0);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and state.get('active_crt_initializer') and imports[addr].lower().endswith('!__p__commode'):
    sp=uc.reg_read(UC_X86_REG_RSP)
    if not stack<=sp<=stack+0x200000-8:state['stop']={'kind':'unsafe_crt_commode'};uc.emu_stop();return
    state['fake_crt_commode_pointer']=hex(exception_mem+0x4000);uc.reg_write(UC_X86_REG_RAX,exception_mem+0x4000);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and imports[addr].lower()=='kernel32.dll!initializeslisthead':
    sp=uc.reg_read(UC_X86_REG_RSP);ptr=uc.reg_read(UC_X86_REG_RCX)
    if not stack<=sp<=stack+0x200000-8 or ptr%16 or not (base+0x33534000<=ptr<=base+0x392a6be1-16 or 0x790000000000<=ptr<=0x790000000000+state.get('fake_heap_used',0)-16):state['stop']={'kind':'unsafe_fake_slist'};uc.emu_stop();return
    if any(ptr<point+0x40 and point<ptr+16 for point in watch_points):state['stop']={'kind':'watched_fake_slist','destination':hex(ptr)};uc.emu_stop();return
    uc.mem_write(ptr,bytes(16));state.setdefault('fake_slist_heads',[]).append(hex(ptr));state.setdefault('fake_crt_basic_calls',[]).append({'import':imports[addr],'arg':hex(ptr)});uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and (state.get('active_crt_initializer') or imports[addr].lower().endswith('!_crt_atexit')) and imports[addr].lower().split('!')[-1] in ('_crt_atexit','_configure_narrow_argv','_initialize_narrow_environment','_configthreadlocale','initializeslisthead','_set_new_mode'):
    sp=uc.reg_read(UC_X86_REG_RSP);arg=uc.reg_read(UC_X86_REG_RCX);name=imports[addr].lower().split('!')[-1]
    if not (stack<=sp<=stack+0x200000-8 or (state.get('synthetic_second_d3d12_device') and name=='_crt_atexit' and child_stack<=sp<=child_stack+0x200000-8)):state['stop']={'kind':'unsafe_crt_basic_stack'};uc.emu_stop();return
    if name=='_crt_atexit' and not base+0x1000<=arg<base+0x32c84000:state['stop']={'kind':'unsafe_crt_atexit'};uc.emu_stop();return
    if name=='_set_new_mode' and arg!=0:state['stop']={'kind':'unsupported_fake_new_mode'};uc.emu_stop();return
    if name=='_configure_narrow_argv' and arg!=1:state['stop']={'kind':'unsupported_fake_argv'};uc.emu_stop();return
    if name=='_configthreadlocale' and arg!=0:state['stop']={'kind':'unsupported_fake_locale'};uc.emu_stop();return
    if name=='initializeslisthead':
     if arg%16 or not base+0x33534000<=arg<base+0x392a6be1-16:state['stop']={'kind':'unsafe_fake_slist'};uc.emu_stop();return
     uc.mem_write(arg,bytes(16))
    state.setdefault('fake_crt_basic_calls',[]).append({'import':imports[addr],'arg':hex(arg)})
    if name in ('_crt_atexit','_configure_narrow_argv','_initialize_narrow_environment','_set_new_mode'):uc.reg_write(UC_X86_REG_RAX,0)
    if name=='_configthreadlocale':uc.reg_write(UC_X86_REG_RAX,2)
    uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and state.get('active_crt_initializer') and imports[addr].lower()=='kernel32.dll!setunhandledexceptionfilter':
    sp=uc.reg_read(UC_X86_REG_RSP);arg=uc.reg_read(UC_X86_REG_RCX)
    if not stack<=sp<=stack+0x200000-8 or not base+0x1000<=arg<base+0x32c84000:state['stop']={'kind':'unsafe_fake_exception_filter'};uc.emu_stop();return
    state.setdefault('fake_unhandled_filters',[]).append(hex(arg));uc.reg_write(UC_X86_REG_RAX,0);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and imports[addr].lower() in ('kernel32.dll!getcurrentprocess','kernel32.dll!flushinstructioncache','api-ms-win-crt-convert-l1-1-0.dll!atoi'):
    import re
    sp=uc.reg_read(UC_X86_REG_RSP);name=imports[addr].lower();arg=uc.reg_read(UC_X86_REG_RCX)
    if not (stack<=sp<=stack+0x200000-8 or state.get('dynamic_worker_experiment') and child_stack<=sp<=child_stack+0x200000-8):state['stop']={'kind':'unsafe_constructor_api_stack'};uc.emu_stop();return
    detail={'import':imports[addr],'arg':hex(arg)}
    if name.endswith('getcurrentprocess'):result=0xffffffffffffffff
    elif name.endswith('flushinstructioncache'):
     if arg!=0xffffffffffffffff:state['stop']={'kind':'unsafe_constructor_cache'};uc.emu_stop();return
     detail.update(address=hex(uc.reg_read(UC_X86_REG_RDX)),length=uc.reg_read(UC_X86_REG_R8));result=1
    else:
     if not (base+0x32c84000<=arg<base+0x392a6be1-128 or stack<=arg<=stack+0x200000-128):state['stop']={'kind':'unsafe_constructor_atoi'};uc.emu_stop();return
     raw=bytes(uc.mem_read(arg,128));end=raw.find(b'\0')
     if end<0:state['stop']={'kind':'unterminated_constructor_atoi'};uc.emu_stop();return
     value=raw[:end];match=re.match(rb'^\s*[+-]?[0-9]+',value);result=int(match.group()) if match else 0
     if not -0x80000000<=result<=0x7fffffff:state['stop']={'kind':'overflow_constructor_atoi'};uc.emu_stop();return
     result &= 0xffffffff;detail['input']=value.decode('ascii','backslashreplace');detail['result']=result
    state.setdefault('fake_constructor_api_calls',[]).append(detail);uc.reg_write(UC_X86_REG_RAX,result);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and state.get('virtual_sku_config') and imports[addr].lower()=='api-ms-win-crt-string-l1-1-0.dll!strncmp':
    sp=uc.reg_read(UC_X86_REG_RSP);left=uc.reg_read(UC_X86_REG_RCX);right=uc.reg_read(UC_X86_REG_RDX);n=uc.reg_read(UC_X86_REG_R8)
    def allowed(v):return base+0x32c84000<=v<=base+0x392a6be1-n or stack<=v<=stack+0x200000-n or any(lo<=v and v+n<=hi for lo,hi in state.get('fake_virtual_commits',[]))
    if not stack<=sp<=stack+0x200000-8 or n>4096 or not allowed(left) or not allowed(right):state['stop']={'kind':'unsupported_virtual_sku_strncmp'};uc.emu_stop();return
    x=bytes(uc.mem_read(left,n));y=bytes(uc.mem_read(right,n));result=0
    for l,r in zip(x,y):
     if l!=r:result=l-r;break
     if not l:break
    uc.reg_write(UC_X86_REG_RAX,result&0xffffffff);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and state.get('virtual_sku_config') and imports[addr].lower()=='api-ms-win-crt-string-l1-1-0.dll!strlen':
    sp=uc.reg_read(UC_X86_REG_RSP);ptr=uc.reg_read(UC_X86_REG_RCX);limit=4096
    if not stack<=sp<=stack+0x200000-8 or not (base+0x32c84000<=ptr<=base+0x392a6be1-limit or stack<=ptr<=stack+0x200000-limit):state['stop']={'kind':'unsupported_virtual_sku_strlen','pointer':hex(ptr)};uc.emu_stop();return
    raw=bytes(uc.mem_read(ptr,limit));length=raw.find(b'\0')
    if length<0:state['stop']={'kind':'unterminated_virtual_sku_strlen'};uc.emu_stop();return
    uc.reg_write(UC_X86_REG_RAX,length);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and imports[addr].lower()=='api-ms-win-crt-string-l1-1-0.dll!strnlen':
    sp=uc.reg_read(UC_X86_REG_RSP);ptr=uc.reg_read(UC_X86_REG_RCX);n=uc.reg_read(UC_X86_REG_RDX)
    in_module=any(int(m['base'],16)<=ptr and ptr+n<=int(m['base'],16)+m['size'] for m in state.get('synthetic_peb_modules',[]))
    committed=any(lo<=ptr and ptr+n<=hi for lo,hi in state.get('fake_virtual_commits',[]))
    if not (stack<=sp<=stack+0x200000-8 or state.get('dynamic_worker_experiment') and child_stack<=sp<=child_stack+0x200000-8) or n>0x100000 or not (base+0x32c84000<=ptr<=base+0x392a6be1-n or stack<=ptr<=stack+0x200000-n or state.get('dynamic_worker_experiment') and child_stack<=ptr<=child_stack+0x200000-n or tls_block<=ptr<=tls_block+0x100000-n or in_module or committed):state['stop']={'kind':'unsafe_constructor_strnlen'};uc.emu_stop();return
    raw=bytes(uc.mem_read(ptr,n));end=raw.find(b'\0');result=n if end<0 else end;state.setdefault('fake_constructor_api_calls',[]).append({'import':imports[addr],'arg':hex(ptr),'limit':n,'result':result});uc.reg_write(UC_X86_REG_RAX,result);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and imports[addr].lower()=='api-ms-win-crt-string-l1-1-0.dll!strncpy_s':
    sp=uc.reg_read(UC_X86_REG_RSP);dst=uc.reg_read(UC_X86_REG_RCX);size=uc.reg_read(UC_X86_REG_RDX);src=uc.reg_read(UC_X86_REG_R8);limit=uc.reg_read(UC_X86_REG_R9)
    in_module=any(int(m['base'],16)<=src and src+size<=int(m['base'],16)+m['size'] for m in state.get('synthetic_peb_modules',[]))
    committed=any(lo<=dst and dst+size<=hi for lo,hi in state.get('fake_virtual_commits',[]))
    src_committed=any(lo<=src and src+size<=hi for lo,hi in state.get('fake_virtual_commits',[]))
    if not (stack<=sp<=stack+0x200000-8 or state.get('dynamic_worker_experiment') and child_stack<=sp<=child_stack+0x200000-8) or not 1<=size<=4096 or (limit!=0xffffffffffffffff and limit>=size) or not (base+0x33534000<=dst<=base+0x392a6be1-size or stack<=dst<=stack+0x200000-size or state.get('dynamic_worker_experiment') and child_stack<=dst<=child_stack+0x200000-size or tls_block<=dst<=tls_block+0x100000-size or committed) or not (base+0x32c84000<=src<=base+0x392a6be1-size or stack<=src<=stack+0x200000-size or state.get('dynamic_worker_experiment') and child_stack<=src<=child_stack+0x200000-size or tls_block<=src<=tls_block+0x100000-size or in_module or src_committed):state['stop']={'kind':'unsafe_constructor_strncpy'};uc.emu_stop();return
    if committed:
     for page in range(dst&~0xfff,(dst+size+4095)&~0xfff,4096):
      if page not in pages and not invalid(uc,UC_MEM_WRITE_UNMAPPED,page,1,0,None):uc.emu_stop();return
    if any(dst < point+0x40 and point < dst+size for point in watch_points):state['stop']={'kind':'watched_fake_strncpy','destination':hex(dst),'size':size};uc.emu_stop();return
    raw=bytes(uc.mem_read(src,size));end=raw.find(b'\0');effective=size-1 if limit==0xffffffffffffffff else limit;truncated=limit==0xffffffffffffffff and (end<0 or end>effective);copied=raw[:effective] if end<0 else raw[:min(end,effective)];uc.mem_write(dst,copied+b'\0');result=80 if truncated else 0
    state.setdefault('fake_constructor_api_calls',[]).append({'import':imports[addr],'destination':hex(dst),'source':hex(src),'size':size,'result':result});uc.reg_write(UC_X86_REG_RAX,result);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and state.get('active_crt_initializer') and imports[addr].lower()=='vcruntime140.dll!strstr':
    sp=uc.reg_read(UC_X86_REG_RSP);ptr=uc.reg_read(UC_X86_REG_RCX);needle=uc.reg_read(UC_X86_REG_RDX)
    if not stack<=sp<=stack+0x200000-8 or any(not (base+0x32c84000<=v<=base+0x392a6be1-4096 or stack<=v<=stack+0x200000-4096) for v in (ptr,needle)):state['stop']={'kind':'unsafe_constructor_strstr'};uc.emu_stop();return
    values=[]
    for v in (ptr,needle):
     raw=bytes(uc.mem_read(v,4096));end=raw.find(b'\0')
     if end<0:state['stop']={'kind':'unterminated_constructor_strstr'};uc.emu_stop();return
     values.append(raw[:end])
    found=values[0].find(values[1]);result=0 if found<0 else ptr+found;state.setdefault('fake_constructor_api_calls',[]).append({'import':imports[addr],'haystack':hex(ptr),'needle':hex(needle),'result':hex(result)});uc.reg_write(UC_X86_REG_RAX,result);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and state.get('active_crt_initializer') and imports[addr].lower()=='api-ms-win-crt-stdio-l1-1-0.dll!__stdio_common_vsnprintf_s':
    sp=uc.reg_read(UC_X86_REG_RSP);opts=uc.reg_read(UC_X86_REG_RCX);dst=uc.reg_read(UC_X86_REG_RDX);size=uc.reg_read(UC_X86_REG_R8);limit=uc.reg_read(UC_X86_REG_R9)
    if opts not in (0,0x24) or limit!=0xffffffffffffffff or not 1<=size<=4096 or not stack<=sp<=stack+0x200000-0x40 or not (0x173534000<=dst<=0x1792a6be1-size or stack<=dst<=stack+0x200000-size or tls_block<=dst<=tls_block+0x100000-size):state['stop']={'kind':'unsafe_fake_format'};uc.emu_stop();return
    fmt,locale,va=struct.unpack('<QQQ',bytes(uc.mem_read(sp+0x28,24)))
    if locale or not stack<=va<=stack+0x200000-64 or not 0x172c84000<=fmt<=0x173534000-4096:state['stop']={'kind':'unsupported_fake_format_args'};uc.emu_stop();return
    args=struct.unpack('<8Q',bytes(uc.mem_read(va,64)));values=[]
    for v in (fmt,):
     if not 0x172c84000<=v<=0x173534000-4096:state['stop']={'kind':'unsupported_fake_format_pointer'};uc.emu_stop();return
     raw=bytes(uc.mem_read(v,4096));end=raw.find(b'\0')
     if end<0:state['stop']={'kind':'unterminated_fake_format'};uc.emu_stop();return
     values.append(raw[:end])
    if values[0] in (b'%s%s',b' %s',b'%s_%s@%s',b'%s@%s@%s'):
     for v in args[:2 if values[0]==b'%s%s' else 3 if values[0] in (b'%s_%s@%s',b'%s@%s@%s') else 1]:
      if not (0x172c84000<=v<=0x1792a6be1-4096 or stack<=v<=stack+0x200000-4096 or tls_block<=v<=tls_block+0x100000-4096):state['stop']={'kind':'unsupported_fake_format_pointer'};uc.emu_stop();return
      raw=bytes(uc.mem_read(v,4096));end=raw.find(b'\0')
      if end<0:state['stop']={'kind':'unterminated_fake_format'};uc.emu_stop();return
      values.append(raw[:end])
     out=values[1]+values[2] if values[0]==b'%s%s' else values[1]+b'_'+values[2]+b'@'+values[3] if values[0]==b'%s_%s@%s' else values[1]+b'@'+values[2]+b'@'+values[3] if values[0]==b'%s@%s@%s' else b' '+values[1]
    elif values[0]==b'%02X:%02X:%02X:%02X:%02X:%02X:%02X%02X':out=(values[0].decode()%tuple(z&0xffffffff for z in args)).encode()
    elif values[0]==b'%07d':
     value=args[0]&0xffffffff;value=value if value<0x80000000 else value-0x100000000;out=f'{value:07d}'.encode()
    elif values[0]==b'+%d':
     value=args[0]&0xffffffff;value=value if value<0x80000000 else value-0x100000000;out=('+'+str(value)).encode()
    elif b'%' not in values[0]:out=values[0]
    else:state['stop']={'kind':'unsupported_fake_format_value','format':values[0].decode('ascii','backslashreplace')};uc.emu_stop();return
    if len(out)>=size:state['stop']={'kind':'unsupported_fake_format_length'};uc.emu_stop();return
    uc.mem_write(dst,out+b'\0');state.setdefault('fake_constructor_api_calls',[]).append({'import':imports[addr],'format':values[0].decode('ascii'),'result':len(out)});uc.reg_write(UC_X86_REG_RAX,len(out));uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and state.get('active_crt_initializer') and imports[addr].lower()=='api-ms-win-crt-string-l1-1-0.dll!strncmp':
    sp=uc.reg_read(UC_X86_REG_RSP);left=uc.reg_read(UC_X86_REG_RCX);right=uc.reg_read(UC_X86_REG_RDX);n=uc.reg_read(UC_X86_REG_R8)
    if not stack<=sp<=stack+0x200000-8 or n>4096 or any(not (0x172c84000<=v<=0x1792a6be1-n or stack<=v<=stack+0x200000-n) for v in (left,right)):state['stop']={'kind':'unsafe_fake_strncmp'};uc.emu_stop();return
    vals=[]
    for v in (left,right):
     vals.append(bytes(uc.mem_read(v,n)))
    result=0
    for x,y in zip(*vals):
     if x!=y:result=x-y;break
     if not x:break
    state.setdefault('fake_constructor_api_calls',[]).append({'import':imports[addr],'length':n,'result':result});uc.reg_write(UC_X86_REG_RAX,result&0xffffffff);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and imports[addr].lower()=='api-ms-win-crt-time-l1-1-0.dll!_time64':
    sp=uc.reg_read(UC_X86_REG_RSP);ptr=uc.reg_read(UC_X86_REG_RCX)
    if not stack<=sp<=stack+0x200000-8 or ptr and not stack<=ptr<=stack+0x200000-8:state['stop']={'kind':'unsafe_fake_time64'};uc.emu_stop();return
    if ptr:uc.mem_write(ptr,struct.pack('<q',1600000000))
    state.setdefault('fake_constructor_api_calls',[]).append({'import':imports[addr],'result':1600000000});uc.reg_write(UC_X86_REG_RAX,1600000000);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and state.get('active_crt_initializer') and imports[addr].lower()=='api-ms-win-crt-time-l1-1-0.dll!_ctime64':
    sp=uc.reg_read(UC_X86_REG_RSP);ptr=uc.reg_read(UC_X86_REG_RCX)
    if not stack<=sp<=stack+0x200000-8 or not stack<=ptr<=stack+0x200000-8 or struct.unpack('<q',bytes(uc.mem_read(ptr,8)))[0]!=1600000000:state['stop']={'kind':'unsupported_fake_ctime64'};uc.emu_stop();return
    buf=exception_mem+0x5000;uc.mem_write(buf,b'Sun Sep 13 12:26:40 2020\n\0');state.setdefault('fake_constructor_api_calls',[]).append({'import':imports[addr],'fixed_utc':True});uc.reg_write(UC_X86_REG_RAX,buf);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and state.get('active_crt_initializer') and imports[addr].lower()=='api-ms-win-crt-time-l1-1-0.dll!_gmtime64':
    sp=uc.reg_read(UC_X86_REG_RSP);ptr=uc.reg_read(UC_X86_REG_RCX)
    if not stack<=sp<=stack+0x200000-8 or not stack<=ptr<=stack+0x200000-8 or struct.unpack('<q',bytes(uc.mem_read(ptr,8)))[0]!=1600000000:state['stop']={'kind':'unsupported_fake_gmtime64'};uc.emu_stop();return
    buf=exception_mem+0x5100;uc.mem_write(buf,struct.pack('<9i',40,26,12,13,8,120,0,256,0));state.setdefault('fake_constructor_api_calls',[]).append({'import':imports[addr],'fixed_utc':True});uc.reg_write(UC_X86_REG_RAX,buf);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and imports[addr].lower() in ('kernel32.dll!queryperformancefrequency','kernel32.dll!queryperformancecounter'):
    sp=uc.reg_read(UC_X86_REG_RSP);ptr=uc.reg_read(UC_X86_REG_RCX)
    if not (stack<=sp<=stack+0x200000-8 or state.get('dynamic_worker_experiment') and child_stack<=sp<=child_stack+0x200000-8) or not (stack<=ptr<=stack+0x200000-8 or state.get('dynamic_worker_experiment') and child_stack<=ptr<=child_stack+0x200000-8 or base+0x33534000<=ptr<=base+0x392a6be1-8):state['stop']={'kind':'unsafe_fake_perf_counter'};uc.emu_stop();return
    if any(ptr<point+0x40 and point<ptr+8 for point in watch_points):state['stop']={'kind':'watched_fake_perf_counter','address':hex(ptr)};uc.emu_stop();return
    value=10000000 if imports[addr].lower().endswith('frequency') else 12345678;uc.mem_write(ptr,struct.pack('<Q',value));state.setdefault('fake_constructor_api_calls',[]).append({'import':imports[addr],'value':value,'fixed':True});uc.reg_write(UC_X86_REG_RAX,1);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and imports[addr].lower() in ('kernel32.dll!createeventw','kernel32.dll!createeventa'):
    sp=uc.reg_read(UC_X86_REG_RSP);security=uc.reg_read(UC_X86_REG_RCX);manual=uc.reg_read(UC_X86_REG_RDX);initial=uc.reg_read(UC_X86_REG_R8);name=uc.reg_read(UC_X86_REG_R9);handles=state.setdefault('fake_events',{})
    if not stack<=sp<=stack+0x200000-8 or security or name or manual not in (0,1) or initial not in (0,1) or len(handles)>=1024:state['stop']={'kind':'unsupported_fake_event'};uc.emu_stop();return
    result=0x7c0000000000+len(handles)*16;handles[hex(result)]={'manual':manual,'signaled':initial};state.setdefault('fake_constructor_api_calls',[]).append({'import':imports[addr],'handle':hex(result),'manual':manual,'signaled':initial,'synchronization':'synthetic single-threaded'});uc.reg_write(UC_X86_REG_RAX,result);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and imports[addr].lower() in ('kernel32.dll!createsemaphorew','kernel32.dll!createsemaphorea'):
    sp=uc.reg_read(UC_X86_REG_RSP);security=uc.reg_read(UC_X86_REG_RCX);initial=uc.reg_read(UC_X86_REG_RDX);maximum=uc.reg_read(UC_X86_REG_R8);name=uc.reg_read(UC_X86_REG_R9)
    handles=state.setdefault('fake_semaphores',{})
    if not stack<=sp<=stack+0x200000-8 or security or name or not 0<=initial<=maximum<=0x7fffffff or maximum==0 or len(handles)>=1024:state['stop']={'kind':'unsupported_fake_semaphore'};uc.emu_stop();return
    result=0x7b0000000000+len(handles)*16;handles[hex(result)]={'count':initial,'maximum':maximum};state.setdefault('fake_constructor_api_calls',[]).append({'import':imports[addr],'handle':hex(result),'initial':initial,'maximum':maximum,'synchronization':'synthetic single-threaded'});uc.reg_write(UC_X86_REG_RAX,result);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and imports[addr].lower()=='kernel32.dll!virtualalloc':
    sp=uc.reg_read(UC_X86_REG_RSP);requested=uc.reg_read(UC_X86_REG_RCX);size=uc.reg_read(UC_X86_REG_RDX);kind=uc.reg_read(UC_X86_REG_R8);prot=uc.reg_read(UC_X86_REG_R9)
    reserves=state.setdefault('fake_virtual_reservations',[])
    if not stack<=sp<=stack+0x200000-8 or not 1<=size<=0x100000000:state['stop']={'kind':'unsupported_fake_virtualalloc'};uc.emu_stop();return
    if requested==0 and kind==0x2000 and prot in (1,4) and len(reserves)<16:
     result=0x7a0000000000+len(reserves)*0x100000000;reserves.append({'address':hex(result),'size':size,'protection':prot})
    elif kind==0x1000 and prot==4 and size<=0x80000000:
     start=requested&~0xfff;end=(requested+size+4095)&~4095;commits=state.setdefault('fake_virtual_commits',[])
     if not any(int(res['address'],16)<=start<end<=int(res['address'],16)+res['size'] for res in reserves) or sum(y-x for x,y in commits)+end-start>0x200000000:state['stop']={'kind':'unsafe_fake_virtual_commit'};uc.emu_stop();return
     commits.append((start,end));result=requested
    else:state['stop']={'kind':'unsupported_fake_virtualalloc','address':hex(requested),'size':size,'allocation_type':hex(kind),'protection':hex(prot)};uc.emu_stop();return
    state.setdefault('fake_constructor_api_calls',[]).append({'import':imports[addr],'size':size,'result':hex(result),'allocation_type':hex(kind)});uc.reg_write(UC_X86_REG_RAX,result);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and state.get('virtual_sku_config') and imports[addr].lower()=='vcruntime140.dll!strrchr':
    sp=uc.reg_read(UC_X86_REG_RSP);ptr=uc.reg_read(UC_X86_REG_RCX);target=uc.reg_read(UC_X86_REG_RDX)&0xff
    if not stack<=sp<=stack+0x200000-8 or not (base+0x32c84000<=ptr<=base+0x392a6be1-4096 or stack<=ptr<=stack+0x200000-4096):state['stop']={'kind':'unsafe_fake_strrchr'};uc.emu_stop();return
    raw=bytes(uc.mem_read(ptr,4096));end=raw.find(b'\0')
    if end<0:state['stop']={'kind':'unterminated_fake_strrchr'};uc.emu_stop();return
    found=raw[:end+1].rfind(bytes([target]));uc.reg_write(UC_X86_REG_RAX,ptr+found if found>=0 else 0);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and imports[addr].lower()=='vcruntime140.dll!strchr':
    sp=uc.reg_read(UC_X86_REG_RSP);ptr=uc.reg_read(UC_X86_REG_RCX);target=uc.reg_read(UC_X86_REG_RDX)&0xff
    module=next((m for m in state.get('synthetic_peb_modules',[]) if int(m['base'],16)<=ptr<int(m['base'],16)+m['size']),None)
    if not stack<=sp<=stack+0x200000-8 or not (module or stack<=ptr<stack+0x200000):state['stop']={'kind':'unsafe_fake_strchr'};uc.emu_stop();return
    limit=min(4096,(int(module['base'],16)+module['size'] if module else stack+0x200000)-ptr);raw=bytes(uc.mem_read(ptr,limit));end=raw.find(b'\0')
    if end<0:state['stop']={'kind':'unterminated_fake_strchr'};uc.emu_stop();return
    found=raw[:end+1].find(bytes([target]));result=ptr+found if found>=0 else 0;state.setdefault('fake_constructor_api_calls',[]).append({'import':imports[addr],'target':target,'result':hex(result)});uc.reg_write(UC_X86_REG_RAX,result);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and imports[addr].lower()=='api-ms-win-crt-string-l1-1-0.dll!wcsncpy_s':
    sp=uc.reg_read(UC_X86_REG_RSP);dst=uc.reg_read(UC_X86_REG_RCX);capacity=uc.reg_read(UC_X86_REG_RDX);src=uc.reg_read(UC_X86_REG_R8);count=uc.reg_read(UC_X86_REG_R9)
    if not stack<=sp<=stack+0x200000-8 or not 1<=capacity<=1024 or count!=0xffffffffffffffff or not stack<=dst<=stack+0x200000-2*capacity or not base+0x32c84000<=src<=base+0x33534000-2*capacity:state['stop']={'kind':'unsupported_fake_wcsncpy_s'};uc.emu_stop();return
    units=struct.unpack('<'+'H'*capacity,bytes(uc.mem_read(src,2*capacity)));end=next((i for i,v in enumerate(units) if v==0),None);length=min(end if end is not None else capacity,capacity-1);result=0 if end is not None and end<capacity else 80
    uc.mem_write(dst,struct.pack('<'+'H'*(length+1),*units[:length],0));state.setdefault('fake_constructor_api_calls',[]).append({'import':imports[addr],'capacity':capacity,'length':length,'result':result});uc.reg_write(UC_X86_REG_RAX,result);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and imports[addr].lower()=='api-ms-win-crt-string-l1-1-0.dll!_wcsicmp':
    sp=uc.reg_read(UC_X86_REG_RSP);left=uc.reg_read(UC_X86_REG_RCX);right=uc.reg_read(UC_X86_REG_RDX);heap=0x790000000000;used=state.get('fake_heap_used',0)
    def allowed(v):return stack<=v<=stack+0x200000-2 or teb<=v<=teb+0x2000-2 or heap<=v<=heap+used-2 or base+0x32c84000<=v<=base+0x392a6be1-2
    if not stack<=sp<=stack+0x200000-8:state['stop']={'kind':'unsafe_fake_wcsicmp'};uc.emu_stop();return
    result=None
    for i in range(1024):
     if not allowed(left+2*i) or not allowed(right+2*i):state['stop']={'kind':'unsafe_fake_wcsicmp'};uc.emu_stop();return
     x=struct.unpack('<H',bytes(uc.mem_read(left+2*i,2)))[0];y=struct.unpack('<H',bytes(uc.mem_read(right+2*i,2)))[0]
     if x>127 or y>127:state['stop']={'kind':'unsupported_fake_wcsicmp_unicode'};uc.emu_stop();return
     x=ord(chr(x).lower());y=ord(chr(y).lower())
     if x!=y or not x:result=x-y;break
    if result is None:state['stop']={'kind':'unterminated_fake_wcsicmp'};uc.emu_stop();return
    state.setdefault('fake_constructor_api_calls',[]).append({'import':imports[addr],'result':result,'ascii_only':True});uc.reg_write(UC_X86_REG_RAX,result&0xffffffff);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and imports[addr].lower()=='api-ms-win-crt-string-l1-1-0.dll!_wcsnicmp':
    sp=uc.reg_read(UC_X86_REG_RSP);left=uc.reg_read(UC_X86_REG_RCX);right=uc.reg_read(UC_X86_REG_RDX);n=uc.reg_read(UC_X86_REG_R8)
    if not stack<=sp<=stack+0x200000-8 or n>1024 or any(not (0x172c84000<=v<=0x1792a6be1-2*n or stack<=v<=stack+0x200000-2*n or teb<=v<=teb+0x2000-2*n or state.get('synthetic_loaded_module_images') and 0x7e1100000000<=v<=0x7e1100010000-2*n) for v in (left,right)):state['stop']={'kind':'unsafe_fake_wcsnicmp'};uc.emu_stop();return
    vals=[struct.unpack('<'+'H'*n,bytes(uc.mem_read(v,2*n))) for v in (left,right)];result=0
    for x,y in zip(*vals):
     if x>127 or y>127:state['stop']={'kind':'unsupported_fake_wcsnicmp_unicode'};uc.emu_stop();return
     x=ord(chr(x).lower());y=ord(chr(y).lower())
     if x!=y:result=x-y;break
     if not x:break
    state.setdefault('fake_constructor_api_calls',[]).append({'import':imports[addr],'length':n,'result':result});uc.reg_write(UC_X86_REG_RAX,result&0xffffffff);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and imports[addr].lower()=='kernel32.dll!getdynamictimezoneinformation':
    sp=uc.reg_read(UC_X86_REG_RSP);ptr=uc.reg_read(UC_X86_REG_RCX)
    if not stack<=sp<=stack+0x200000-8 or not stack<=ptr<=stack+0x200000-432:state['stop']={'kind':'unsafe_fake_timezone'};uc.emu_stop();return
    uc.mem_write(ptr,bytes(432));state['fake_timezone']='UTC, no daylight saving';uc.reg_write(UC_X86_REG_RAX,0);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and imports[addr].lower()=='kernel32.dll!getcurrentthread':
    sp=uc.reg_read(UC_X86_REG_RSP)
    if not stack<=sp<=stack+0x200000-8:state['stop']={'kind':'unsafe_fake_current_thread'};uc.emu_stop();return
    state.setdefault('fake_constructor_api_calls',[]).append({'import':imports[addr],'result':'synthetic pseudo-handle'});uc.reg_write(UC_X86_REG_RAX,0xfffffffffffffffe);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and imports[addr].lower()=='kernel32.dll!sleep':
    sp=uc.reg_read(UC_X86_REG_RSP);duration=uc.reg_read(UC_X86_REG_RCX)
    if state.get('dynamic_worker_experiment') and child_stack<=sp<=child_stack+0x200000-8 and 0<duration<=10000:state['stop']={'kind':'synthetic_worker_sleep','milliseconds':duration,'host_sleep':False};uc.emu_stop();return
    if not stack<=sp<=stack+0x200000-8 or duration>10000:state['stop']={'kind':'unsafe_fake_sleep'};uc.emu_stop();return
    state.setdefault('fake_sleeps',[]).append({'milliseconds':duration,'host_sleep':False});state['fake_timegettime']=state.get('fake_timegettime',100000)+duration;uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and imports[addr].lower()=='kernel32.dll!setdlldirectoryw':
    sp=uc.reg_read(UC_X86_REG_RSP);ptr=uc.reg_read(UC_X86_REG_RCX)
    if not stack<=sp<=stack+0x200000-8 or not stack<=ptr<=stack+0x200000-1024:state['stop']={'kind':'unsafe_fake_dll_directory'};uc.emu_stop();return
    raw=bytes(uc.mem_read(ptr,1024));end=next((i for i in range(0,len(raw)-1,2) if raw[i:i+2]==b'\0\0'),-1)
    if end<0:state['stop']={'kind':'unterminated_fake_dll_directory'};uc.emu_stop();return
    state['fake_dll_directory_hash']=hashlib.sha256(raw[:end]).hexdigest();uc.reg_write(UC_X86_REG_RAX,1);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and state.get('virtual_sku_config') and imports[addr].lower()=='api-ms-win-crt-stdio-l1-1-0.dll!fclose':
    sp=uc.reg_read(UC_X86_REG_RSP);file=state['virtual_sku_config']
    if not stack<=sp<=stack+0x200000-8 or hex(uc.reg_read(UC_X86_REG_RCX))!=file.get('handle'):state['stop']={'kind':'unsupported_virtual_sku_close'};uc.emu_stop();return
    file['closed']=True;file.pop('handle');uc.reg_write(UC_X86_REG_RAX,0);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and state.get('virtual_sku_config') and imports[addr].lower()=='api-ms-win-crt-stdio-l1-1-0.dll!fread':
    sp=uc.reg_read(UC_X86_REG_RSP);dst=uc.reg_read(UC_X86_REG_RCX);size=uc.reg_read(UC_X86_REG_RDX);count=uc.reg_read(UC_X86_REG_R8);file=state['virtual_sku_config'];n=size*count
    committed=any(lo<=dst and dst+n<=hi for lo,hi in state.get('fake_virtual_commits',[]))
    if not stack<=sp<=stack+0x200000-8 or hex(uc.reg_read(UC_X86_REG_R9))!=file.get('handle') or n>0x10000 or not (stack<=dst<=stack+0x200000-n or committed):state['stop']={'kind':'unsupported_virtual_sku_read','destination':hex(dst),'size':size,'count':count};uc.emu_stop();return
    if committed:
     for page in range(dst&~0xfff,(dst+n+4095)&~0xfff,4096):
      if page not in pages and not invalid(uc,UC_MEM_WRITE_UNMAPPED,page,1,0,None):uc.emu_stop();return
    data=bytes.fromhex(file['data']);raw=data[file['position']:file['position']+n];uc.mem_write(dst,raw);file['position']+=len(raw);state.setdefault('virtual_sku_reads',[]).append({'offset':file['position']-len(raw),'bytes':len(raw),'host_api_called':False});uc.reg_write(UC_X86_REG_RAX,len(raw)//size if size else 0);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and state.get('virtual_sku_config') and imports[addr].lower()=='api-ms-win-crt-stdio-l1-1-0.dll!_fseeki64':
    sp=uc.reg_read(UC_X86_REG_RSP);file=state['virtual_sku_config'];offset=uc.reg_read(UC_X86_REG_RDX);origin=uc.reg_read(UC_X86_REG_R8)
    if offset>=1<<63:offset-=1<<64
    if not stack<=sp<=stack+0x200000-8 or hex(uc.reg_read(UC_X86_REG_RCX))!=file.get('handle') or origin not in (0,1,2):state['stop']={'kind':'unsupported_virtual_sku_seek'};uc.emu_stop();return
    position=(0 if origin==0 else file['position'] if origin==1 else len(bytes.fromhex(file['data'])))+offset
    if not 0<=position<=len(bytes.fromhex(file['data'])):state['stop']={'kind':'unsupported_virtual_sku_seek_position'};uc.emu_stop();return
    file['position']=position;uc.reg_write(UC_X86_REG_RAX,0);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and state.get('virtual_sku_config') and imports[addr].lower()=='api-ms-win-crt-stdio-l1-1-0.dll!_ftelli64':
    sp=uc.reg_read(UC_X86_REG_RSP);file=state['virtual_sku_config']
    if not stack<=sp<=stack+0x200000-8 or hex(uc.reg_read(UC_X86_REG_RCX))!=file.get('handle'):state['stop']={'kind':'unsupported_virtual_sku_tell'};uc.emu_stop();return
    uc.reg_write(UC_X86_REG_RAX,file['position']);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and state.get('virtual_sku_config') and imports[addr].lower()=='kernel32.dll!heapqueryinformation':
    sp=uc.reg_read(UC_X86_REG_RSP);heap=uc.reg_read(UC_X86_REG_RCX);kind=uc.reg_read(UC_X86_REG_RDX);out=uc.reg_read(UC_X86_REG_R8);size=uc.reg_read(UC_X86_REG_R9)
    if not stack<=sp<=stack+0x200000-0x30 or heap!=0x7d0000001000 or kind!=0 or size!=4 or not stack<=out<=stack+0x200000-4 or struct.unpack('<Q',uc.mem_read(sp+0x28,8))[0]!=0:state['stop']={'kind':'unsupported_synthetic_heap_query'};uc.emu_stop();return
    uc.mem_write(out,struct.pack('<I',0));state.setdefault('fake_system_heap_calls',[]).append({'call':'query compatibility','result':0,'assumption':'synthetic standard heap','host_api_called':False});uc.reg_write(UC_X86_REG_RAX,1);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and state.get('virtual_sku_config') and imports[addr].lower()=='kernel32.dll!heapfree':
    sp=uc.reg_read(UC_X86_REG_RSP);heap=uc.reg_read(UC_X86_REG_RCX);flags=uc.reg_read(UC_X86_REG_RDX);ptr=uc.reg_read(UC_X86_REG_R8);allocs=state.setdefault('fake_heap_allocations',{})
    if not stack<=sp<=stack+0x200000-8 or heap!=0x7d0000001000 or flags!=0 or hex(ptr) not in allocs:state['stop']={'kind':'unsupported_virtual_sku_heapfree','pointer':hex(ptr)};uc.emu_stop();return
    del allocs[hex(ptr)];state.setdefault('fake_constructor_api_calls',[]).append({'import':imports[addr],'pointer':hex(ptr),'reuse':False});uc.reg_write(UC_X86_REG_RAX,1);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and state.get('virtual_sku_config') and imports[addr].lower()=='kernel32.dll!setunhandledexceptionfilter':
    sp=uc.reg_read(UC_X86_REG_RSP);callback=uc.reg_read(UC_X86_REG_RCX)
    if not stack<=sp<=stack+0x200000-8 or callback and not base+0x1000<=callback<base+0x32c84000:state['stop']={'kind':'unsupported_synthetic_unhandled_filter'};uc.emu_stop();return
    previous=state.get('synthetic_unhandled_filter',0);state['synthetic_unhandled_filter']=callback;uc.reg_write(UC_X86_REG_RAX,previous);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and state.get('virtual_sku_config') and imports[addr].lower()=='kernel32.dll!getcurrentdirectorya':
    sp=uc.reg_read(UC_X86_REG_RSP);capacity=uc.reg_read(UC_X86_REG_RCX);out=uc.reg_read(UC_X86_REG_RDX);value=b'C:\\Preservation'
    if not stack<=sp<=stack+0x200000-8 or not len(value)+1<=capacity<=0x10000 or not stack<=out<=stack+0x200000-capacity:state['stop']={'kind':'unsupported_synthetic_current_directory'};uc.emu_stop();return
    uc.mem_write(out,value+b'\0');state.setdefault('synthetic_environment_queries',[]).append({'name':'current directory','value':value.decode('ascii'),'host_api_called':False});uc.reg_write(UC_X86_REG_RAX,len(value));uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and state.get('virtual_sku_config') and imports[addr].lower()=='kernel32.dll!getenvironmentvariablea':
    sp=uc.reg_read(UC_X86_REG_RSP);name=uc.reg_read(UC_X86_REG_RCX);out=uc.reg_read(UC_X86_REG_RDX);capacity=uc.reg_read(UC_X86_REG_R8)
    if not stack<=sp<=stack+0x200000-8 or name!=0x172cab028 or bytes(uc.mem_read(name,5)).lower()!=b'path\0' or capacity>0x10000 or not stack<=out<=stack+0x200000-capacity:state['stop']={'kind':'unsupported_synthetic_environment'};uc.emu_stop();return
    state.setdefault('synthetic_environment_queries',[]).append({'name':'PATH','assumption':'absent in synthetic environment','host_api_called':False});uc.mem_write(teb+0x68,struct.pack('<I',203));uc.reg_write(UC_X86_REG_RAX,0);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and state.get('virtual_sku_config') and imports[addr].lower()=='kernel32.dll!getprocessheap':
    sp=uc.reg_read(UC_X86_REG_RSP)
    if not stack<=sp<=stack+0x200000-8:state['stop']={'kind':'unsafe_fake_process_heap'};uc.emu_stop();return
    state.setdefault('fake_constructor_api_calls',[]).append({'import':imports[addr],'assumption':'shared synthetic process heap'});uc.reg_write(UC_X86_REG_RAX,0x7d0000001000);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and imports[addr].lower()=='kernel32.dll!createfilew':
    sp=uc.reg_read(UC_X86_REG_RSP);ptr=uc.reg_read(UC_X86_REG_RCX)
    if not stack<=sp<=stack+0x200000-0x40 or not stack<=ptr<stack+0x200000:state['stop']={'kind':'unsafe_fake_createfile'};uc.emu_stop();return
    raw=bytes(uc.mem_read(ptr,min(1024,stack+0x200000-ptr)));end=next((i for i in range(0,len(raw)-1,2) if raw[i:i+2]==b'\0\0'),-1);path=raw[:end].decode('utf-16le','replace') if end>=0 else '<unterminated>'
    state.setdefault('fake_file_open_failures',[]).append({'api':imports[addr],'path':path,'host_filesystem_access':False});uc.mem_write(teb+0x68,struct.pack('<I',2));uc.reg_write(UC_X86_REG_RAX,0xffffffffffffffff);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and state.get('synthetic_shell_assumptions') and imports[addr].lower()=='api-ms-win-crt-stdio-l1-1-0.dll!_wfopen':
    sp=uc.reg_read(UC_X86_REG_RSP);ptr=uc.reg_read(UC_X86_REG_RCX);mode=uc.reg_read(UC_X86_REG_RDX)
    if not stack<=sp<=stack+0x200000-8 or not stack<=ptr<=stack+0x200000-512 or not base+0x32c84000<=mode<=base+0x392a6be1-8:state['stop']={'kind':'unsupported_synthetic_wfopen'};uc.emu_stop();return
    raw=bytes(uc.mem_read(ptr,512));end=next((i for i in range(0,len(raw)-1,2) if raw[i:i+2]==b'\0\0'),-1);path=raw[:end].decode('utf-16le','replace') if end>=0 else ''
    if path.lower()!='c:\\preservation\\appdata\\bungie\\marathon\\prefs\\cvars.xml' or bytes(uc.mem_read(mode,6))!=b'r\0b\0\0\0':state['stop']={'kind':'unsupported_synthetic_wfopen_path','path':path};uc.emu_stop();return
    state.setdefault('fake_file_open_failures',[]).append({'api':imports[addr],'path':path,'assumption':'empty synthetic user profile','host_filesystem_access':False});uc.reg_write(UC_X86_REG_RAX,0);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and imports[addr].lower()=='api-ms-win-crt-stdio-l1-1-0.dll!_wfsopen':
    sp=uc.reg_read(UC_X86_REG_RSP);path=uc.reg_read(UC_X86_REG_RCX);mode=uc.reg_read(UC_X86_REG_RDX)
    if not stack<=sp<=stack+0x200000-8 or not stack<=path<stack+0x200000 or not stack<=mode<stack+0x200000:state['stop']={'kind':'unsafe_fake_wfsopen'};uc.emu_stop();return
    raw=bytes(uc.mem_read(path,min(1024,stack+0x200000-path)));end=next((i for i in range(0,len(raw)-1,2) if raw[i:i+2]==b'\0\0'),-1);name=raw[:end].decode('utf-16le','replace') if end>=0 else '<unterminated>'
    if name.lower()=='c:\\preservation\\sku_config.txt' and state.get('virtual_sku_config'):
     mode_raw=bytes(uc.mem_read(mode,min(32,stack+0x200000-mode)));end_mode=next((i for i in range(0,len(mode_raw)-1,2) if mode_raw[i:i+2]==b'\0\0'),-1);mode_text=mode_raw[:end_mode].decode('utf-16le','replace') if end_mode>=0 else ''
     if mode_text not in ('r','rt','rb','rbN'):state['stop']={'kind':'unsupported_virtual_sku_open_mode','mode':mode_text};uc.emu_stop();return
     state['virtual_sku_config'].update(position=0,handle='0x7d4000000001',mode=mode_text);uc.reg_write(UC_X86_REG_RAX,0x7d4000000001);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
    state.setdefault('fake_file_open_failures',[]).append({'api':imports[addr],'path':name,'host_filesystem_access':False});uc.reg_write(UC_X86_REG_RAX,0);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and imports[addr].lower()=='api-ms-win-crt-convert-l1-1-0.dll!wcstombs':
    sp=uc.reg_read(UC_X86_REG_RSP);dst=uc.reg_read(UC_X86_REG_RCX);src=uc.reg_read(UC_X86_REG_RDX);n=uc.reg_read(UC_X86_REG_R8)
    if not stack<=sp<=stack+0x200000-8 or not 1<=n<=1024 or not stack<=dst<=stack+0x200000-n or not stack<=src<=stack+0x200000-2*n:state['stop']={'kind':'unsafe_fake_wcstombs'};uc.emu_stop();return
    units=struct.unpack('<'+'H'*n,bytes(uc.mem_read(src,2*n)));out=bytearray();terminated=False
    for value in units:
     if not value:terminated=True;break
     if value>127:state['stop']={'kind':'unsupported_fake_wcstombs_unicode'};uc.emu_stop();return
     out.append(value)
    uc.mem_write(dst,bytes(out)+(b'\0' if terminated else b''));state.setdefault('fake_constructor_api_calls',[]).append({'import':imports[addr],'length':len(out),'terminated':terminated});uc.reg_write(UC_X86_REG_RAX,len(out));uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and state.get('virtual_sku_config') and imports[addr].lower()=='kernel32.dll!findfirstfilew':
    sp=uc.reg_read(UC_X86_REG_RSP);ptr=uc.reg_read(UC_X86_REG_RCX);out=uc.reg_read(UC_X86_REG_RDX)
    if not stack<=sp<=stack+0x200000-8 or not stack<=ptr<=stack+0x200000-512 or not stack<=out<=stack+0x200000-592:state['stop']={'kind':'unsupported_synthetic_findfirst'};uc.emu_stop();return
    raw=bytes(uc.mem_read(ptr,512));end=next((i for i in range(0,len(raw)-1,2) if raw[i:i+2]==b'\0\0'),-1);pattern=raw[:end].decode('utf-16le','replace') if end>=0 else ''
    if pattern.lower()!='c:\\preservation\\packages\\_virtual\\chunk_config_*.*':state['stop']={'kind':'unsupported_synthetic_find_pattern','pattern':pattern};uc.emu_stop();return
    state.setdefault('synthetic_file_enumerations',[]).append({'pattern':pattern,'result':'no matches','basis':'preserved build lacks packages/_virtual at inspection','host_api_called':False});uc.mem_write(teb+0x68,struct.pack('<I',2));uc.reg_write(UC_X86_REG_RAX,0xffffffffffffffff);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and imports[addr].lower()=='kernel32.dll!getfileattributesw':
    sp=uc.reg_read(UC_X86_REG_RSP);ptr=uc.reg_read(UC_X86_REG_RCX)
    if not stack<=sp<=stack+0x200000-8 or not stack<=ptr<=stack+0x200000-1024:state['stop']={'kind':'unsafe_fake_file_attributes'};uc.emu_stop();return
    raw=bytes(uc.mem_read(ptr,1024));end=next((i for i in range(0,len(raw)-1,2) if raw[i:i+2]==b'\0\0'),-1)
    if end<0:state['stop']={'kind':'unterminated_fake_file_attributes'};uc.emu_stop();return
    key=hashlib.sha256(raw[:end]).hexdigest();is_file=bool(state.get('virtual_steam_module')) and key=='f2e5accbc162a9025da586f9804c119cd8576466696a3ccf818b4435cb338fab';exists=is_file or key in state.get('fake_directory_hashes',[]);result=0x80 if is_file else 0x10 if exists else 0xffffffff;uc.mem_write(teb+0x68,struct.pack('<I',0 if exists else 2));state.setdefault('fake_file_attribute_queries',[]).append({'path_hash':key,'exists':exists});uc.reg_write(UC_X86_REG_RAX,result);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and imports[addr].lower()=='kernel32.dll!createdirectoryw':
    sp=uc.reg_read(UC_X86_REG_RSP);ptr=uc.reg_read(UC_X86_REG_RCX);security=uc.reg_read(UC_X86_REG_RDX)
    if not stack<=sp<=stack+0x200000-8 or security or not stack<=ptr<=stack+0x200000-1024:state['stop']={'kind':'unsafe_fake_directory'};uc.emu_stop();return
    raw=bytes(uc.mem_read(ptr,1024));end=next((i for i in range(0,len(raw)-1,2) if raw[i:i+2]==b'\0\0'),-1)
    if end<0:state['stop']={'kind':'unterminated_fake_directory'};uc.emu_stop();return
    key=hashlib.sha256(raw[:end]).hexdigest();dirs=state.setdefault('fake_directory_hashes',[]);exists=key in dirs
    if not exists:dirs.append(key)
    uc.mem_write(teb+0x68,struct.pack('<I',183 if exists else 0));uc.reg_write(UC_X86_REG_RAX,0 if exists else 1);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and imports[addr].lower()=='kernel32.dll!gettemppathw':
    sp=uc.reg_read(UC_X86_REG_RSP);n=uc.reg_read(UC_X86_REG_RCX);dst=uc.reg_read(UC_X86_REG_RDX);value='C:\\Temp\\';raw=(value+'\0').encode('utf-16le')
    if not stack<=sp<=stack+0x200000-8 or n<len(value)+1 or not stack<=dst<=stack+0x200000-len(raw):state['stop']={'kind':'unsafe_fake_temp_path'};uc.emu_stop();return
    uc.mem_write(dst,raw);state.setdefault('fake_constructor_api_calls',[]).append({'import':imports[addr],'assumption':'synthetic temp path'});uc.reg_write(UC_X86_REG_RAX,len(value));uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and imports[addr].lower()=='kernel32.dll!getmodulefilenamew':
    sp=uc.reg_read(UC_X86_REG_RSP);module=uc.reg_read(UC_X86_REG_RCX);dst=uc.reg_read(UC_X86_REG_RDX);n=uc.reg_read(UC_X86_REG_R8);value='C:\\Preservation\\Marathon.exe';raw=(value+'\0').encode('utf-16le')
    if not stack<=sp<=stack+0x200000-8 or module!=0 or n<len(value)+1 or not stack<=dst<=stack+0x200000-len(raw):state['stop']={'kind':'unsafe_fake_module_path'};uc.emu_stop();return
    uc.mem_write(dst,raw);state.setdefault('fake_constructor_api_calls',[]).append({'import':imports[addr],'assumption':'synthetic module path'});uc.reg_write(UC_X86_REG_RAX,len(value));uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and imports[addr].lower() in ('vcruntime140.dll!_set_purecall_handler','api-ms-win-crt-runtime-l1-1-0.dll!_set_invalid_parameter_handler'):
    sp=uc.reg_read(UC_X86_REG_RSP);ptr=uc.reg_read(UC_X86_REG_RCX)
    if not stack<=sp<=stack+0x200000-8 or not 0x140001000<=ptr<0x172c84000:state['stop']={'kind':'unsafe_fake_purecall_handler'};uc.emu_stop();return
    key='fake_purecall_handler' if imports[addr].lower().endswith('_set_purecall_handler') else 'fake_invalid_parameter_handler';previous=state.get(key,0);state[key]=ptr;uc.reg_write(UC_X86_REG_RAX,previous);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and imports[addr].lower() in ('kernel32.dll!createmutexw','kernel32.dll!createmutexa'):
    sp=uc.reg_read(UC_X86_REG_RSP);security=uc.reg_read(UC_X86_REG_RCX);initial=uc.reg_read(UC_X86_REG_RDX);ptr=uc.reg_read(UC_X86_REG_R8)
    if not stack<=sp<=stack+0x200000-8 or security or initial not in (0,1) or not (0x172c84000<=ptr<0x173534000-128 or stack<=ptr<=stack+0x200000-256):state['stop']={'kind':'unsafe_fake_mutex_create'};uc.emu_stop();return
    handles=state.setdefault('fake_mutex_handles',[]);handle=0x7d2000000001+len(handles);handles.append({'name_pointer':hex(ptr),'initial_owner':initial,'handle':hex(handle)});uc.mem_write(teb+0x68,struct.pack('<I',0));uc.reg_write(UC_X86_REG_RAX,handle);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and imports[addr].lower() in ('kernel32.dll!entercriticalsection','kernel32.dll!leavecriticalsection') and state.get('synthetic_peb_loader_lock'):
    sp=uc.reg_read(UC_X86_REG_RSP);ptr=uc.reg_read(UC_X86_REG_RCX);name=imports[addr].lower().split('!')[-1];lock=int(state['synthetic_peb_loader_lock']['address'],16);depths=state.setdefault('fake_critical_depths',{});depth=depths.get(hex(ptr),state.get('synthetic_peb_lock_depth',0) if ptr==lock else 0)
    initialized=ptr==lock or any(c.get('object')==hex(ptr) and c.get('import','').lower().startswith('kernel32.dll!initializecriticalsection') for c in state.get('fake_constructor_api_calls',[]))
    if not (stack<=sp<=stack+0x200000-8 or (state.get('synthetic_second_d3d12_device') and child_stack<=sp<=child_stack+0x200000-8)) or not initialized or (name=='leavecriticalsection' and not depth):state['stop']={'kind':'unsupported_fake_critical_lock','pointer':hex(ptr)};uc.emu_stop();return
    depths[hex(ptr)]=depth+(1 if name=='entercriticalsection' else -1)
    if ptr==lock:state['synthetic_peb_lock_depth']=depths[hex(ptr)]
    state.setdefault('fake_peb_lock_calls',[]).append({'operation':name,'object':hex(ptr),'depth':depths[hex(ptr)],'single_thread_assumption':True});uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and imports[addr].lower()=='kernel32.dll!getmodulehandlea' and state.get('synthetic_peb_modules'):
    sp=uc.reg_read(UC_X86_REG_RSP);ptr=uc.reg_read(UC_X86_REG_RCX)
    if not stack<=sp<=stack+0x200000-8 or not (stack<=ptr<=stack+0x200000-128 or base+0x32c84000<=ptr<=base+0x392a6be1-128):state['stop']={'kind':'unsafe_fake_getmodulehandle'};uc.emu_stop();return
    raw=bytes(uc.mem_read(ptr,128));end=raw.find(b'\0')
    if end<0:state['stop']={'kind':'unterminated_fake_getmodulehandle'};uc.emu_stop();return
    name=raw[:end].decode('ascii','backslashreplace').lower();canonical=name if '.' in name else name+'.dll';matches=[m for m in state['synthetic_peb_modules'] if m['name'].lower()==canonical];result=int(matches[0]['base'],16) if matches else 0;uc.mem_write(teb+0x68,struct.pack('<I',0 if result else 126));state.setdefault('fake_module_lookups',[]).append({'name':name,'result':hex(result)});uc.reg_write(UC_X86_REG_RAX,result);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and imports[addr].lower()=='kernel32.dll!getprocaddress' and any(uc.reg_read(UC_X86_REG_RCX)==int(m['base'],16) for m in state.get('synthetic_peb_modules',[])):
    sp=uc.reg_read(UC_X86_REG_RSP);handle=uc.reg_read(UC_X86_REG_RCX);ptr=uc.reg_read(UC_X86_REG_RDX);mod=next(m for m in state['synthetic_peb_modules'] if int(m['base'],16)==handle)
    if not stack<=sp<=stack+0x200000-8 or not (handle<=ptr<=handle+mod['size']-128 or base+0x32c84000<=ptr<=base+0x392a6be1-128):state['stop']={'kind':'unsafe_fake_system_getproc'};uc.emu_stop();return
    raw=bytes(uc.mem_read(ptr,128));end=raw.find(b'\0');symbol=raw[:end].decode('ascii','backslashreplace') if end>=0 else '<unterminated>'
    if (mod['name'],symbol)==('kernel32.dll','HeapAlloc'):result=exception_mem+0x7050;state['fake_system_heap_alloc_symbol']=True
    elif (mod['name'],symbol)==('kernel32.dll','GetLogicalProcessorInformation'):result=exception_mem+0x70c0;state['fake_processor_info_symbol']=True
    elif (mod['name'],symbol)==('kernel32.dll','SetProcessMitigationPolicy'):result=exception_mem+0x7060;state['fake_mitigation_symbol']=True
    elif (mod['name'],symbol) in (('crypt32.dll','CryptProtectMemory'),('crypt32.dll','CryptUnprotectMemory')):result=exception_mem+(0x7070 if symbol=='CryptProtectMemory' else 0x7080);state['fake_crypt_symbols']=True
    else:state['stop']={'kind':'dynamic_import_required','library':mod['name'],'symbol':symbol};uc.emu_stop();return
    state.setdefault('fake_system_proc_lookups',[]).append({'library':mod['name'],'symbol':symbol});uc.reg_write(UC_X86_REG_RAX,result);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and imports[addr].lower()=='kernel32.dll!getprocaddress' and uc.reg_read(UC_X86_REG_RCX) in state.get('fake_library_handles',{}).values():
    sp=uc.reg_read(UC_X86_REG_RSP);handle=uc.reg_read(UC_X86_REG_RCX);ptr=uc.reg_read(UC_X86_REG_RDX)
    if state.get('synthetic_dxgi_adapter') and handle==state.get('fake_library_handles',{}).get('d3d12.dll') and ptr==101 and state.get('synthetic_d3d12_ordinal_101')=='D3D12CreateDevice':
     if not child_stack<=sp<=child_stack+0x200000-8:state['stop']={'kind':'unsafe_synthetic_d3d12_ordinal'};uc.emu_stop();return
     state['fake_d3d12_create_device_symbol']=True;state.setdefault('fake_system_proc_lookups',[]).append({'library':'d3d12.dll','ordinal':101,'symbol':'D3D12CreateDevice','basis':'hash-checked local system PE export only'});uc.reg_write(UC_X86_REG_RAX,exception_mem+0x70f0);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
    if not (stack<=sp<=stack+0x200000-8 or state.get('dynamic_worker_experiment') and child_stack<=sp<=child_stack+0x200000-8) or not 0x172c84000<=ptr<=0x173534000-128:state['stop']={'kind':'unsafe_fake_getproc'};uc.emu_stop();return
    raw=bytes(uc.mem_read(ptr,128));end=raw.find(b'\0');symbol=raw[:end].decode('ascii','backslashreplace') if end>=0 else '<unterminated>';library=next(k for k,v in state['fake_library_handles'].items() if v==handle)
    if (library,symbol)==('user32.dll','RegisterWindowMessageW'):result=exception_mem+0x7000;state['fake_window_message_symbol']=True
    elif (library,symbol)==('shlwapi.dll','PathRemoveFileSpecW'):result=exception_mem+0x7010;state['fake_path_remove_symbol']=True
    elif (library,symbol)==('shell32.dll','SHFileOperationW'):result=exception_mem+0x7020;state['fake_file_operation_symbol']=True
    elif (library,symbol)==('shell32.dll','SHGetKnownFolderPath'):result=exception_mem+0x7030;state['fake_known_folder_symbol']=True
    elif (library,symbol)==('shell32.dll','SHGetFolderPathW'):result=exception_mem+0x7090;state['fake_shgetfolderpath_symbol']=True
    elif (library,symbol)==('ole32.dll','CoTaskMemFree'):result=exception_mem+0x7040;state['fake_cotaskfree_symbol']=True
    elif (library,symbol)==('ole32.dll','CoInitializeEx'):result=exception_mem+0x70d0;state['fake_coinitialize_symbol']=True
    elif (library,symbol)==('dxgi.dll','CreateDXGIFactory1'):result=exception_mem+0x70e0;state['fake_dxgi_factory_symbol']=True
    elif library=='xinput1_4.dll' and symbol in state.get('virtual_xinput_module',{}).get('exports',[]):
     markers=state.setdefault('virtual_xinput_markers',{});existing=next((int(k,16) for k,v in markers.items() if v==symbol),None);result=existing if existing is not None else 0x7d7100000000+16*len(markers)
     if result>=0x7d7100001000:state['stop']={'kind':'virtual_xinput_marker_limit'};uc.emu_stop();return
     markers[hex(result)]=symbol
    elif library=='oo2core_9_win64.dll' and symbol in state.get('virtual_oodle_module',{}).get('exports',[]):
     markers=state.setdefault('virtual_oodle_markers',{});existing=next((int(k,16) for k,v in markers.items() if v==symbol),None);result=existing if existing is not None else 0x7d7000000000+16*len(markers)
     if result>=0x7d7000001000:state['stop']={'kind':'virtual_oodle_marker_limit'};uc.emu_stop();return
     markers[hex(result)]=symbol
    elif library=='steam_api64.dll' and symbol in state.get('virtual_steam_module',{}).get('exports',[]):
     markers=state.setdefault('virtual_steam_markers',{});existing=next((int(k,16) for k,v in markers.items() if v==symbol),None);result=existing if existing is not None else exception_mem+0x9000+16*len(markers)
     if result>=exception_mem+0x10000:state['stop']={'kind':'virtual_steam_marker_limit'};uc.emu_stop();return
     markers[hex(result)]=symbol
    else:state['stop']={'kind':'dynamic_import_required','library':library,'symbol':symbol};uc.emu_stop();return
    state.setdefault('fake_constructor_api_calls',[]).append({'import':imports[addr],'library':library,'symbol':symbol});uc.reg_write(UC_X86_REG_RAX,result);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and imports[addr].lower()=='kernel32.dll!loadlibraryexa':
    sp=uc.reg_read(UC_X86_REG_RSP);ptr=uc.reg_read(UC_X86_REG_RCX)
    if not (stack<=sp<=stack+0x200000-8 or state.get('dynamic_worker_experiment') and child_stack<=sp<=child_stack+0x200000-8) or not 0x172c84000<=ptr<=0x173534000-128:state['stop']={'kind':'unsafe_fake_loadlibrary'};uc.emu_stop();return
    raw=bytes(uc.mem_read(ptr,128));end=raw.find(b'\0');value=raw[:end].lower() if end>=0 else b''
    if value not in (b'user32.dll',b'shlwapi.dll',b'gdi32.dll',b'shell32.dll',b'ole32.dll',b'winmm.dll') and value.decode('ascii','backslashreplace') not in state.get('fake_library_handles',{}) and not (value==b'steam_api64.dll' and state.get('virtual_steam_module')) and not (value==b'oo2core_9_win64.dll' and state.get('virtual_oodle_module')):state['stop']={'kind':'unsupported_fake_library','name':value.decode('ascii','backslashreplace')};uc.emu_stop();return
    libs=state.setdefault('fake_library_handles',{});key=value.decode();handle=libs.setdefault(key,0x7d1000000000+len(libs)*0x1000);state.setdefault('fake_constructor_api_calls',[]).append({'import':imports[addr],'library':key,'handle':hex(handle)});uc.reg_write(UC_X86_REG_RAX,handle);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and imports[addr].lower() in ('api-ms-win-crt-runtime-l1-1-0.dll!__p___argv','api-ms-win-crt-runtime-l1-1-0.dll!__p___argc'):
    sp=uc.reg_read(UC_X86_REG_RSP)
    if not stack<=sp<=stack+0x200000-8:state['stop']={'kind':'unsafe_fake_argv_stack'};uc.emu_stop();return
    if not state.get('fake_argv_initialized'):
     uc.mem_write(exception_mem+0x6000,struct.pack('<Q',exception_mem+0x6100));uc.mem_write(exception_mem+0x6008,struct.pack('<I',1));uc.mem_write(exception_mem+0x6100,struct.pack('<QQ',exception_mem+0x6200,0));uc.mem_write(exception_mem+0x6200,b'Marathon.exe\0');state['fake_argv_initialized']=True
    result=exception_mem+0x6000 if imports[addr].lower().endswith('__p___argv') else exception_mem+0x6008;state.setdefault('fake_constructor_api_calls',[]).append({'import':imports[addr],'assumption':'synthetic argv'});uc.reg_write(UC_X86_REG_RAX,result);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and imports[addr].lower()=='api-ms-win-crt-runtime-l1-1-0.dll!_get_narrow_winmain_command_line':
    sp=uc.reg_read(UC_X86_REG_RSP)
    if not stack<=sp<=stack+0x200000-8:state['stop']={'kind':'unsafe_fake_command_line'};uc.emu_stop();return
    ptr=exception_mem+0x5300;uc.mem_write(ptr,b'\x00');state.setdefault('fake_constructor_api_calls',[]).append({'import':imports[addr],'assumption':'empty synthetic command line'});uc.reg_write(UC_X86_REG_RAX,ptr);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and imports[addr].lower()=='kernel32.dll!getstartupinfow':
    sp=uc.reg_read(UC_X86_REG_RSP);ptr=uc.reg_read(UC_X86_REG_RCX)
    if not stack<=sp<=stack+0x200000-8 or not stack<=ptr<=stack+0x200000-0x68:state['stop']={'kind':'unsafe_fake_startup_info'};uc.emu_stop();return
    uc.mem_write(ptr,struct.pack('<I',0x68)+bytes(0x64));state.setdefault('fake_constructor_api_calls',[]).append({'import':imports[addr],'assumption':'zeroed synthetic STARTUPINFOW'});uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and imports[addr].lower()=='vcruntime140.dll!memset':
    sp=uc.reg_read(UC_X86_REG_RSP);ptr=uc.reg_read(UC_X86_REG_RCX);value=uc.reg_read(UC_X86_REG_RDX)&255;n=uc.reg_read(UC_X86_REG_R8)
    committed=any(start<=ptr and ptr+n<=end for start,end in state.get('fake_virtual_commits',[]))
    if not (stack<=sp<=stack+0x200000-8 or state.get('dynamic_worker_experiment') and child_stack<=sp<=child_stack+0x200000-8) or n>0x1000000 or not (0x173534000<=ptr<=0x1792a6be1-n or stack<=ptr<=stack+0x200000-n or state.get('dynamic_worker_experiment') and child_stack<=ptr<=child_stack+0x200000-n or 0x790000000000<=ptr<=0x790000000000+state.get('fake_heap_used',0)-n or committed):state['stop']={'kind':'unsafe_fake_memset'};uc.emu_stop();return
    if committed:
     for page in range(ptr&~0xfff,(ptr+n+4095)&~0xfff,4096):
      if page not in pages and not invalid(uc,UC_MEM_WRITE_UNMAPPED,page,1,0,None):uc.emu_stop();return
    if n and any(ptr < point+0x40 and point < ptr+n for point in watch_points):state['stop']={'kind':'watched_fake_memset','destination':hex(ptr),'size':n,'value':value};uc.emu_stop();return
    uc.mem_write(ptr,bytes([value])*n);state.setdefault('fake_constructor_api_calls',[]).append({'import':imports[addr],'destination':hex(ptr),'size':n,'value':value});uc.reg_write(UC_X86_REG_RAX,ptr);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and state.get('active_crt_initializer') and imports[addr].lower()=='advapi32.dll!getusernamea':
    sp=uc.reg_read(UC_X86_REG_RSP);dst=uc.reg_read(UC_X86_REG_RCX);sizeptr=uc.reg_read(UC_X86_REG_RDX);value=b'preservation\0'
    if not stack<=sp<=stack+0x200000-8 or not stack<=sizeptr<=stack+0x200000-4 or not stack<=dst<=stack+0x200000-len(value) or struct.unpack('<I',bytes(uc.mem_read(sizeptr,4)))[0]<len(value):state['stop']={'kind':'unsafe_fake_username'};uc.emu_stop();return
    uc.mem_write(dst,value);uc.mem_write(sizeptr,struct.pack('<I',len(value)));state.setdefault('fake_constructor_api_calls',[]).append({'import':imports[addr],'value':'synthetic'});uc.reg_write(UC_X86_REG_RAX,1);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and state.get('active_crt_initializer') and imports[addr].lower()=='iphlpapi.dll!getadaptersaddresses':
    sp=uc.reg_read(UC_X86_REG_RSP)
    if not stack<=sp<=stack+0x200000-0x30:state['stop']={'kind':'unsafe_fake_adapter_query'};uc.emu_stop();return
    state.setdefault('fake_constructor_api_calls',[]).append({'import':imports[addr],'result':'ERROR_NO_DATA','host_network_access':False});uc.reg_write(UC_X86_REG_RAX,232);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and imports[addr].lower() in ('vcruntime140.dll!memcpy','vcruntime140.dll!memmove'):
    sp=uc.reg_read(UC_X86_REG_RSP);dst=uc.reg_read(UC_X86_REG_RCX);src=uc.reg_read(UC_X86_REG_RDX);n=uc.reg_read(UC_X86_REG_R8)
    dst_committed=any(lo<=dst and dst+n<=hi for lo,hi in state.get('fake_virtual_commits',[]));src_committed=any(lo<=src and src+n<=hi for lo,hi in state.get('fake_virtual_commits',[]));src_module=any(int(m['base'],16)<=src and src+n<=int(m['base'],16)+m['size'] for m in state.get('synthetic_peb_modules',[]))
    def allowed_copy_stack(ptr,size):return stack<=ptr<=stack+0x200000-size or (state.get('synthetic_dxgi_output') and child_stack<=ptr<=child_stack+0x200000-size)
    if not allowed_copy_stack(sp,8) or n>65536 or not (0x173534000<=dst<=0x1792a6be1-n or allowed_copy_stack(dst,n) or 0x790000000000<=dst<=0x790000000000+state.get('fake_heap_used',0)-n or dst_committed) or (n and not (0x172c84000<=src<=0x1792a6be1-n or allowed_copy_stack(src,n) or 0x790000000000<=src<=0x790000000000+state.get('fake_heap_used',0)-n or src_committed or src_module)):state['stop']={'kind':'unsafe_fake_memcpy'};uc.emu_stop();return
    for ptr,committed,access in ((dst,dst_committed,UC_MEM_WRITE_UNMAPPED),(src,src_committed,UC_MEM_READ_UNMAPPED)):
     if committed:
      for page in range(ptr&~0xfff,(ptr+n+4095)&~0xfff,4096):
       if page not in pages and not invalid(uc,access,page,1,0,None):uc.emu_stop();return
    if n and any(dst < point+0x40 and point < dst+n for point in watch_points):state['stop']={'kind':'watched_fake_memcpy','destination':hex(dst),'size':n};uc.emu_stop();return
    uc.mem_write(dst,bytes(uc.mem_read(src,n)) if n else b'');state.setdefault('fake_constructor_api_calls',[]).append({'import':imports[addr],'destination':hex(dst),'source':hex(src),'size':n});uc.reg_write(UC_X86_REG_RAX,dst);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and state.get('active_crt_initializer') and imports[addr].lower()=='advapi32.dll!reggetvaluea':
    sp=uc.reg_read(UC_X86_REG_RSP);flags=uc.reg_read(UC_X86_REG_R9)
    if not stack<=sp<=stack+0x200000-0x40 or flags&0x20000000:state['stop']={'kind':'unsafe_fake_registry_query'};uc.emu_stop();return
    state.setdefault('fake_constructor_api_calls',[]).append({'import':imports[addr],'result':'ERROR_FILE_NOT_FOUND','host_registry_access':False});uc.reg_write(UC_X86_REG_RAX,2);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and state.get('active_crt_initializer') and imports[addr].lower()=='kernel32.dll!globalmemorystatusex':
    sp=uc.reg_read(UC_X86_REG_RSP);ptr=uc.reg_read(UC_X86_REG_RCX)
    if not stack<=sp<=stack+0x200000-8 or not stack<=ptr<=stack+0x200000-64 or struct.unpack('<I',bytes(uc.mem_read(ptr,4)))[0]!=64:state['stop']={'kind':'unsafe_fake_memory_status'};uc.emu_stop();return
    uc.mem_write(ptr,struct.pack('<II7Q',64,50,8<<30,4<<30,16<<30,8<<30,1<<47,1<<46,0));state.setdefault('fake_constructor_api_calls',[]).append({'import':imports[addr],'synthetic':True});uc.reg_write(UC_X86_REG_RAX,1);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and state.get('active_crt_initializer') and imports[addr].lower()=='api-ms-win-crt-runtime-l1-1-0.dll!_register_onexit_function':
    sp=uc.reg_read(UC_X86_REG_RSP);table=uc.reg_read(UC_X86_REG_RCX);callback=uc.reg_read(UC_X86_REG_RDX)
    if not stack<=sp<=stack+0x200000-8 or not 0x173534000<=table<0x1792a6be1 or not 0x140001000<=callback<0x172c84000:state['stop']={'kind':'unsafe_fake_onexit'};uc.emu_stop();return
    state.setdefault('fake_constructor_api_calls',[]).append({'import':imports[addr],'table':hex(table),'callback':hex(callback),'executed':False});uc.reg_write(UC_X86_REG_RAX,0);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and imports[addr].lower() in ('kernel32.dll!initializecriticalsectionex','kernel32.dll!initializecriticalsectionandspincount','kernel32.dll!initializecriticalsection'):
    sp=uc.reg_read(UC_X86_REG_RSP);ptr=uc.reg_read(UC_X86_REG_RCX)
    committed=any(lo<=ptr and ptr+40<=hi for lo,hi in state.get('fake_virtual_commits',[]))
    if not (stack<=sp<=stack+0x200000-8 or (state.get('synthetic_second_d3d12_device') and child_stack<=sp<=child_stack+0x200000-8)) or ptr%4 or not (0x173534000<=ptr<=0x1792a6be1-40 or committed) or (imports[addr].lower().endswith('initializecriticalsectionex') and uc.reg_read(UC_X86_REG_R8)!=0):state['stop']={'kind':'unsafe_fake_critical_section'};uc.emu_stop();return
    if committed:
     for page in range(ptr&~0xfff,(ptr+40+4095)&~0xfff,4096):
      if page not in pages and not invalid(uc,UC_MEM_WRITE_UNMAPPED,page,1,0,None):uc.emu_stop();return
    if any(ptr < point+0x40 and point < ptr+40 for point in watch_points):state['stop']={'kind':'watched_fake_critical_section','destination':hex(ptr)};uc.emu_stop();return
    uc.mem_write(ptr,struct.pack('<QiIQQQ',0,-1,0,0,0,0));state.setdefault('fake_constructor_api_calls',[]).append({'import':imports[addr],'object':hex(ptr),'synchronization':'synthetic single-threaded'});uc.reg_write(UC_X86_REG_RAX,1 if not imports[addr].lower().endswith('!initializecriticalsection') else uc.reg_read(UC_X86_REG_RAX));uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and imports[addr].lower()=='api-ms-win-crt-heap-l1-1-0.dll!malloc':
    sp=uc.reg_read(UC_X86_REG_RSP);n=uc.reg_read(UC_X86_REG_RCX);heap=0x790000000000
    if not stack<=sp<=stack+0x200000-8 or n>0x100000:state['stop']={'kind':'unsafe_fake_malloc'};uc.emu_stop();return
    if 'fake_heap_used' not in state:uc.mem_map(heap,0x1000000);state['fake_heap_used']=0
    off=(state['fake_heap_used']+15)&~15;end=off+max(1,n)
    if end>0x1000000:state['stop']={'kind':'fake_heap_exhausted'};uc.emu_stop();return
    state['fake_heap_used']=end;result=heap+off;state.setdefault('fake_heap_allocations',{})[hex(result)]=n;state.setdefault('fake_constructor_api_calls',[]).append({'import':imports[addr],'size':n,'result':hex(result)});uc.reg_write(UC_X86_REG_RAX,result);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and imports[addr].lower() in ('kernel32.dll!acquiresrwlockexclusive','kernel32.dll!releasesrwlockexclusive','kernel32.dll!acquiresrwlockshared','kernel32.dll!releasesrwlockshared','kernel32.dll!wakeallconditionvariable','kernel32.dll!wakeconditionvariable'):
    sp=uc.reg_read(UC_X86_REG_RSP);ptr=uc.reg_read(UC_X86_REG_RCX)
    if not (stack<=sp<=stack+0x200000-8 or state.get('dynamic_worker_experiment') and child_stack<=sp<=child_stack+0x200000-8) or not 0x173534000<=ptr<0x1792a6be1:state['stop']={'kind':'unsafe_fake_srw'};uc.emu_stop();return
    state.setdefault('fake_constructor_api_calls',[]).append({'import':imports[addr],'lock':hex(ptr),'synchronization':'synthetic single-threaded'});uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and state.get('active_crt_initializer') and imports[addr].lower() in ('kernel32.dll!initoncebegininitialize','kernel32.dll!initoncecomplete'):
    sp=uc.reg_read(UC_X86_REG_RSP);ptr=uc.reg_read(UC_X86_REG_RCX);flags=uc.reg_read(UC_X86_REG_RDX);short=imports[addr].lower().split('!')[-1]
    if not stack<=sp<=stack+0x200000-8 or flags!=0 or not 0x790000000000<=ptr<0x790000000000+state.get('fake_heap_used',0):state['stop']={'kind':'unsafe_fake_once'};uc.emu_stop();return
    states=state.setdefault('fake_once_states',{});key=hex(ptr)
    if short=='initoncebegininitialize':
     out=uc.reg_read(UC_X86_REG_R8)
     if not stack<=out<=stack+0x200000-4:state['stop']={'kind':'unsafe_fake_once_output'};uc.emu_stop();return
     pending=0 if states.get(key)=='complete' else 1;uc.mem_write(out,struct.pack('<I',pending));states[key]='complete' if pending==0 else 'pending'
    else:
     if states.get(key)!='pending':state['stop']={'kind':'unexpected_fake_once_complete'};uc.emu_stop();return
     states[key]='complete'
    state.setdefault('fake_constructor_api_calls',[]).append({'import':imports[addr],'object':key,'state':states[key]});uc.reg_write(UC_X86_REG_RAX,1);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and state.get('active_crt_initializer') and imports[addr].lower()=='msvcp140.dll!_cnd_init_in_situ':
    sp=uc.reg_read(UC_X86_REG_RSP);ptr=uc.reg_read(UC_X86_REG_RCX)
    if not stack<=sp<=stack+0x200000-8 or not 0x173534000<=ptr<0x1792a6be1:state['stop']={'kind':'unsafe_fake_condition'};uc.emu_stop();return
    state.setdefault('fake_constructor_api_calls',[]).append({'import':imports[addr],'object':hex(ptr),'synchronization':'synthetic single-threaded'});uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and state.get('active_crt_initializer') and imports[addr].lower()=='msvcp140.dll!_mtx_init_in_situ':
    sp=uc.reg_read(UC_X86_REG_RSP);ptr=uc.reg_read(UC_X86_REG_RCX);kind=uc.reg_read(UC_X86_REG_RDX)
    if not stack<=sp<=stack+0x200000-8 or kind!=2 or not (0x790000000000<=ptr<0x790000000000+state.get('fake_heap_used',0) or 0x173534000<=ptr<0x1792a6be1):state['stop']={'kind':'unsafe_fake_mutex'};uc.emu_stop();return
    state.setdefault('fake_constructor_api_calls',[]).append({'import':imports[addr],'object':hex(ptr),'kind':kind,'synchronization':'synthetic single-threaded'});uc.reg_write(UC_X86_REG_RAX,0);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and state.get('active_crt_initializer') and imports[addr].lower() in ('msvcp140.dll!_mtx_lock','msvcp140.dll!_mtx_unlock'):
    sp=uc.reg_read(UC_X86_REG_RSP);ptr=uc.reg_read(UC_X86_REG_RCX);short=imports[addr].lower().split('!')[-1];key=hex(ptr);locks=state.setdefault('fake_mutex_locks',{})
    if not stack<=sp<=stack+0x200000-8 or not 0x790000000000<=ptr<0x790000000000+state.get('fake_heap_used',0) or (short=='_mtx_unlock' and not locks.get(key)):state['stop']={'kind':'unsafe_fake_mutex_lock'};uc.emu_stop();return
    locks[key]=locks.get(key,0)+(1 if short=='_mtx_lock' else -1);state.setdefault('fake_constructor_api_calls',[]).append({'import':imports[addr],'object':key,'depth':locks[key]});uc.reg_write(UC_X86_REG_RAX,0);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and imports[addr].lower()=='api-ms-win-crt-heap-l1-1-0.dll!free':
    sp=uc.reg_read(UC_X86_REG_RSP);ptr=uc.reg_read(UC_X86_REG_RCX);allocs=state.setdefault('fake_heap_allocations',{})
    if not stack<=sp<=stack+0x200000-8 or ptr and hex(ptr) not in allocs:state['stop']={'kind':'unsafe_fake_free'};uc.emu_stop();return
    if ptr:del allocs[hex(ptr)]
    state.setdefault('fake_constructor_api_calls',[]).append({'import':imports[addr],'pointer':hex(ptr),'reuse':False});uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and imports[addr].lower()=='vcruntime140.dll!memcmp':
    sp=uc.reg_read(UC_X86_REG_RSP);left=uc.reg_read(UC_X86_REG_RCX);right=uc.reg_read(UC_X86_REG_RDX);n=uc.reg_read(UC_X86_REG_R8)
    if not stack<=sp<=stack+0x200000-8 or n>65536 or any(not (0x172c84000<=v<=0x1792a6be1-n or stack<=v<=stack+0x200000-n or 0x790000000000<=v<=0x790000000000+state.get('fake_heap_used',0)-n or any(lo<=v and v+n<=hi for lo,hi in state.get('fake_virtual_commits',[]))) for v in (left,right)):state['stop']={'kind':'unsafe_fake_memcmp'};uc.emu_stop();return
    vals=[]
    for v in (left,right):
     vals.append(bytes(uc.mem_read(v,n)))
    result=next((x-y for x,y in zip(*vals) if x!=y),0);state.setdefault('fake_constructor_api_calls',[]).append({'import':imports[addr],'size':n,'result':result});uc.reg_write(UC_X86_REG_RAX,result&0xffffffff);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and imports[addr].lower()=='kernel32.dll!getsysteminfo':
    sp=uc.reg_read(UC_X86_REG_RSP);ptr=uc.reg_read(UC_X86_REG_RCX)
    if not stack<=sp<=stack+0x200000-8 or not stack<=ptr<=stack+0x200000-48:state['stop']={'kind':'unsafe_fake_system_info'};uc.emu_stop();return
    uc.mem_write(ptr,struct.pack('<HHIQQQIIIHH',9,0,4096,0x10000,0x7fffffffffff,0xff,8,8664,65536,6,0x3a09));state.setdefault('fake_constructor_api_calls',[]).append({'import':imports[addr],'synthetic':True});uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and state.get('virtual_xinput_module') and imports[addr].lower()=='kernel32.dll!loadlibrarya':
    sp=uc.reg_read(UC_X86_REG_RSP);ptr=uc.reg_read(UC_X86_REG_RCX)
    if not stack<=sp<=stack+0x200000-8 or not base+0x32c84000<=ptr<=base+0x392a6be1-128:state['stop']={'kind':'unsafe_fake_xinput_load'};uc.emu_stop();return
    value=bytes(uc.mem_read(ptr,128)).split(b'\0',1)[0].lower()
    if value!=b'xinput1_4.dll':state['stop']={'kind':'unsupported_fake_xinput_load','name':value.decode('ascii','backslashreplace')};uc.emu_stop();return
    libs=state.setdefault('fake_library_handles',{});handle=libs.setdefault('xinput1_4.dll',0x7d1000000000+len(libs)*0x1000);uc.reg_write(UC_X86_REG_RAX,handle);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and state.get('active_crt_initializer') and imports[addr].lower()=='kernel32.dll!loadlibrarya':
    sp=uc.reg_read(UC_X86_REG_RSP);ptr=uc.reg_read(UC_X86_REG_RCX)
    if not stack<=sp<=stack+0x200000-8 or not base+0x32c84000<=ptr<base+0x33534000-32:state['stop']={'kind':'unsafe_fake_loadlibrary'};uc.emu_stop();return
    raw=bytes(uc.mem_read(ptr,32));name=raw.split(b'\0',1)[0].lower()
    if name!=b'kernel32.dll':state['stop']={'kind':'unsupported_fake_loadlibrary','library':name.decode('ascii','backslashreplace')};uc.emu_stop();return
    state['fake_kernel32_handle']='0x7b0000000000';uc.reg_write(UC_X86_REG_RAX,0x7b0000000000);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and state.get('active_crt_initializer') and imports[addr].lower()=='kernel32.dll!loadlibraryexa':
    sp=uc.reg_read(UC_X86_REG_RSP);ptr=uc.reg_read(UC_X86_REG_RCX)
    if not stack<=sp<=stack+0x200000-8 or not base+0x32c84000<=ptr<base+0x33534000-64 or uc.reg_read(UC_X86_REG_RDX)!=0 or uc.reg_read(UC_X86_REG_R8)!=0:state['stop']={'kind':'unsafe_fake_loadlibraryex'};uc.emu_stop();return
    raw=bytes(uc.mem_read(ptr,64));name=raw.split(b'\0',1)[0].lower()
    if name!=b'winmm.dll':state['stop']={'kind':'unsupported_fake_loadlibraryex','library':name.decode('ascii','backslashreplace')};uc.emu_stop();return
    state['fake_winmm_handle']='0x7b0000010000';uc.reg_write(UC_X86_REG_RAX,0x7b0000010000);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and imports[addr].lower()=='kernel32.dll!getprocaddress' and uc.reg_read(UC_X86_REG_RCX)==0x7b0000010000 and state.get('fake_winmm_handle'):
    sp=uc.reg_read(UC_X86_REG_RSP);ptr=uc.reg_read(UC_X86_REG_RDX)
    if not stack<=sp<=stack+0x200000-8 or not base+0x32c84000<=ptr<base+0x33534000-128:state['stop']={'kind':'unsafe_fake_winmm_getproc'};uc.emu_stop();return
    symbol=bytes(uc.mem_read(ptr,128)).split(b'\0',1)[0]
    if symbol==b'timeGetDevCaps':state['fake_timer_caps_symbol']=True;uc.reg_write(UC_X86_REG_RAX,exception_mem+0x70a0);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
    if symbol==b'timeBeginPeriod':state['fake_timer_begin_symbol']=True;uc.reg_write(UC_X86_REG_RAX,exception_mem+0x70b0);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
    if symbol!=b'timeGetTime':state['stop']={'kind':'dynamic_import_required','library':'winmm.dll','symbol':symbol.decode('ascii','backslashreplace')};uc.emu_stop();return
    if not state.get('fake_cpu_query_mapped'):uc.mem_map(0x7b0000001000,0x1000);state['fake_cpu_query_mapped']=True
    state['fake_winmm_symbol']=symbol.decode();uc.reg_write(UC_X86_REG_RAX,0x7b0000001030);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and state.get('active_crt_initializer') and imports[addr].lower()=='kernel32.dll!getprocaddress' and state.get('fake_kernel32_handle'):
    sp=uc.reg_read(UC_X86_REG_RSP);handle=uc.reg_read(UC_X86_REG_RCX);ptr=uc.reg_read(UC_X86_REG_RDX)
    if not stack<=sp<=stack+0x200000-8 or handle!=0x7b0000000000 or not base+0x32c84000<=ptr<base+0x33534000-128:state['stop']={'kind':'unsafe_fake_getproc'};uc.emu_stop();return
    raw=bytes(uc.mem_read(ptr,128));symbol=raw.split(b'\0',1)[0]
    if symbol not in (b'GetLogicalProcessorInformation',b'RtlCaptureContext',b'RtlCaptureStackBackTrace'):state['stop']={'kind':'dynamic_import_required','library':'kernel32.dll','symbol':symbol.decode('ascii','backslashreplace')};uc.emu_stop();return
    dyn=0x7b0000001000+({b'GetLogicalProcessorInformation':0,b'RtlCaptureContext':0x10,b'RtlCaptureStackBackTrace':0x20}[symbol])
    if not state.get('fake_cpu_query_mapped'):uc.mem_map(0x7b0000001000,0x1000);state['fake_cpu_query_mapped']=True
    state['fake_cpu_dynamic_symbol']=symbol.decode();uc.reg_write(UC_X86_REG_RAX,dyn);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and imports[addr].lower()=='kernel32.dll!getlasterror':
    sp=uc.reg_read(UC_X86_REG_RSP)
    if not (stack<=sp<=stack+0x200000-8 or (state.get('synthetic_second_d3d12_device') and child_stack<=sp<=child_stack+0x200000-8)):state['stop']={'kind':'unsafe_fake_last_error'};uc.emu_stop();return
    uc.reg_write(UC_X86_REG_RAX,struct.unpack('<I',bytes(uc.mem_read(teb+0x68,4)))[0]);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and state.get('active_crt_initializer') and imports[addr].lower()=='kernel32.dll!freelibrary':
    sp=uc.reg_read(UC_X86_REG_RSP);handle=uc.reg_read(UC_X86_REG_RCX)
    if not stack<=sp<=stack+0x200000-8 or handle!=0x7b0000000000 or not state.get('fake_kernel32_handle'):state['stop']={'kind':'unsafe_fake_freelibrary'};uc.emu_stop();return
    state['fake_kernel32_released']=True;uc.reg_write(UC_X86_REG_RAX,1);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and imports[addr].lower() in ('kernel32.dll!tlsalloc','kernel32.dll!tlssetvalue','kernel32.dll!tlsgetvalue'):
    sp=uc.reg_read(UC_X86_REG_RSP);short=imports[addr].lower().split('!')[-1];slots=state.setdefault('fake_dynamic_tls',{})
    if not stack<=sp<=stack+0x200000-8:state['stop']={'kind':'unsafe_fake_tls_stack'};uc.emu_stop();return
    if short=='tlsalloc':
     index=64+len(slots)
     if index>=1088:state['stop']={'kind':'fake_tls_limit'};uc.emu_stop();return
     slots[str(index)]=0;result=index
    else:
     index=uc.reg_read(UC_X86_REG_RCX)
     if str(index) not in slots:state['stop']={'kind':'unknown_fake_tls_slot','index':index};uc.emu_stop();return
     if short=='tlssetvalue':slots[str(index)]=uc.reg_read(UC_X86_REG_RDX);result=1
     else:result=slots[str(index)];uc.mem_write(teb+0x68,struct.pack('<I',0))
    state.setdefault('fake_dynamic_tls_calls',[]).append({'api':short,'index':index,'result':hex(result)});uc.reg_write(UC_X86_REG_RAX,result);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and state.get('active_crt_initializer') and imports[addr].lower()=='api-ms-win-crt-locale-l1-1-0.dll!_create_locale':
    sp=uc.reg_read(UC_X86_REG_RSP);category=uc.reg_read(UC_X86_REG_RCX);ptr=uc.reg_read(UC_X86_REG_RDX)
    if not stack<=sp<=stack+0x200000-8 or category!=0 or not base+0x32c84000<=ptr<base+0x33534000-2 or bytes(uc.mem_read(ptr,2))!=b'C\0':state['stop']={'kind':'unsupported_fake_locale_create'};uc.emu_stop();return
    result=exception_mem+0x5200;state['fake_c_locale']=hex(result);uc.reg_write(UC_X86_REG_RAX,result);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and state.get('virtual_sku_config') and imports[addr].lower()=='api-ms-win-crt-stdio-l1-1-0.dll!__stdio_common_vsnprintf_s':
    sp=uc.reg_read(UC_X86_REG_RSP);options=uc.reg_read(UC_X86_REG_RCX);dst=uc.reg_read(UC_X86_REG_RDX);size=uc.reg_read(UC_X86_REG_R8);limit=uc.reg_read(UC_X86_REG_R9)
    if stack<=sp<=stack+0x200000-0x40 and options==0x24 and size==0x20 and limit==0xffffffffffffffff and base+0x33534000<=dst<=base+0x392a6be1-size:
     fmt,locale,va=struct.unpack('<QQQ',bytes(uc.mem_read(sp+0x28,24)))
     if fmt!=0x172d2c5d8 or locale or not stack<=va<=stack+0x200000-24:state['stop']={'kind':'unsupported_virtual_sku_format_args'};uc.emu_stop();return
     ptr,a1,a2=struct.unpack('<QqQ',bytes(uc.mem_read(va,24)));a1=ctypes.c_int32(a1).value;a2=ctypes.c_int32(a2).value
     if not base+0x32c84000<=ptr<=base+0x392a6be1-256:state['stop']={'kind':'unsupported_virtual_sku_format_strings'};uc.emu_stop();return
     raw=bytes(uc.mem_read(ptr,256));end=raw.find(b'\0')
     if end<0:state['stop']={'kind':'unsupported_virtual_sku_format_strings'};uc.emu_stop();return
     value=raw[:end]+f' #{a1}/{a2}'.encode('ascii')
     if len(value)>=size or any(dst<point+0x40 and point<dst+size for point in watch_points):state['stop']={'kind':'unsupported_virtual_sku_format_destination'};uc.emu_stop();return
     uc.mem_write(dst,value+b'\0');uc.reg_write(UC_X86_REG_RAX,len(value));uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
    if stack<=sp<=stack+0x200000-0x40 and options==0x24 and size==0x100 and limit==0xffffffffffffffff and stack<=dst<=stack+0x200000-size:
     fmt,locale,va=struct.unpack('<QQQ',bytes(uc.mem_read(sp+0x28,24)))
     if fmt!=0x172cab030 or locale or not stack<=va<=stack+0x200000-8:state['stop']={'kind':'unsupported_virtual_sku_format_args'};uc.emu_stop();return
     ptr=struct.unpack('<Q',uc.mem_read(va,8))[0]
     if not base+0x32c84000<=ptr<=base+0x392a6be1-256:state['stop']={'kind':'unsupported_virtual_sku_format_strings'};uc.emu_stop();return
     data=bytes(uc.mem_read(ptr,256));end=data.find(b'\0')
     if end<0 or end+len(b'_image')>=size:state['stop']={'kind':'unsupported_virtual_sku_format_truncation'};uc.emu_stop();return
     value=data[:end]+b'_image';uc.mem_write(dst,value+b'\0');uc.reg_write(UC_X86_REG_RAX,len(value));uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
    if stack<=sp<=stack+0x200000-0x40 and options==0x24 and size==0x80 and limit==0xffffffffffffffff and base+0x33534000<=dst<=base+0x392a6be1-size:
     fmt,locale,va=struct.unpack('<QQQ',bytes(uc.mem_read(sp+0x28,24)))
     if fmt!=0x172d2b6d0 or locale or not stack<=va<=stack+0x200000-24:state['stop']={'kind':'unsupported_virtual_sku_format_args'};uc.emu_stop();return
     strings=[]
     for ptr in struct.unpack('<3Q',bytes(uc.mem_read(va,24))):
      if not (base+0x32c84000<=ptr<=base+0x392a6be1-256 or stack<=ptr<=stack+0x200000-256):break
      data=bytes(uc.mem_read(ptr,256));end=data.find(b'\0')
      if end<0:break
      strings.append(data[:end])
     if len(strings)!=3:state['stop']={'kind':'unsupported_virtual_sku_format_strings'};uc.emu_stop();return
     value=strings[0]+b'_'+strings[1]+b'@'+strings[2]
     if len(value)>=size or any(dst<point+0x40 and point<dst+size for point in watch_points):state['stop']={'kind':'unsupported_virtual_sku_format_destination'};uc.emu_stop();return
     uc.mem_write(dst,value+b'\0');uc.reg_write(UC_X86_REG_RAX,len(value));uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
    if stack<=sp<=stack+0x200000-0x40 and options==0x24 and size==8 and limit==0xffffffffffffffff and stack<=dst<=stack+0x200000-size:
     fmt,locale,va=struct.unpack('<QQQ',bytes(uc.mem_read(sp+0x28,24)))
     if fmt!=0x172d27960 or locale or not stack<=va<=stack+0x200000-8:state['stop']={'kind':'unsupported_virtual_sku_format_args'};uc.emu_stop();return
     number=struct.unpack('<i',bytes(uc.mem_read(va,4)))[0];value=f'{number:07d}'.encode('ascii')
     if len(value)>=size:state['stop']={'kind':'unsupported_virtual_sku_format_truncation'};uc.emu_stop();return
     uc.mem_write(dst,value+b'\0');uc.reg_write(UC_X86_REG_RAX,len(value));uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
    if stack<=sp<=stack+0x200000-0x40 and options==0x24 and size==0xa0 and limit==0xffffffffffffffff and base+0x33534000<=dst<=base+0x392a6be1-size:
     fmt,locale,va=struct.unpack('<QQQ',bytes(uc.mem_read(sp+0x28,24)))
     if fmt!=0x172d2bbe8 or locale or not stack<=va<=stack+0x200000-32:state['stop']={'kind':'unsupported_virtual_sku_format_args'};uc.emu_stop();return
     strings=[]
     for ptr in struct.unpack('<4Q',bytes(uc.mem_read(va,32))):
      if not (base+0x32c84000<=ptr<=base+0x392a6be1-256 or stack<=ptr<=stack+0x200000-256):break
      data=bytes(uc.mem_read(ptr,256));end=data.find(b'\0')
      if end<0:break
      strings.append(data[:end])
     if len(strings)!=4:state['stop']={'kind':'unsupported_virtual_sku_format_strings'};uc.emu_stop();return
     value=strings[0]+b'_'+strings[1]+b'@'+strings[2]+b'@'+strings[3]
     if len(value)>=size or any(dst<point+0x40 and point<dst+size for point in watch_points):state['stop']={'kind':'unsupported_virtual_sku_format_destination'};uc.emu_stop();return
     uc.mem_write(dst,value+b'\0');uc.reg_write(UC_X86_REG_RAX,len(value));uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
    if not stack<=sp<=stack+0x200000-0x40 or options!=0x24 or size!=32 or limit!=0xffffffffffffffff or not tls_block<=dst<=tls_block+0x100000-size:state['stop']={'kind':'unsupported_virtual_sku_format'};uc.emu_stop();return
    fmt,locale,va=struct.unpack('<QQQ',bytes(uc.mem_read(sp+0x28,24)))
    if fmt!=0x172d2bc08 or locale or not stack<=va<=stack+0x200000-64:state['stop']={'kind':'unsupported_virtual_sku_format_args'};uc.emu_stop();return
    values=[v&0xffffffff for v in struct.unpack('<8Q',bytes(uc.mem_read(va,64)))];value=':'.join(f'{v:02X}' for v in values[:6])+':'+''.join(f'{v:02X}' for v in values[6:])
    if len(value)>=size:state['stop']={'kind':'unsupported_virtual_sku_format_truncation'};uc.emu_stop();return
    uc.mem_write(dst,value.encode('ascii')+b'\0');uc.reg_write(UC_X86_REG_RAX,len(value));uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and state.get('dynamic_worker_experiment') and imports[addr].lower()=='api-ms-win-crt-stdio-l1-1-0.dll!__stdio_common_vsnwprintf_s':
    sp=uc.reg_read(UC_X86_REG_RSP);options=uc.reg_read(UC_X86_REG_RCX);dst=uc.reg_read(UC_X86_REG_RDX);size=uc.reg_read(UC_X86_REG_R8);limit=uc.reg_read(UC_X86_REG_R9)
    if not child_stack<=sp<=child_stack+0x200000-0x40 or options!=0x24 or not 1<=size<=4096 or limit!=0xffffffffffffffff or not child_stack<=dst<=child_stack+0x200000-2*size:state['stop']={'kind':'unsupported_fake_worker_format'};uc.emu_stop();return
    fmt,locale,va=struct.unpack('<QQQ',bytes(uc.mem_read(sp+0x28,24)))
    if fmt==0x172d2b580 and locale==0 and bytes(uc.mem_read(fmt,18))=='Marathon\0'.encode('utf-16le') and size>=9:
     uc.mem_write(dst,'Marathon\0'.encode('utf-16le'));state.setdefault('fake_worker_operations',[]).append({'operation':'format literal','value':'Marathon','host_api_called':False});uc.reg_write(UC_X86_REG_RAX,8);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
    count=2 if fmt==0x172d2f400 else 3 if fmt==0x172d2f428 else 0
    if not count or locale or not child_stack<=va<=child_stack+0x200000-8*count:state['stop']={'kind':'unsupported_fake_worker_format_args'};uc.emu_stop();return
    pointers=struct.unpack('<'+'Q'*count,bytes(uc.mem_read(va,8*count)));parts=[]
    for ptr in pointers:
     if not (child_stack<=ptr<=child_stack+0x200000-512 or exception_mem<=ptr<=exception_mem+0x10000-512 or base+0x32c84000<=ptr<=base+0x392a6be1-512):break
     raw=bytes(uc.mem_read(ptr,512));end=next((i for i in range(0,510,2) if raw[i:i+2]==b'\0\0'),-1)
     if end<0:break
     parts.append(raw[:end].decode('utf-16le'))
    if len(parts)!=count:state['stop']={'kind':'unsupported_fake_worker_format_strings'};uc.emu_stop();return
    result=parts[0]+'\\'+parts[1]+(parts[2] if count==3 else '');raw=result.encode('utf-16le')+b'\0\0'
    if len(raw)>size*2:state['stop']={'kind':'unsupported_fake_worker_format_truncation'};uc.emu_stop();return
    uc.mem_write(dst,raw);state.setdefault('fake_worker_operations',[]).append({'operation':'format system path','value':result,'host_api_called':False});uc.reg_write(UC_X86_REG_RAX,len(result));uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and state.get('dynamic_worker_experiment') and imports[addr].lower()=='kernel32.dll!setthreadpriority':
    sp=uc.reg_read(UC_X86_REG_RSP);handle=uc.reg_read(UC_X86_REG_RCX);priority=uc.reg_read(UC_X86_REG_RDX)&0xffffffff
    if not child_stack<=sp<=child_stack+0x200000-8 or handle!=0xfffffffffffffffe or priority!=0xffffffff:state['stop']={'kind':'unsupported_fake_thread_priority'};uc.emu_stop();return
    state.setdefault('fake_worker_operations',[]).append({'operation':'SetThreadPriority','priority':-1,'host_api_called':False});uc.reg_write(UC_X86_REG_RAX,1);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and imports[addr].lower()=='api-ms-win-crt-utility-l1-1-0.dll!srand':
    sp=uc.reg_read(UC_X86_REG_RSP);seed=uc.reg_read(UC_X86_REG_RCX)&0xffffffff
    if not stack<=sp<=stack+0x200000-8:state['stop']={'kind':'unsafe_fake_srand'};uc.emu_stop();return
    state['fake_rand_seed']=seed;state.setdefault('fake_constructor_api_calls',[]).append({'import':imports[addr],'seed':seed,'assumption':'single synthetic CRT random state'});uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and imports[addr].lower()=='api-ms-win-crt-utility-l1-1-0.dll!rand':
    sp=uc.reg_read(UC_X86_REG_RSP)
    if not stack<=sp<=stack+0x200000-8:state['stop']={'kind':'unsafe_fake_rand'};uc.emu_stop();return
    seed=(state.get('fake_rand_seed',1)*214013+2531011)&0xffffffff;state['fake_rand_seed']=seed;result=(seed>>16)&0x7fff;state.setdefault('fake_rand_values',[]).append(result);uc.reg_write(UC_X86_REG_RAX,result);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and imports[addr].lower()=='kernel32.dll!setlasterror':
    sp=uc.reg_read(UC_X86_REG_RSP);value=uc.reg_read(UC_X86_REG_RCX)&0xffffffff
    if not (stack<=sp<=stack+0x200000-8 or (state.get('synthetic_second_d3d12_device') and child_stack<=sp<=child_stack+0x200000-8)):state['stop']={'kind':'unsafe_fake_last_error'};uc.emu_stop();return
    uc.mem_write(teb+0x68,struct.pack('<I',value));state.setdefault('fake_last_error_values',[]).append(hex(value));uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and state.get('active_crt_initializer') and imports[addr].lower() in ('api-ms-win-crt-math-l1-1-0.dll!cosf','api-ms-win-crt-math-l1-1-0.dll!sinf'):
    import math
    sp=uc.reg_read(UC_X86_REG_RSP);old=uc.reg_read(UC_X86_REG_XMM0);value=struct.unpack('<f',struct.pack('<I',old&0xffffffff))[0]
    if not stack<=sp<=stack+0x200000-8 or not math.isfinite(value):state['stop']={'kind':'unsupported_fake_cosf'};uc.emu_stop();return
    api=imports[addr].lower().split('!')[-1];result=struct.unpack('<I',struct.pack('<f',math.cos(value) if api=='cosf' else math.sin(value)))[0];uc.reg_write(UC_X86_REG_XMM0,(old&~0xffffffff)|result);state.setdefault('fake_math_calls',[]).append({'api':api,'input_bits':hex(old&0xffffffff),'result_bits':hex(result),'note':'synthetic double-precision result rounded to float'});uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.stub_veh and imports[addr].lower()=='kernel32.dll!addvectoredexceptionhandler':
    sp=uc.reg_read(UC_X86_REG_RSP)
    if not stack<=sp<=stack+0x200000-8:state['stop']={'kind':'unsafe_import_stack','rip':hex(addr)};uc.emu_stop();return
    retaddr=struct.unpack('<Q',uc.mem_read(sp,8))[0];state.setdefault('fake_veh_registrations',[]).append({'first':hex(uc.reg_read(UC_X86_REG_RCX)),'handler':hex(uc.reg_read(UC_X86_REG_RDX)),'return_address':hex(retaddr)})
    uc.reg_write(UC_X86_REG_RAX,0x760000000000);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,retaddr);return
   if a.stub_virtualprotect and (state.get('in_fake_worker') or a.stub_parent_virtualprotect and state.get('in_fake_parent')) and imports[addr].lower()=='kernel32.dll!virtualprotect':
    sp=uc.reg_read(UC_X86_REG_RSP);oldptr=uc.reg_read(UC_X86_REG_R9)
    stack_base=child_stack if state.get('in_fake_worker') else stack
    if not stack_base<=sp<=stack_base+0x200000-8 or not stack_base<=oldptr<=stack_base+0x200000-4:state['stop']={'kind':'unsafe_virtualprotect_stub'};uc.emu_stop();return
    retaddr=struct.unpack('<Q',uc.mem_read(sp,8))[0];state.setdefault('fake_virtualprotect',[]).append({'phase':'worker' if state.get('in_fake_worker') else 'parent','address':hex(uc.reg_read(UC_X86_REG_RCX)),'length':uc.reg_read(UC_X86_REG_RDX),'protection':hex(uc.reg_read(UC_X86_REG_R8))})
    uc.mem_write(oldptr,struct.pack('<I',2));uc.reg_write(UC_X86_REG_RAX,1);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,retaddr);return
   if a.stub_worker_wait and state.get('in_fake_parent') and imports[addr].lower()=='kernel32.dll!waitformultipleobjects':
    sp=uc.reg_read(UC_X86_REG_RSP);arr=uc.reg_read(UC_X86_REG_RDX);count=uc.reg_read(UC_X86_REG_RCX)
    handle=struct.unpack('<Q',uc.mem_read(arr,8))[0] if stack<=arr<=stack+0x200000-8 else 0
    if count!=1 or not stack<=sp<=stack+0x200000-8 or handle not in (1,2) or handle==2 and not state.get('fake_second_worker_outcome'):
     state['stop']={'kind':'unexpected_worker_wait','count':count,'handle_array':hex(arr)};uc.emu_stop();return
    retaddr=struct.unpack('<Q',uc.mem_read(sp,8))[0];state.setdefault('fake_worker_waits',[]).append({'count':count,'handle':hex(handle),'wait_all':hex(uc.reg_read(UC_X86_REG_R8)),'timeout':hex(uc.reg_read(UC_X86_REG_R9))})
    uc.reg_write(UC_X86_REG_RAX,0);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,retaddr);return
   if a.model_crt_initterm_e and imports[addr].lower() in ('kernel32.dll!waitforsingleobject','kernel32.dll!waitforsingleobjectex') and hex(uc.reg_read(UC_X86_REG_RCX)) in state.get('fake_semaphores',{}):
    sp=uc.reg_read(UC_X86_REG_RSP);key=hex(uc.reg_read(UC_X86_REG_RCX));sem=state['fake_semaphores'][key];name=imports[addr].lower()
    if not stack<=sp<=stack+0x200000-8 or uc.reg_read(UC_X86_REG_RDX)!=0xffffffff or name.endswith('ex') and uc.reg_read(UC_X86_REG_R8)!=0 or sem['count']<=0:state['stop']={'kind':'unsupported_fake_semaphore_wait','handle':key,'count':sem['count']};uc.emu_stop();return
    sem['count']-=1;state.setdefault('fake_semaphore_operations',[]).append({'operation':'wait','handle':key,'count':sem['count'],'assumption':'uncontended synthetic single thread'});uc.reg_write(UC_X86_REG_RAX,0);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_crt_initterm_e and imports[addr].lower() in ('kernel32.dll!waitforsingleobject','kernel32.dll!releasemutex') and any(h['handle']==hex(uc.reg_read(UC_X86_REG_RCX)) for h in state.get('fake_mutex_handles',[])):
    sp=uc.reg_read(UC_X86_REG_RSP);handle=uc.reg_read(UC_X86_REG_RCX);name=imports[addr].lower().split('!')[-1];mutex=next(h for h in state['fake_mutex_handles'] if h['handle']==hex(handle));depth=mutex.get('depth',int(bool(mutex['initial_owner'])))
    if not stack<=sp<=stack+0x200000-8 or name=='waitforsingleobject' and uc.reg_read(UC_X86_REG_RDX)!=0xffffffff or name=='releasemutex' and depth==0:state['stop']={'kind':'unsupported_fake_mutex_wait','handle':hex(handle)};uc.emu_stop();return
    mutex['depth']=depth+(1 if name=='waitforsingleobject' else -1);state.setdefault('fake_mutex_operations',[]).append({'operation':name,'handle':hex(handle),'depth':mutex['depth'],'single_thread_assumption':True});uc.reg_write(UC_X86_REG_RAX,0 if name=='waitforsingleobject' else 1);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.stub_worker_wait and state.get('in_fake_parent') and imports[addr].lower()=='kernel32.dll!waitforsingleobject':
    sp=uc.reg_read(UC_X86_REG_RSP);handle=uc.reg_read(UC_X86_REG_RCX)
    if handle!=2 or not state.get('fake_second_worker_outcome') or not stack<=sp<=stack+0x200000-8:
     state['stop']={'kind':'unexpected_single_worker_wait','handle':hex(handle)};uc.emu_stop();return
    retaddr=struct.unpack('<Q',uc.mem_read(sp,8))[0];state.setdefault('fake_worker_waits',[]).append({'count':1,'handle':hex(handle),'timeout':hex(uc.reg_read(UC_X86_REG_RDX))})
    uc.reg_write(UC_X86_REG_RAX,0);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,retaddr);return
   if a.stub_worker_wait and state.get('in_fake_parent') and imports[addr].lower()=='kernel32.dll!closehandle':
    sp=uc.reg_read(UC_X86_REG_RSP);handle=uc.reg_read(UC_X86_REG_RCX)
    if handle not in (1,2) or not any(x['handle']==hex(handle) for x in state.get('fake_worker_waits',[])) or not stack<=sp<=stack+0x200000-8:
     state['stop']={'kind':'unexpected_worker_close','handle':hex(handle)};uc.emu_stop();return
    retaddr=struct.unpack('<Q',uc.mem_read(sp,8))[0];state.setdefault('fake_worker_closes',[]).append({'handle':hex(handle)})
    uc.reg_write(UC_X86_REG_RAX,1);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,retaddr);return
   if a.stub_worker_cache and state.get('fake_second_worker') and state.get('in_fake_worker') and imports[addr].lower() in ('kernel32.dll!getcurrentprocess','kernel32.dll!flushinstructioncache'):
    sp=uc.reg_read(UC_X86_REG_RSP);calls=state.setdefault('fake_worker_cache_calls',[])
    if len(calls)>=1000 or not child_stack<=sp<=child_stack+0x200000-8:state['stop']={'kind':'unsafe_worker_cache_stub'};uc.emu_stop();return
    name=imports[addr];retaddr=struct.unpack('<Q',uc.mem_read(sp,8))[0];calls.append({'import':name,'address':hex(uc.reg_read(UC_X86_REG_RDX)),'length':uc.reg_read(UC_X86_REG_R8)})
    uc.reg_write(UC_X86_REG_RAX,0xffffffffffffffff if name.lower().endswith('getcurrentprocess') else 1);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,retaddr);return
   if a.stub_crt_clock and state.get('fake_second_worker_outcome') and state.get('in_fake_parent') and imports[addr].lower() in ('kernel32.dll!getsystemtimeasfiletime','kernel32.dll!getsystemtimepreciseasfiletime','kernel32.dll!getcurrentprocessid','kernel32.dll!getcurrentthreadid','kernel32.dll!gettickcount','kernel32.dll!gettickcount64','kernel32.dll!queryperformancecounter'):
    sp=uc.reg_read(UC_X86_REG_RSP);name=imports[addr].lower();calls=state.setdefault('fake_crt_clock_calls',[])
    if len(calls)>=100 or not stack<=sp<=stack+0x200000-8:state['stop']={'kind':'unsafe_crt_clock_stub'};uc.emu_stop();return
    ptr=uc.reg_read(UC_X86_REG_RCX)
    if name.endswith(('getsystemtimeasfiletime','getsystemtimepreciseasfiletime','queryperformancecounter')):
     if not stack<=ptr<=stack+0x200000-8:state['stop']={'kind':'unsafe_crt_clock_pointer','address':hex(ptr)};uc.emu_stop();return
     uc.mem_write(ptr,struct.pack('<Q',0x01d0000000000000 if 'systemtime' in name else 0x123456789))
    if name.endswith('queryperformancecounter'):uc.reg_write(UC_X86_REG_RAX,1)
    elif name.endswith('getcurrentprocessid'):uc.reg_write(UC_X86_REG_RAX,0x1234)
    elif name.endswith('getcurrentthreadid'):uc.reg_write(UC_X86_REG_RAX,2)
    elif name.endswith(('gettickcount','gettickcount64')):uc.reg_write(UC_X86_REG_RAX,0x12345678)
    retaddr=struct.unpack('<Q',uc.mem_read(sp,8))[0];calls.append({'import':imports[addr],'output_pointer':hex(ptr)})
    uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,retaddr);return
   state['import_arguments']={name:hex(uc.reg_read(reg)) for name,reg in (('rcx',UC_X86_REG_RCX),('rdx',UC_X86_REG_RDX),('r8',UC_X86_REG_R8),('r9',UC_X86_REG_R9),('rsp',UC_X86_REG_RSP))}
   state['stop']={'kind':'import_marker','import':imports[addr],'rip':hex(addr)};uc.emu_stop();return
  if addr==handler_ret and a.model_veh_exceptions:state['stop']={'kind':'synthetic_handler_return'};uc.emu_stop();return
  if addr==ret:state['stop']={'kind':'synthetic_return'};uc.emu_stop();return
  if a.stop_at_parent_aes and state.get('in_fake_parent') and addr==0x17004d360:
   rcx=uc.reg_read(UC_X86_REG_RCX);rdx=uc.reg_read(UC_X86_REG_RDX);state['parent_aes_input']={'data':hex(uc.reg_read(UC_X86_REG_R8)),'length':uc.reg_read(UC_X86_REG_R9),'key':bytes(uc.mem_read(rcx,16)).hex(),'counter':bytes(uc.mem_read(rdx,16)).hex()};state['stop']={'kind':'parent_aes_checkpoint','rip':hex(addr)};uc.emu_stop();return
  if a.parent_aes_reference and state.get('in_fake_parent') and addr==0x17004d360:
   from Crypto.Cipher import AES
   i=state.get('parent_aes_completed',0);sp=uc.reg_read(UC_X86_REG_RSP);data=uc.reg_read(UC_X86_REG_R8);length=uc.reg_read(UC_X86_REG_R9)
   in_data=i>=len(parent_reference) and a.allow_parent_data and base+0x33534000<=data<=base+0x33534000+0x5d72be1-length
   in_vmp=i>=len(parent_reference) and a.allow_parent_vmp and base+0x39600000<=data<=base+0x39600000+0x676200-length
   in_aux=i>=len(parent_reference) and a.allow_parent_vmp and base+0x39c77000<=data<=base+0x39c77000+0x22c00-length
   if not stack<=sp<=stack+0x200000-8 or not 0<length<=16*1024*1024 or not (i<len(parent_reference) and base+0x1000<=data<=base+0x1000+851977728-length or in_data or in_vmp or in_aux):
    state['stop']={'kind':'parent_aes_guard','index':i,'data':hex(data),'length':length};uc.emu_stop();return
   key=bytes(uc.mem_read(uc.reg_read(UC_X86_REG_RCX),16));counter=bytes(uc.mem_read(uc.reg_read(UC_X86_REG_RDX),16));before=bytes(uc.mem_read(data,length))
   if not in_data and not in_vmp and not in_aux:
    event,ctx=parent_reference[i];checks={'data':data==int(event['data'],16),'length':length==event['length'],'key':key==bytes.fromhex(ctx['rcx_bytes'])[:16],'counter':counter==bytes.fromhex(ctx['rdx_bytes'])[:16],'before':hashlib.sha256(before).hexdigest()==event['before_sha256']}
    if not all(checks.values()):state['stop']={'kind':'parent_aes_reference_mismatch','index':i,'failed':[k for k,v in checks.items() if not v]};uc.emu_stop();return
   elif in_data and (len(state.setdefault('parent_data_events',[]))>=200000 or state.get('parent_data_bytes',0)+length>128*1024*1024) or (in_vmp or in_aux) and len(state.setdefault('parent_vmp_events',[]))>=16:
    state['stop']={'kind':'parent_data_limit'};uc.emu_stop();return
   after=AES.new(key,AES.MODE_CTR,nonce=b'',initial_value=int.from_bytes(counter,'big')).encrypt(before)
   if not in_data and not in_vmp and not in_aux and hashlib.sha256(after).hexdigest()!=event['after_sha256']:state['stop']={'kind':'parent_aes_output_mismatch','index':i};uc.emu_stop();return
   uc.mem_write(data,after)
   if in_data:
    events=state['parent_data_events'];row={'data':hex(data),'length':length,'key':key.hex(),'counter':counter.hex(),'before_sha256':hashlib.sha256(before).hexdigest(),'after_sha256':hashlib.sha256(after).hexdigest()}
    if len(events)<4 and length<=65536:row['input']=before.hex()
    events.append(row);state['parent_data_bytes']=state.get('parent_data_bytes',0)+length
   elif in_vmp or in_aux:
    state['parent_vmp_events'].append({'section':'.vmp0' if in_vmp else '_RDATA','data':hex(data),'length':length,'key':key.hex(),'counter':counter.hex(),'before_sha256':hashlib.sha256(before).hexdigest(),'after_sha256':hashlib.sha256(after).hexdigest(),'input_prefix':before[:4096].hex(),'output_prefix_sha256':hashlib.sha256(after[:4096]).hexdigest()})
   else:state['parent_aes_completed']=i+1;state['parent_aes_bytes']=state.get('parent_aes_bytes',0)+length
   uc.reg_write(UC_X86_REG_RAX,(length-1)%16);uc.reg_write(UC_X86_REG_RDX,((length-1)%16)+1);uc.reg_write(UC_X86_REG_RCX,0x2b992ddfa2320000);uc.reg_write(UC_X86_REG_R8,sp-0xc8);uc.reg_write(UC_X86_REG_R9,4);uc.reg_write(UC_X86_REG_R10,0xac);uc.reg_write(UC_X86_REG_R11,sp-8);uc.reg_write(UC_X86_REG_EFLAGS,0x246)
   if not in_data and not in_vmp and not in_aux and a.parent_aes_stop_after is not None and i+1==a.parent_aes_stop_after or in_data and a.parent_data_stop_after is not None and len(state['parent_data_events'])==a.parent_data_stop_after or in_vmp and a.stop_after_vmp:
    uc.reg_write(UC_X86_REG_RIP,0x17004d64e);state['stop']={'kind':'parent_vmp_checkpoint' if in_vmp else 'parent_data_checkpoint' if in_data else 'parent_aes_checkpoint','completed':len(state['parent_vmp_events']) if in_vmp else len(state['parent_data_events']) if in_data else i+1,'rip':'0x17004d64e'};uc.emu_stop();return
   retaddr=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,retaddr);return
  if a.trace_aes and state.get('in_fake_worker') and addr==0x17004d360:
   samples=state.setdefault('aes_entries',[])
   if len(samples)<1024:
    rcx=uc.reg_read(UC_X86_REG_RCX);rdx=uc.reg_read(UC_X86_REG_RDX)
    samples.append({'rcx':hex(rcx),'rdx':hex(rdx),'data':hex(uc.reg_read(UC_X86_REG_R8)),'length':uc.reg_read(UC_X86_REG_R9),'key':bytes(uc.mem_read(rcx,16)).hex(),'counter':bytes(uc.mem_read(rdx,16)).hex()})
   if a.accelerate_worker_aes and not (a.native_final_aes and state.get('aes_completed',0)==a.stop_after_aes-1) and not (a.native_aes_every and (state.get('aes_completed',0)+1)%a.native_aes_every==0) and state.get('aes_completed',0)+1!=a.native_aes_at:
    from Crypto.Cipher import AES
    sp=uc.reg_read(UC_X86_REG_RSP);data=uc.reg_read(UC_X86_REG_R8);length=uc.reg_read(UC_X86_REG_R9);done=state.get('aes_completed',0)
    if sp!=child_stack+0x1fef68 or not 0<length<=16*1024*1024 or not base+0x32c84000<=data<=base+0x32c84000+9107968-length or done>=70000:
     state['stop']={'kind':'worker_aes_guard','data':hex(data),'length':length,'rsp':hex(sp)};uc.emu_stop();return
    key=bytes(uc.mem_read(uc.reg_read(UC_X86_REG_RCX),16));counter=bytes(uc.mem_read(uc.reg_read(UC_X86_REG_RDX),16));before=bytes(uc.mem_read(data,length));after=AES.new(key,AES.MODE_CTR,nonce=b'',initial_value=int.from_bytes(counter,'big')).encrypt(before);uc.mem_write(data,after)
    state.setdefault('fast_aes_events',[]).append({'index':done,'data':hex(data),'length':length,'before_sha256':hashlib.sha256(before).hexdigest(),'after_sha256':hashlib.sha256(after).hexdigest()});state['aes_completed']=done+1
    uc.reg_write(UC_X86_REG_RAX,(length-1)%16);uc.reg_write(UC_X86_REG_RDX,((length-1)%16)+1);uc.reg_write(UC_X86_REG_RCX,0x2b992ddfa2320000);uc.reg_write(UC_X86_REG_R8,sp-0xc8);uc.reg_write(UC_X86_REG_R9,4);uc.reg_write(UC_X86_REG_R10,0xac);uc.reg_write(UC_X86_REG_R11,sp-8);uc.reg_write(UC_X86_REG_EFLAGS,0x246)
    if a.stop_after_aes is not None and done+1==a.stop_after_aes:
     uc.reg_write(UC_X86_REG_RIP,0x17004d64e);state['stop']={'kind':'aes_checkpoint','completed':a.stop_after_aes,'rip':'0x17004d64e'};uc.emu_stop();return
    retaddr=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,retaddr);return
  if a.trace_aes and state.get('in_fake_worker') and addr==0x17004d64e:
   state['aes_completed']=state.get('aes_completed',0)+1
   if a.stop_after_aes is not None and state['aes_completed']==a.stop_after_aes:
    state['stop']={'kind':'aes_checkpoint','completed':a.stop_after_aes,'rip':hex(addr)};uc.emu_stop();return
  try:op=bytes(uc.mem_read(addr,min(size,4)))
  except UcError:return
  if op.startswith((b'\x0f\x31',b'\x0f\x01\xf9')):
   state['timestamp_instructions']=state.get('timestamp_instructions',0)+1;state.setdefault('first_timestamp_instruction',hex(addr))
   if a.fixed_tsc:
    synthetic=0x100000+1000*state['timestamp_instructions'];uc.reg_write(UC_X86_REG_RAX,synthetic&0xffffffff);uc.reg_write(UC_X86_REG_RDX,synthetic>>32)
    if op.startswith(b'\x0f\x01\xf9'):uc.reg_write(UC_X86_REG_RCX,0)
    uc.reg_write(UC_X86_REG_RIP,addr+(3 if op.startswith(b'\x0f\x01\xf9') else 2));return
  if op.startswith((b'\x0f\x05',b'\x0f\x34',b'\xcd',b'\xcc')):state['stop']={'kind':'host_or_breakpoint','address':hex(addr),'bytes':op.hex()};uc.emu_stop()
 def intr(uc,num,user):state['stop']={'kind':'interrupt','number':num,'address':hex(uc.reg_read(UC_X86_REG_RIP))};uc.emu_stop()
 def write(uc,access,addr,size,value,user):
  if a.watch_stack_address is not None and addr<=a.watch_stack_address+7 and a.watch_stack_address<addr+size:
   events=state.setdefault('watched_stack_writes',[])
   if len(events)>=1000:del events[0]
   events.append({'address':hex(addr),'size':size,'value':hex(value&((1<<(size*8))-1)),'rip':hex(uc.reg_read(UC_X86_REG_RIP)),'recent':list(recent)[-20:]})
  for module in state.get('synthetic_peb_modules',[]):
   if int(module['base'],16)<=addr and addr+size<=int(module['base'],16)+module['size']:
    events=state.setdefault('synthetic_system_writes',[])
    if len(events)<1000:events.append({'module':module['name'],'address':hex(addr),'size':size,'before':bytes(uc.mem_read(addr,size)).hex(),'value':hex(value&((1<<(size*8))-1)),'rip':hex(uc.reg_read(UC_X86_REG_RIP))})
    break
  if base<=addr<base+pe.OPTIONAL_HEADER.SizeOfImage:
   state['image_writes']+=1;state.setdefault('first_image_write',{'address':hex(addr),'rip':hex(uc.reg_read(UC_X86_REG_RIP))})
   if a.trace_second_image_writes and state.get('in_fake_second_worker'):
    events=state.setdefault('second_image_write_events',[])
    if len(events)>=100000:state['second_image_write_truncated']=True
    else:events.append({'address':hex(addr),'size':size,'value':hex(value&((1<<(size*8))-1)),'before':bytes(uc.mem_read(addr,size)).hex(),'rip':hex(uc.reg_read(UC_X86_REG_RIP))})
   if watch_points:
    i=bisect.bisect_right(watch_points,addr)-1
    if i>=0 and addr<watch_points[i]+0x40:
     samples=state.setdefault('registry_writes',[])
     if len(samples)<100000:samples.append({'object':hex(watch_points[i]),'address':hex(addr),'size':size,'value':hex(value),'rip':hex(uc.reg_read(UC_X86_REG_RIP))})
   if a.trace_image_writes:
    samples=state.setdefault('image_write_samples',[])
    if len(samples)<1000:samples.append({'address':hex(addr),'size':size,'value':hex(value),'rip':hex(uc.reg_read(UC_X86_REG_RIP))})
  elif stack<=addr<stack+0x200000 or a.follow_thread and child_stack<=addr<child_stack+0x200000:state['stack_writes']+=1
  elif tls_block<=addr<tls_block+0x100000:state['tls_writes']+=1
  else:state.setdefault('other_write',{'address':hex(addr),'rip':hex(uc.reg_read(UC_X86_REG_RIP))})
 def deliver_fault(fault):
  """Run the registered original handler with an artificial x64 exception record/context."""
  entries=state.setdefault('modeled_faults',[])
  if len(entries)>=(16384 if a.model_crt_initterm_e else 32):state['stop']={'kind':'exception_limit'};return False
  regs=[(0x78,UC_X86_REG_RAX),(0x80,UC_X86_REG_RCX),(0x88,UC_X86_REG_RDX),(0x90,UC_X86_REG_RBX),(0x98,UC_X86_REG_RSP),(0xa0,UC_X86_REG_RBP),(0xa8,UC_X86_REG_RSI),(0xb0,UC_X86_REG_RDI),(0xb8,UC_X86_REG_R8),(0xc0,UC_X86_REG_R9),(0xc8,UC_X86_REG_R10),(0xd0,UC_X86_REG_R11),(0xd8,UC_X86_REG_R12),(0xe0,UC_X86_REG_R13),(0xe8,UC_X86_REG_R14),(0xf0,UC_X86_REG_R15),(0xf8,UC_X86_REG_RIP)]
  original=uc.context_save();ctx=bytearray(0x500);struct.pack_into('<I',ctx,0x30,0x10001f);struct.pack_into('<I',ctx,0x44,uc.reg_read(UC_X86_REG_EFLAGS))
  for off,reg in regs:struct.pack_into('<Q',ctx,off,uc.reg_read(reg))
  before={name:hex(uc.reg_read(reg)) for name,reg in (('rbx',UC_X86_REG_RBX),('rbp',UC_X86_REG_RBP),('rsp',UC_X86_REG_RSP),('rip',UC_X86_REG_RIP))}
  signature=(uc.reg_read(UC_X86_REG_RBX)^uc.reg_read(UC_X86_REG_RBP)^0xd5e1740f6aceb1bb)&0xffffffffffffffff
  table_address=0x173534010+(signature>>32)*16
  try:table_before=bytes(uc.mem_read(table_address,16)).hex();stack_before=bytes(uc.mem_read(uc.reg_read(UC_X86_REG_RSP),16)).hex()
  except UcError:table_before=None;stack_before=None
  rec=bytearray(0x100);struct.pack_into('<I',rec,0,0xc0000005);struct.pack_into('<Q',rec,0x10,fault['rip']);struct.pack_into('<I',rec,0x18,2);struct.pack_into('<Q',rec,0x20,{19:0,20:1,21:8}.get(fault['access'],0));struct.pack_into('<Q',rec,0x28,fault['address'])
  uc.mem_write(exception_mem,struct.pack('<QQ',exception_mem+0x100,exception_mem+0x1000));uc.mem_write(exception_mem+0x100,bytes(rec));uc.mem_write(exception_mem+0x1000,bytes(ctx))
  sp=stack+0xfffd8;uc.mem_write(sp,struct.pack('<Q',handler_ret));uc.reg_write(UC_X86_REG_RSP,sp);uc.reg_write(UC_X86_REG_RCX,exception_mem)
  handler=int(state['fake_veh_registrations'][-1]['handler'],16);state['handling_exception']=True;state['stop']=None
  try:uc.emu_start(handler,0,count=1000000,timeout=a.timeout_ms*1000)
  except UcError as ex:
   if state['stop'] is None:state['stop']={'kind':'handler_unicorn_error','message':str(ex),'rip':hex(uc.reg_read(UC_X86_REG_RIP))}
  state['handling_exception']=False;result=uc.reg_read(UC_X86_REG_RAX)&0xffffffff;handler_stop=state['stop'];modified=bytes(uc.mem_read(exception_mem+0x1000,len(ctx)))
  row={'fault_address':hex(fault['address']),'fault_rip':hex(fault['rip']),'access':fault['access'],'handler':hex(handler),'handler_stop':handler_stop,'handler_result':hex(result),'resume_rip':hex(struct.unpack_from('<Q',modified,0xf8)[0]),'before':before,'signature':hex(signature),'table_address':hex(table_address),'table_before':table_before,'stack_before':stack_before,'after':{name:hex(struct.unpack_from('<Q',modified,off)[0]) for name,off in (('rbx',0x90),('rsp',0x98),('rbp',0xa0),('rip',0xf8))}};entries.append(row)
  if result!=0xffffffff:row['fault_registers']=fault.get('registers');row['fault_recent']=fault.get('recent');row['fault_stack_base']=fault.get('stack_base');row['fault_stack_hex']=fault.get('stack_hex')
  if not handler_stop or handler_stop.get('kind')!='synthetic_handler_return' or result!=0xffffffff:return False
  uc.context_restore(original)
  for off,reg in regs:uc.reg_write(reg,struct.unpack_from('<Q',modified,off)[0])
  uc.reg_write(UC_X86_REG_EFLAGS,struct.unpack_from('<I',modified,0x44)[0]);state['stop']=None;return True
 def invalid_instruction(uc,user):
  if not a.model_crt_initterm_e:return False
  def memory(ptr,n,writing):
   committed=any(lo<=ptr and ptr+n<=hi for lo,hi in state.get('fake_virtual_commits',[]))
   if writing and any(ptr<point+0x40 and point<ptr+n for point in watch_points):return False
   if committed:
    for page in range(ptr&~0xfff,(ptr+n+4095)&~0xfff,4096):
     if page not in pages and not invalid(uc,UC_MEM_WRITE_UNMAPPED if writing else UC_MEM_READ_UNMAPPED,page,1,0,None):return False
    if writing and any(ptr<hi and lo<ptr+n for lo,hi in state.get('fake_virtual_exec_requests',[])):return False
    return True
   valid=(base<=ptr and ptr+n<=base+pe.OPTIONAL_HEADER.SizeOfImage or stack<=ptr and ptr+n<=stack+0x200000 or a.follow_thread and child_stack<=ptr and ptr+n<=child_stack+0x200000 or tls_block<=ptr and ptr+n<=tls_block+0x100000 or exception_mem<=ptr and ptr+n<=exception_mem+0x10000 or 0x790000000000<=ptr and ptr+n<=0x790000000000+state.get('fake_heap_used',0) or not writing and any(int(m['base'],16)<=ptr and ptr+n<=int(m['base'],16)+m['size'] for m in state.get('synthetic_peb_modules',[])))
   return bool(valid)
  try:event=try_avx(uc,uc.reg_read(UC_X86_REG_RIP),15,memory)
  except (UcError,ValueError):return False
  if not event:return False
  state.setdefault('general_avx_events',[]).append(event);return True
 uc.hook_add(UC_HOOK_MEM_INVALID,invalid);uc.hook_add(UC_HOOK_INSN_INVALID,invalid_instruction);uc.hook_add(UC_HOOK_INTR,intr);uc.hook_add(UC_HOOK_MEM_WRITE,write)
 if a.sparse:
  def block(uc,addr,size,user):state['blocks']=state.get('blocks',0)+1;recent.append(hex(addr))
  def host(uc,user):state['stop']={'kind':'host_instruction','address':hex(uc.reg_read(UC_X86_REG_RIP))};uc.emu_stop()
  if not a.fast:uc.hook_add(UC_HOOK_BLOCK,block)
  uc.hook_add(UC_HOOK_CODE,code,None,stub,stub+((len(imports)*16+4095)//4096)*4096-1);uc.hook_add(UC_HOOK_CODE,code,None,ret,ret)
  uc.hook_add(UC_HOOK_INSN,host,None,1,0,UC_X86_INS_SYSCALL);uc.hook_add(UC_HOOK_INSN,host,None,1,0,UC_X86_INS_SYSENTER)
 else:uc.hook_add(UC_HOOK_CODE,code)
 start=time.monotonic()
 try:
  if a.resume_checkpoint:
   state,recent_values=restore_checkpoint(uc,a.resume_checkpoint,checkpoint_identity);recent=collections.deque(recent_values,maxlen=10000);state['stop']=None;pc=uc.reg_read(UC_X86_REG_RIP)
   for start,end in state.get('fake_virtual_commits',[]):
    for lo,hi,_ in uc.mem_regions():
     pages.update(range(max(start,lo)&~0xfff,min(end,hi+1),4096))
   if a.synthetic_system_peb:
    if state.get('synthetic_peb_modules'):raise ValueError('checkpoint already contains the synthetic loader list')
    from synthetic_system_peb import install as install_system_peb
    state['synthetic_peb_modules']=install_system_peb(uc,teb,base,pe.OPTIONAL_HEADER.SizeOfImage)
   if a.synthetic_crypt32_dependency and not a.synthetic_loaded_module_images:raise ValueError('crypt32 experiment requires loaded-module images')
   if a.synthetic_loaded_module_images:
    if not state.get('synthetic_peb_modules') or state.get('synthetic_loaded_module_images'):raise ValueError('loaded-module experiment requires a fresh synthetic PEB')
    names=list(dict.fromkeys(x['name'] for x in state.get('fake_library_loads',[])))
    if a.synthetic_crypt32_dependency and 'crypt32.dll' not in names:names.append('crypt32.dll')
    if any(m['name'] in names for m in state['synthetic_peb_modules']):raise ValueError('loaded-module experiment duplicates mapped modules')
    from synthetic_system_peb import install_loaded_modules
    additions=install_loaded_modules(uc,teb,names);state['synthetic_peb_modules'].extend(additions);state['synthetic_loaded_module_images']={'names':names,'assumption':'prior simulated successful loads backed by local data-only PE images'}
   if a.synthetic_user32_module:
    if not state.get('synthetic_peb_modules') or 'user32.dll' not in state.get('fake_library_handles',{}) or any(m['name']=='user32.dll' for m in state['synthetic_peb_modules']):raise ValueError('user32 experiment requires an existing simulated load and no prior mapping')
    from synthetic_system_peb import install_user32
    state['synthetic_peb_modules'].append(install_user32(uc))
   if a.synthetic_user32_loader_entry:
    modules=[m for m in state.get('synthetic_peb_modules',[]) if m['name']=='user32.dll']
    if len(modules)!=1 or state.get('synthetic_user32_loader_entry'):raise ValueError('user32 loader entry requires a new synthetic image')
    from synthetic_system_peb import link_user32
    state['synthetic_user32_loader_entry']=link_user32(uc,teb,modules[0])
   if a.synthetic_peb_loader_lock:
    if not state.get('synthetic_peb_modules'):raise ValueError('synthetic loader lock requires the synthetic PEB')
    lock=teb+0x1c00;uc.mem_write(lock,struct.pack('<QiIQQQ',0,-1,0,0,0,0));uc.mem_write(teb+0x1110,struct.pack('<Q',lock));state['synthetic_peb_loader_lock']={'address':hex(lock),'assumption':'PEB + 0x110 is loader lock'}
   if state.get('synthetic_peb_modules'):
    if state.get('synthetic_dxgi_adapter'):
     d3d_info=next(m for m in state['synthetic_peb_modules'] if m['name']=='d3d12.dll');d3d_raw=Path('C:/Windows/System32/d3d12.dll').read_bytes()
     if hashlib.sha256(d3d_raw).hexdigest()!=d3d_info['sha256']:raise ValueError('synthetic d3d12 image changed')
     d3d_pe=pefile.PE(data=d3d_raw,fast_load=True);d3d_pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']]);ordinal=[e for e in d3d_pe.DIRECTORY_ENTRY_EXPORT.symbols if e.ordinal==101]
     if len(ordinal)!=1 or ordinal[0].name!=b'D3D12CreateDevice' or ordinal[0].forwarder:raise ValueError('unexpected local D3D12 ordinal 101')
     state['synthetic_d3d12_ordinal_101']='D3D12CreateDevice'
    info=next(m for m in state['synthetic_peb_modules'] if m['name']=='kernel32.dll');raw=Path('C:/Windows/System32/kernel32.dll').read_bytes()
    if hashlib.sha256(raw).hexdigest()!=info['sha256']:raise ValueError('synthetic kernel32 image changed')
    kp=pefile.PE(data=raw)
    for symbol,key in ((b'HeapSetInformation','fake_heap_info_export'),(b'HeapCreate','fake_heap_create_export'),(b'LoadLibraryExW','fake_loadlibraryexw_export'),(b'GetSystemDirectoryW','fake_system_directory_export')):
     found=[v for v in kp.DIRECTORY_ENTRY_EXPORT.symbols if v.name==symbol]
     if len(found)!=1 or found[0].forwarder:raise ValueError('unexpected heap export')
     state[key]=int(info['base'],16)+found[0].address
    info=next(m for m in state['synthetic_peb_modules'] if m['name']=='ntdll.dll');raw=Path('C:/Windows/System32/ntdll.dll').read_bytes()
    if hashlib.sha256(raw).hexdigest()!=info['sha256']:raise ValueError('synthetic ntdll image changed')
    np=pefile.PE(data=raw)
    for symbol,key in ((b'LdrRegisterDllNotification','fake_dll_notification_export'),(b'NtQueryVirtualMemory','fake_ntquery_virtual_memory_export'),(b'NtAllocateVirtualMemory','fake_ntallocate_virtual_memory_export'),(b'NtProtectVirtualMemory','fake_ntprotect_virtual_memory_export'),(b'NtQuerySystemInformation','fake_ntquery_system_information_export')):
     found=[v for v in np.DIRECTORY_ENTRY_EXPORT.symbols if v.name==symbol]
     if len(found)!=1 or found[0].forwarder:raise ValueError('unexpected ntdll export')
     state[key]=int(info['base'],16)+found[0].address
   if a.assume_loadicon_success:
    sp=uc.reg_read(UC_X86_REG_RSP)
    if pc!=exception_mem+0x7110 or uc.reg_read(UC_X86_REG_RCX)!=base or uc.reg_read(UC_X86_REG_RDX)!=1018 or not child_stack<=sp<=child_stack+0x200000-8:raise ValueError('unexpected LoadIconA checkpoint')
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']]);groups=[e for e in pe.DIRECTORY_ENTRY_RESOURCE.entries if e.id==14];ids=[e.id for g in groups for e in g.directory.entries]
    if 1018 not in ids:raise ValueError('expected icon group absent from preserved PE')
    state.setdefault('synthetic_gui_assumptions',[]).append({'method':'LoadIconA','resource_id':1018,'assumption':'hypothetical success with inert handle; resource group exists in preserved PE, no host UI','host_api_called':False});uc.reg_write(UC_X86_REG_RAX,0x7d5900000001);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc)
   if a.assume_loadcursor_success:
    sp=uc.reg_read(UC_X86_REG_RSP)
    if pc!=exception_mem+0x7120 or uc.reg_read(UC_X86_REG_RCX)!=0 or uc.reg_read(UC_X86_REG_RDX)!=0x7f00 or not child_stack<=sp<=child_stack+0x200000-8:raise ValueError('unexpected LoadCursorA checkpoint')
    state.setdefault('synthetic_gui_assumptions',[]).append({'method':'LoadCursorA','resource_id':'IDC_ARROW','assumption':'hypothetical success with inert cursor handle; no host UI','host_api_called':False});uc.reg_write(UC_X86_REG_RAX,0x7d5900000002);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc)
   if a.assume_stockobject_success:
    sp=uc.reg_read(UC_X86_REG_RSP)
    if pc!=exception_mem+0x7130 or uc.reg_read(UC_X86_REG_RCX)!=4 or not child_stack<=sp<=child_stack+0x200000-8:raise ValueError('unexpected GetStockObject checkpoint')
    state.setdefault('synthetic_gui_assumptions',[]).append({'method':'GetStockObject','index':'BLACK_BRUSH','assumption':'hypothetical success with inert brush handle; no host UI','host_api_called':False});uc.reg_write(UC_X86_REG_RAX,0x7d5900000003);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc)
   if a.assume_registerclass_success:
    sp=uc.reg_read(UC_X86_REG_RSP);ptr=uc.reg_read(UC_X86_REG_RCX)
    if pc!=exception_mem+0x7140 or not child_stack<=sp<=child_stack+0x200000-8 or not child_stack<=ptr<=child_stack+0x200000-80:raise ValueError('unexpected window class checkpoint')
    size,style,proc,extra1,extra2,module,icon,cursor,brush,menu,name,small=struct.unpack('<IIQiiQQQQQQQ',uc.mem_read(ptr,80));label='Tiger D3D Window\0'.encode('utf-16le')
    if size!=80 or style!=8 or proc!=0x1704ab430 or module!=base or icon!=0x7d5900000001 or cursor!=0x7d5900000002 or brush!=0x7d5900000003 or menu!=0 or small!=0 or not base+0x32c84000<=name<=base+0x392a6be1-len(label) or bytes(uc.mem_read(name,len(label)))!=label:raise ValueError('unexpected window class contents')
    state['synthetic_window_class']={'name':'Tiger D3D Window','procedure':hex(proc),'atom':0xc001,'assumption':'hypothetical class registration; no host window','host_api_called':False};uc.reg_write(UC_X86_REG_RAX,0xc001);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc)
   if a.assume_window_without_callbacks:
    sp=uc.reg_read(UC_X86_REG_RSP);klass=uc.reg_read(UC_X86_REG_RDX);title=uc.reg_read(UC_X86_REG_R8);style=uc.reg_read(UC_X86_REG_R9)
    if pc!=exception_mem+0x7150 or uc.reg_read(UC_X86_REG_RCX)!=0 or klass!=0x172d418e8 or style!=0xcb0000 or not child_stack<=sp<=child_stack+0x200000-0x68 or not child_stack<=title<=child_stack+0x200000-18 or bytes(uc.mem_read(title,18))!='Marathon\0'.encode('utf-16le') or struct.unpack('<8Q',uc.mem_read(sp+0x28,64))!=(0xffff8300,0xffff8300,4,4,0,0,base,0):raise ValueError('unexpected CreateWindowExW checkpoint')
    state['synthetic_window']={'handle':'0x7d5900000004','class':'Tiger D3D Window','assumption':'hypothetical window success without synchronous window-procedure messages; no host window; not faithful Windows creation','host_api_called':False};uc.reg_write(UC_X86_REG_RAX,0x7d5900000004);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc)
   if a.assume_window_userdata_two:
    sp=uc.reg_read(UC_X86_REG_RSP);window=state.get('synthetic_window',{})
    if pc!=exception_mem+0x7160 or uc.reg_read(UC_X86_REG_RCX)!=0x7d5900000004 or uc.reg_read(UC_X86_REG_RDX)&0xffffffff!=0xffffffeb or uc.reg_read(UC_X86_REG_R8)!=2 or window.get('userdata')!='0x0' or not child_stack<=sp<=child_stack+0x200000-8:raise ValueError('unexpected window userdata two checkpoint')
    window['userdata']='0x2';window['userdata_assumption']='synthetic prior value zero; real callbacks omitted';uc.reg_write(UC_X86_REG_RAX,0);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc)
   if a.assume_window_userdata_zero:
    sp=uc.reg_read(UC_X86_REG_RSP)
    if pc!=exception_mem+0x7160 or uc.reg_read(UC_X86_REG_RCX)!=0x7d5900000004 or uc.reg_read(UC_X86_REG_RDX)&0xffffffff!=0xffffffeb or uc.reg_read(UC_X86_REG_R8)!=0 or not child_stack<=sp<=child_stack+0x200000-8:raise ValueError('unexpected window userdata checkpoint')
    state['synthetic_window']['userdata']='0x0';state['synthetic_window']['userdata_assumption']='initial userdata assumed zero; creation callbacks omitted';uc.reg_write(UC_X86_REG_RAX,0);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc)
   if a.assume_window_title_without_callback:
    sp=uc.reg_read(UC_X86_REG_RSP);ptr=uc.reg_read(UC_X86_REG_RDX);payload='Marathon\0'.encode('utf-16le')
    if pc!=exception_mem+0x7170 or uc.reg_read(UC_X86_REG_RCX)!=0x7d5900000004 or not child_stack<=sp<=child_stack+0x200000-8 or not child_stack<=ptr<=child_stack+0x200000-len(payload) or bytes(uc.mem_read(ptr,len(payload)))!=payload:raise ValueError('unexpected window title checkpoint')
    state['synthetic_window']['title']='Marathon';state['synthetic_window']['title_assumption']='hypothetical success without WM_SETTEXT callback; no host window';uc.reg_write(UC_X86_REG_RAX,1);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc)
   if a.assume_adjustrect_borderless:
    sp=uc.reg_read(UC_X86_REG_RSP);ptr=uc.reg_read(UC_X86_REG_RCX)
    if pc!=exception_mem+0x7180 or uc.reg_read(UC_X86_REG_RDX)!=0 or uc.reg_read(UC_X86_REG_R8)!=0 or not child_stack<=sp<=child_stack+0x200000-8 or not child_stack<=ptr<=child_stack+0x200000-16 or struct.unpack('<4i',uc.mem_read(ptr,16))!=(50,50,250,250):raise ValueError('unexpected borderless AdjustWindowRect checkpoint')
    state.setdefault('synthetic_gui_assumptions',[]).append({'method':'AdjustWindowRect','assumption':'hypothetical unchanged borderless rectangle; no host metrics or UI','host_api_called':False});uc.reg_write(UC_X86_REG_RAX,1);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc)
   if a.assume_adjustrect_small:
    sp=uc.reg_read(UC_X86_REG_RSP);ptr=uc.reg_read(UC_X86_REG_RCX)
    if pc!=exception_mem+0x7180 or uc.reg_read(UC_X86_REG_RDX)!=0xcb0000 or uc.reg_read(UC_X86_REG_R8)!=0 or not child_stack<=sp<=child_stack+0x200000-8 or not child_stack<=ptr<=child_stack+0x200000-16 or struct.unpack('<4i',uc.mem_read(ptr,16))!=(50,50,250,250):raise ValueError('unexpected small AdjustWindowRect checkpoint')
    uc.mem_write(ptr,struct.pack('<4i',42,19,258,258));state.setdefault('synthetic_gui_assumptions',[]).append({'method':'AdjustWindowRect','assumption':'same hypothetical 8-pixel frame and 31-pixel top; no host metrics or UI','host_api_called':False});uc.reg_write(UC_X86_REG_RAX,1);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc)
   if a.assume_adjustrect:
    sp=uc.reg_read(UC_X86_REG_RSP);ptr=uc.reg_read(UC_X86_REG_RCX)
    if pc!=exception_mem+0x7180 or uc.reg_read(UC_X86_REG_RDX)!=0xcb0000 or uc.reg_read(UC_X86_REG_R8)!=0 or not child_stack<=sp<=child_stack+0x200000-8 or not child_stack<=ptr<=child_stack+0x200000-16 or struct.unpack('<4i',uc.mem_read(ptr,16))!=(0,0,1280,720):raise ValueError('unexpected AdjustWindowRect checkpoint')
    uc.mem_write(ptr,struct.pack('<4i',-8,-31,1288,728));state.setdefault('synthetic_gui_assumptions',[]).append({'method':'AdjustWindowRect','assumption':'hypothetical 8-pixel frame and 31-pixel top; no host metrics or UI','host_api_called':False});uc.reg_write(UC_X86_REG_RAX,1);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc)
   if a.assume_windowpos_without_callbacks:
    sp=uc.reg_read(UC_X86_REG_RSP)
    if pc!=exception_mem+0x7190 or uc.reg_read(UC_X86_REG_RCX)!=0x7d5900000004 or uc.reg_read(UC_X86_REG_RDX)!=0xfffffffffffffffe or uc.reg_read(UC_X86_REG_R8)!=0 or uc.reg_read(UC_X86_REG_R9)!=0 or not child_stack<=sp<=child_stack+0x200000-0x40 or struct.unpack('<3Q',uc.mem_read(sp+0x28,24))!=(0x510,0x2f7,0):raise ValueError('unexpected SetWindowPos checkpoint')
    state['synthetic_window']['position']={'x':0,'y':0,'width':1296,'height':759,'assumption':'hypothetical success without position-change callbacks; no host window'};uc.reg_write(UC_X86_REG_RAX,1);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc)
   if a.assume_window_style:
    sp=uc.reg_read(UC_X86_REG_RSP)
    if pc!=exception_mem+0x71a0 or uc.reg_read(UC_X86_REG_RCX)!=0x7d5900000004 or uc.reg_read(UC_X86_REG_RDX)&0xffffffff!=0xfffffff0 or not child_stack<=sp<=child_stack+0x200000-8:raise ValueError('unexpected GetWindowLongA checkpoint')
    state['synthetic_window']['style_assumption']='original requested style unchanged; creation and position callbacks omitted';state['synthetic_window']['style']='0xcb0000';state['synthetic_window_style_enabled']=True;state['synthetic_window_style_reads']=state.get('synthetic_window_style_reads',0)+1;uc.reg_write(UC_X86_REG_RAX,0xcb0000);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc)
   if a.assume_window_rect:
    sp=uc.reg_read(UC_X86_REG_RSP);out=uc.reg_read(UC_X86_REG_RDX);pos=state.get('synthetic_window',{}).get('position',{})
    if pc!=exception_mem+0x71b0 or uc.reg_read(UC_X86_REG_RCX)!=0x7d5900000004 or not child_stack<=sp<=child_stack+0x200000-8 or not child_stack<=out<=child_stack+0x200000-16 or (pos.get('x'),pos.get('y'),pos.get('width'),pos.get('height'))!=(0,0,1296,759):raise ValueError('unexpected GetWindowRect checkpoint')
    uc.mem_write(out,struct.pack('<4i',0,0,1296,759));state['synthetic_window_rect_enabled']=True;state['synthetic_window_rect_reads']=state.get('synthetic_window_rect_reads',0)+1;state.setdefault('synthetic_gui_assumptions',[]).append({'method':'GetWindowRect','assumption':'returns previously assumed position, no host window or callbacks','host_api_called':False});uc.reg_write(UC_X86_REG_RAX,1);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc)
   if a.assume_getwindowuserdata:
    sp=uc.reg_read(UC_X86_REG_RSP);window=state.get('synthetic_window',{})
    if pc!=exception_mem+0x71c0 or uc.reg_read(UC_X86_REG_RCX)!=0x7d5900000004 or uc.reg_read(UC_X86_REG_RDX)&0xffffffff!=0xffffffeb or window.get('userdata')!='0x0' or not child_stack<=sp<=child_stack+0x200000-8:raise ValueError('unexpected GetWindowLongPtrA checkpoint')
    window['userdata_read_assumption']='returns stored synthetic zero; real creation callbacks omitted';state['synthetic_getwindowuserdata_enabled']=True;state['synthetic_getwindowuserdata_reads']=state.get('synthetic_getwindowuserdata_reads',0)+1;uc.reg_write(UC_X86_REG_RAX,0);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc)
   if a.assume_client_rect:
    sp=uc.reg_read(UC_X86_REG_RSP);out=uc.reg_read(UC_X86_REG_RDX);pos=state.get('synthetic_window',{}).get('position',{})
    if pc!=exception_mem+0x71d0 or uc.reg_read(UC_X86_REG_RCX)!=0x7d5900000004 or not child_stack<=sp<=child_stack+0x200000-8 or not child_stack<=out<=child_stack+0x200000-16 or (pos.get('width'),pos.get('height'))!=(1296,759):raise ValueError('unexpected GetClientRect checkpoint')
    uc.mem_write(out,struct.pack('<4i',0,0,1280,720));state.setdefault('synthetic_gui_assumptions',[]).append({'method':'GetClientRect','assumption':'hypothetical 1280x720 client from prior synthetic frame; no host UI or callbacks','host_api_called':False});uc.reg_write(UC_X86_REG_RAX,1);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc)
   if a.assume_clienttoscreen:
    sp=uc.reg_read(UC_X86_REG_RSP);out=uc.reg_read(UC_X86_REG_RDX);pos=state.get('synthetic_window',{}).get('position',{})
    if pc!=exception_mem+0x71e0 or uc.reg_read(UC_X86_REG_RCX)!=0x7d5900000004 or not child_stack<=sp<=child_stack+0x200000-8 or not child_stack<=out<=child_stack+0x200000-8 or struct.unpack('<2i',uc.mem_read(out,8)) not in ((0,0),(1280,720)) or (pos.get('x'),pos.get('y'),pos.get('width'),pos.get('height'))!=(0,0,1296,759):raise ValueError('unexpected ClientToScreen checkpoint')
    point=struct.unpack('<2i',uc.mem_read(out,8));uc.mem_write(out,struct.pack('<2i',point[0]+8,point[1]+31));state.setdefault('synthetic_gui_assumptions',[]).append({'method':'ClientToScreen','assumption':'synthetic origin from previously assumed frame; no host UI or callbacks','host_api_called':False});uc.reg_write(UC_X86_REG_RAX,1);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc)
   if a.assume_monitorfromwindow:
    sp=uc.reg_read(UC_X86_REG_RSP);window=state.get('synthetic_window',{});output=state.get('synthetic_dxgi_output',{})
    if pc!=exception_mem+0x71f0 or uc.reg_read(UC_X86_REG_RCX)!=0x7d5900000004 or uc.reg_read(UC_X86_REG_RDX)!=2 or window.get('handle')!='0x7d5900000004' or not output or not child_stack<=sp<=child_stack+0x200000-8:raise ValueError('unexpected MonitorFromWindow checkpoint')
    state.setdefault('synthetic_gui_assumptions',[]).append({'method':'MonitorFromWindow','assumption':'hypothetical nearest monitor is prior synthetic output monitor; no host display','host_api_called':False});uc.reg_write(UC_X86_REG_RAX,0x7d5700000000);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc)
   if a.fix_observed_vdivss:
    if not state.get('synthetic_second_d3d12_device'):raise ValueError('vdivss experiment requires synthetic graphics state')
    state['synthetic_fix_observed_vdivss']=True
   if a.assume_modff_qnan:
    sp=uc.reg_read(UC_X86_REG_RSP);out=uc.reg_read(UC_X86_REG_RDX)
    if imports.get(pc,'').lower()!='api-ms-win-crt-math-l1-1-0.dll!modff' or uc.reg_read(UC_X86_REG_XMM0)&0xffffffff!=0xffc00000 or not child_stack<=sp<=child_stack+0x200000-8 or not child_stack<=out<=child_stack+0x200000-4:raise ValueError('unexpected quiet NaN modff checkpoint')
    state['synthetic_modff_qnan_enabled']=True
   if a.assume_monitorinfo:
    sp=uc.reg_read(UC_X86_REG_RSP);out=uc.reg_read(UC_X86_REG_RDX)
    if pc!=exception_mem+0x7200 or uc.reg_read(UC_X86_REG_RCX)!=0x7d5700000000 or not child_stack<=sp<=child_stack+0x200000-8 or not child_stack<=out<=child_stack+0x200000-40 or struct.unpack('<I',uc.mem_read(out,4))[0]!=40:raise ValueError('unexpected GetMonitorInfoA checkpoint')
    uc.mem_write(out,struct.pack('<I8iI',40,0,0,1920,1080,0,0,1920,1080,1));state.setdefault('synthetic_gui_assumptions',[]).append({'method':'GetMonitorInfoA','assumption':'hypothetical primary 1920x1080 monitor with full work area; no host display','host_api_called':False});uc.reg_write(UC_X86_REG_RAX,1);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc)
   if a.trace_getmonitorinfo:
    sp=uc.reg_read(UC_X86_REG_RSP);handle=uc.reg_read(UC_X86_REG_RCX);name=uc.reg_read(UC_X86_REG_RDX)
    if imports.get(pc,'').lower()!='kernel32.dll!getprocaddress' or handle!=state.get('fake_library_handles',{}).get('user32.dll') or not child_stack<=sp<=child_stack+0x200000-8 or bytes(uc.mem_read(name,16))!=b'GetMonitorInfoA\0':raise ValueError('unexpected GetMonitorInfoA lookup checkpoint')
    state['synthetic_getmonitorinfo_symbol']=True;uc.reg_write(UC_X86_REG_RAX,exception_mem+0x7200);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc)
   if a.assume_window_style_zero:
    sp=uc.reg_read(UC_X86_REG_RSP);window=state.get('synthetic_window',{})
    if pc!=exception_mem+0x7210 or uc.reg_read(UC_X86_REG_RCX)!=0x7d5900000004 or uc.reg_read(UC_X86_REG_RDX)&0xffffffff!=0xfffffff0 or uc.reg_read(UC_X86_REG_R8)!=0 or not child_stack<=sp<=child_stack+0x200000-8:raise ValueError('unexpected SetWindowLongA style checkpoint')
    window['style']='0x0';window['style_assumption']='hypothetical style transition; real window callbacks omitted';state['synthetic_window_style_enabled']=True;uc.reg_write(UC_X86_REG_RAX,0xcb0000);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc)
   if a.trace_setwindowlonga:
    sp=uc.reg_read(UC_X86_REG_RSP);handle=uc.reg_read(UC_X86_REG_RCX);name=uc.reg_read(UC_X86_REG_RDX)
    if imports.get(pc,'').lower()!='kernel32.dll!getprocaddress' or handle!=state.get('fake_library_handles',{}).get('user32.dll') or not child_stack<=sp<=child_stack+0x200000-8 or bytes(uc.mem_read(name,15))!=b'SetWindowLongA\0':raise ValueError('unexpected SetWindowLongA lookup checkpoint')
    state['synthetic_setwindowlonga_symbol']=True;uc.reg_write(UC_X86_REG_RAX,exception_mem+0x7210);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc)
   if a.trace_monitorfromwindow:
    sp=uc.reg_read(UC_X86_REG_RSP);handle=uc.reg_read(UC_X86_REG_RCX);name=uc.reg_read(UC_X86_REG_RDX)
    if imports.get(pc,'').lower()!='kernel32.dll!getprocaddress' or handle!=state.get('fake_library_handles',{}).get('user32.dll') or not child_stack<=sp<=child_stack+0x200000-8 or bytes(uc.mem_read(name,18))!=b'MonitorFromWindow\0':raise ValueError('unexpected MonitorFromWindow lookup checkpoint')
    state['synthetic_monitorfromwindow_symbol']=True;uc.reg_write(UC_X86_REG_RAX,exception_mem+0x71f0);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc)
   if a.trace_clienttoscreen:
    sp=uc.reg_read(UC_X86_REG_RSP);handle=uc.reg_read(UC_X86_REG_RCX);name=uc.reg_read(UC_X86_REG_RDX)
    if imports.get(pc,'').lower()!='kernel32.dll!getprocaddress' or handle!=state.get('fake_library_handles',{}).get('user32.dll') or not child_stack<=sp<=child_stack+0x200000-8 or bytes(uc.mem_read(name,15))!=b'ClientToScreen\0':raise ValueError('unexpected ClientToScreen lookup checkpoint')
    state['synthetic_clienttoscreen_symbol']=True;uc.reg_write(UC_X86_REG_RAX,exception_mem+0x71e0);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc)
   if a.trace_getclientrect:
    sp=uc.reg_read(UC_X86_REG_RSP);handle=uc.reg_read(UC_X86_REG_RCX);name=uc.reg_read(UC_X86_REG_RDX)
    if imports.get(pc,'').lower()!='kernel32.dll!getprocaddress' or handle!=state.get('fake_library_handles',{}).get('user32.dll') or not child_stack<=sp<=child_stack+0x200000-8 or bytes(uc.mem_read(name,14))!=b'GetClientRect\0':raise ValueError('unexpected GetClientRect lookup checkpoint')
    state['synthetic_getclientrect_symbol']=True;uc.reg_write(UC_X86_REG_RAX,exception_mem+0x71d0);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc)
   if a.trace_getwindowlongptr:
    sp=uc.reg_read(UC_X86_REG_RSP);handle=uc.reg_read(UC_X86_REG_RCX);name=uc.reg_read(UC_X86_REG_RDX)
    if imports.get(pc,'').lower()!='kernel32.dll!getprocaddress' or handle!=state.get('fake_library_handles',{}).get('user32.dll') or not child_stack<=sp<=child_stack+0x200000-8 or bytes(uc.mem_read(name,18))!=b'GetWindowLongPtrA\0':raise ValueError('unexpected GetWindowLongPtrA lookup checkpoint')
    state['synthetic_getwindowlongptr_symbol']=True;uc.reg_write(UC_X86_REG_RAX,exception_mem+0x71c0);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc)
   if a.trace_getwindowrect:
    sp=uc.reg_read(UC_X86_REG_RSP);handle=uc.reg_read(UC_X86_REG_RCX);name=uc.reg_read(UC_X86_REG_RDX)
    if imports.get(pc,'').lower()!='kernel32.dll!getprocaddress' or handle!=state.get('fake_library_handles',{}).get('user32.dll') or not child_stack<=sp<=child_stack+0x200000-8 or bytes(uc.mem_read(name,14))!=b'GetWindowRect\0':raise ValueError('unexpected GetWindowRect lookup checkpoint')
    state['synthetic_getwindowrect_symbol']=True;uc.reg_write(UC_X86_REG_RAX,exception_mem+0x71b0);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc)
   if a.trace_getwindowlong:
    sp=uc.reg_read(UC_X86_REG_RSP);handle=uc.reg_read(UC_X86_REG_RCX);name=uc.reg_read(UC_X86_REG_RDX)
    if imports.get(pc,'').lower()!='kernel32.dll!getprocaddress' or handle!=state.get('fake_library_handles',{}).get('user32.dll') or not child_stack<=sp<=child_stack+0x200000-8 or bytes(uc.mem_read(name,15))!=b'GetWindowLongA\0':raise ValueError('unexpected GetWindowLongA lookup checkpoint')
    state['synthetic_getwindowlong_symbol']=True;uc.reg_write(UC_X86_REG_RAX,exception_mem+0x71a0);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc)
   if a.trace_setwindowpos:
    sp=uc.reg_read(UC_X86_REG_RSP);handle=uc.reg_read(UC_X86_REG_RCX);name=uc.reg_read(UC_X86_REG_RDX)
    if imports.get(pc,'').lower()!='kernel32.dll!getprocaddress' or handle!=state.get('fake_library_handles',{}).get('user32.dll') or not child_stack<=sp<=child_stack+0x200000-8 or bytes(uc.mem_read(name,13))!=b'SetWindowPos\0':raise ValueError('unexpected SetWindowPos lookup checkpoint')
    state['synthetic_setwindowpos_symbol']=True;uc.reg_write(UC_X86_REG_RAX,exception_mem+0x7190);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc)
   if a.trace_adjustrect:
    sp=uc.reg_read(UC_X86_REG_RSP);handle=uc.reg_read(UC_X86_REG_RCX);name=uc.reg_read(UC_X86_REG_RDX)
    if imports.get(pc,'').lower()!='kernel32.dll!getprocaddress' or handle!=state.get('fake_library_handles',{}).get('user32.dll') or not child_stack<=sp<=child_stack+0x200000-8 or bytes(uc.mem_read(name,17))!=b'AdjustWindowRect\0':raise ValueError('unexpected AdjustWindowRect lookup checkpoint')
    state['synthetic_adjustrect_symbol']=True;uc.reg_write(UC_X86_REG_RAX,exception_mem+0x7180);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc)
   if a.trace_setwindowtext:
    sp=uc.reg_read(UC_X86_REG_RSP);handle=uc.reg_read(UC_X86_REG_RCX);name=uc.reg_read(UC_X86_REG_RDX)
    if imports.get(pc,'').lower()!='kernel32.dll!getprocaddress' or handle!=state.get('fake_library_handles',{}).get('user32.dll') or not child_stack<=sp<=child_stack+0x200000-8 or bytes(uc.mem_read(name,15))!=b'SetWindowTextW\0':raise ValueError('unexpected SetWindowTextW lookup checkpoint')
    state['synthetic_setwindowtext_symbol']=True;uc.reg_write(UC_X86_REG_RAX,exception_mem+0x7170);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc)
   if a.trace_setwindowlong:
    sp=uc.reg_read(UC_X86_REG_RSP);handle=uc.reg_read(UC_X86_REG_RCX);name=uc.reg_read(UC_X86_REG_RDX)
    if imports.get(pc,'').lower()!='kernel32.dll!getprocaddress' or handle!=state.get('fake_library_handles',{}).get('user32.dll') or not child_stack<=sp<=child_stack+0x200000-8 or bytes(uc.mem_read(name,18))!=b'SetWindowLongPtrA\0':raise ValueError('unexpected SetWindowLongPtrA lookup checkpoint')
    state['synthetic_setwindowlong_symbol']=True;uc.reg_write(UC_X86_REG_RAX,exception_mem+0x7160);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc)
   if a.trace_createwindow:
    sp=uc.reg_read(UC_X86_REG_RSP);handle=uc.reg_read(UC_X86_REG_RCX);name=uc.reg_read(UC_X86_REG_RDX)
    if imports.get(pc,'').lower()!='kernel32.dll!getprocaddress' or handle!=state.get('fake_library_handles',{}).get('user32.dll') or not child_stack<=sp<=child_stack+0x200000-8 or bytes(uc.mem_read(name,16))!=b'CreateWindowExW\0':raise ValueError('unexpected CreateWindowExW lookup checkpoint')
    state['synthetic_createwindow_symbol']=True;uc.reg_write(UC_X86_REG_RAX,exception_mem+0x7150);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc)
   if a.trace_registerclass:
    sp=uc.reg_read(UC_X86_REG_RSP);handle=uc.reg_read(UC_X86_REG_RCX);name=uc.reg_read(UC_X86_REG_RDX)
    if imports.get(pc,'').lower()!='kernel32.dll!getprocaddress' or handle!=state.get('fake_library_handles',{}).get('user32.dll') or not child_stack<=sp<=child_stack+0x200000-8 or bytes(uc.mem_read(name,17))!=b'RegisterClassExW\0':raise ValueError('unexpected RegisterClassExW lookup checkpoint')
    state['synthetic_registerclass_symbol']=True;uc.reg_write(UC_X86_REG_RAX,exception_mem+0x7140);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc)
   if a.trace_stockobject:
    sp=uc.reg_read(UC_X86_REG_RSP);handle=uc.reg_read(UC_X86_REG_RCX);name=uc.reg_read(UC_X86_REG_RDX)
    if imports.get(pc,'').lower()!='kernel32.dll!getprocaddress' or handle!=state.get('fake_library_handles',{}).get('gdi32.dll') or not child_stack<=sp<=child_stack+0x200000-8 or bytes(uc.mem_read(name,15))!=b'GetStockObject\0':raise ValueError('unexpected GetStockObject lookup checkpoint')
    state['synthetic_stockobject_symbol']=True;uc.reg_write(UC_X86_REG_RAX,exception_mem+0x7130);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc)
   if a.trace_loadcursor:
    sp=uc.reg_read(UC_X86_REG_RSP);handle=uc.reg_read(UC_X86_REG_RCX);name=uc.reg_read(UC_X86_REG_RDX)
    if imports.get(pc,'').lower()!='kernel32.dll!getprocaddress' or handle!=state.get('fake_library_handles',{}).get('user32.dll') or not child_stack<=sp<=child_stack+0x200000-8 or bytes(uc.mem_read(name,12))!=b'LoadCursorA\0':raise ValueError('unexpected LoadCursorA lookup checkpoint')
    state['synthetic_loadcursor_symbol']=True;uc.reg_write(UC_X86_REG_RAX,exception_mem+0x7120);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc)
   if a.trace_loadicon:
    sp=uc.reg_read(UC_X86_REG_RSP);handle=uc.reg_read(UC_X86_REG_RCX);name=uc.reg_read(UC_X86_REG_RDX)
    if imports.get(pc,'').lower()!='kernel32.dll!getprocaddress' or handle!=state.get('fake_library_handles',{}).get('user32.dll') or not child_stack<=sp<=child_stack+0x200000-8 or bytes(uc.mem_read(name,10))!=b'LoadIconA\0':raise ValueError('unexpected LoadIconA lookup checkpoint')
    state['synthetic_loadicon_symbol']=True;uc.reg_write(UC_X86_REG_RAX,exception_mem+0x7110);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc)
   if a.trace_messagebox:
    sp=uc.reg_read(UC_X86_REG_RSP);handle=uc.reg_read(UC_X86_REG_RCX);name=uc.reg_read(UC_X86_REG_RDX)
    if imports.get(pc,'').lower()!='kernel32.dll!getprocaddress' or handle!=state.get('fake_library_handles',{}).get('user32.dll') or not child_stack<=sp<=child_stack+0x200000-8 or bytes(uc.mem_read(name,12))!=b'MessageBoxW\0':raise ValueError('unexpected MessageBoxW lookup checkpoint')
    state['synthetic_messagebox_symbol']=True;uc.reg_write(UC_X86_REG_RAX,exception_mem+0x7100);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc)
   if a.assume_en_us_lcid:
    sp=uc.reg_read(UC_X86_REG_RSP);name=uc.reg_read(UC_X86_REG_RCX);flags=uc.reg_read(UC_X86_REG_RDX);payload='en-US\0'.encode('utf-16le')
    if imports.get(pc,'').lower()!='kernel32.dll!localenametolcid' or flags!=0 or not child_stack<=sp<=child_stack+0x200000-8 or not child_stack<=name<=child_stack+0x200000-len(payload) or bytes(uc.mem_read(name,len(payload)))!=payload:raise ValueError('unexpected locale conversion checkpoint')
    state.setdefault('synthetic_locale_assumptions',[]).append({'locale':'en-US','lcid':'0x409','assumption':'fixed mapping for hypothetical locale, no host locale read','host_api_called':False});uc.reg_write(UC_X86_REG_RAX,0x409);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc)
   if a.assume_en_us_locale:
    sp=uc.reg_read(UC_X86_REG_RSP);out=uc.reg_read(UC_X86_REG_RCX);capacity=uc.reg_read(UC_X86_REG_RDX);payload='en-US\0'.encode('utf-16le')
    if imports.get(pc,'').lower()!='kernel32.dll!getuserdefaultlocalename' or not child_stack<=sp<=child_stack+0x200000-8 or capacity<6 or not child_stack<=out<=child_stack+0x200000-len(payload):raise ValueError('unexpected locale checkpoint')
    uc.mem_write(out,payload);state.setdefault('synthetic_locale_assumptions',[]).append({'locale':'en-US','assumption':'hypothetical locale, no host locale read','host_api_called':False});uc.reg_write(UC_X86_REG_RAX,6);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc)
   if a.assume_dxgi_retained_release:
    sp=uc.reg_read(UC_X86_REG_RSP)
    if pc!=0x7d5400002020 or uc.reg_read(UC_X86_REG_RCX)!=0x7d5400000000 or not child_stack<=sp<=child_stack+0x200000-8:raise ValueError('unexpected retained DXGI release checkpoint')
    state.setdefault('synthetic_dxgi_assumptions',[]).append({'method':'IDXGIAdapter1::Release','assumption':'synthetic reference count returns one after prior AddRef','host_api_called':False});uc.reg_write(UC_X86_REG_RAX,1);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc)
   if a.assume_dxgi_addref:
    sp=uc.reg_read(UC_X86_REG_RSP)
    if pc!=0x7d5400002010 or uc.reg_read(UC_X86_REG_RCX)!=0x7d5400000000 or not child_stack<=sp<=child_stack+0x200000-8:raise ValueError('unexpected DXGI adapter AddRef checkpoint')
    state.setdefault('synthetic_dxgi_assumptions',[]).append({'method':'IDXGIAdapter1::AddRef','assumption':'hypothetical second reference to inert adapter','host_api_called':False});uc.reg_write(UC_X86_REG_RAX,2);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc)
   if a.assume_dxgi_single_adapter:
    sp=uc.reg_read(UC_X86_REG_RSP);iid=uc.reg_read(UC_X86_REG_R9)
    if pc!=0x7d53000021d0 or uc.reg_read(UC_X86_REG_RCX)!=0x7d5300000000 or uc.reg_read(UC_X86_REG_RDX)!=1 or uc.reg_read(UC_X86_REG_R8)!=2 or not child_stack<=sp<=child_stack+0x200000-0x30 or not base+0x32c84000<=iid<=base+0x392a6be1-16 or bytes(uc.mem_read(iid,16)).hex()!='618f03293938264691fd086879011a05':raise ValueError('unexpected second DXGI adapter checkpoint')
    out=struct.unpack('<Q',uc.mem_read(sp+0x28,8))[0]
    if not child_stack<=out<=child_stack+0x200000-8:raise ValueError('unexpected adapter output pointer')
    uc.mem_write(out,struct.pack('<Q',0));state.setdefault('synthetic_dxgi_assumptions',[]).append({'method':'EnumAdapterByGpuPreference','index':1,'assumption':'hypothetical single-adapter environment, DXGI_ERROR_NOT_FOUND','host_api_called':False});uc.reg_write(UC_X86_REG_RAX,0x887a0002);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc)
   if a.assume_dxgi_factory_release:
    sp=uc.reg_read(UC_X86_REG_RSP)
    if pc!=0x7d5300002020 or uc.reg_read(UC_X86_REG_RCX)!=0x7d5300000000 or not child_stack<=sp<=child_stack+0x200000-8:raise ValueError('unexpected DXGI factory release checkpoint')
    state['synthetic_dxgi_release_enabled']=True;state.setdefault('synthetic_dxgi_assumptions',[]).append({'method':'IDXGIFactory6::Release','assumption':'hypothetical zero return; inert sentinel retained','host_api_called':False})
   if a.assume_dxgi_release:
    sp=uc.reg_read(UC_X86_REG_RSP)
    if pc!=0x7d5400002020 or uc.reg_read(UC_X86_REG_RCX)!=0x7d5400000000 or not child_stack<=sp<=child_stack+0x200000-8:raise ValueError('unexpected DXGI release checkpoint')
    state['synthetic_dxgi_release_enabled']=True;state.setdefault('synthetic_dxgi_assumptions',[]).append({'method':'Release','assumption':'hypothetical final reference release returning zero; inert sentinels retained','host_api_called':False})
   if a.assume_d3d12_release:
    sp=uc.reg_read(UC_X86_REG_RSP)
    if pc!=0x7d5500002020 or uc.reg_read(UC_X86_REG_RCX)!=0x7d5500000000 or not child_stack<=sp<=child_stack+0x200000-8:raise ValueError('unexpected D3D12 release checkpoint')
    state.setdefault('synthetic_d3d12_assumptions',[]).append({'method':'Release','assumption':'hypothetical final reference release, returning zero; inert sentinel retained','host_api_called':False});uc.reg_write(UC_X86_REG_RAX,0);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc)
   if a.assume_d3d12_buffer_formats:
    if not a.assume_d3d12_capable_profile:raise ValueError('buffer format assumption requires capable profile')
    state['synthetic_d3d12_buffer_formats']=True;state.setdefault('synthetic_d3d12_assumptions',[]).append({'assumption':'hypothetical buffer support bit for queried formats, not observed hardware','host_api_called':False})
   if a.assume_d3d12_capable_profile:
    sp=uc.reg_read(UC_X86_REG_RSP);out=uc.reg_read(UC_X86_REG_R8)
    if pc!=0x7d55000020d0 or uc.reg_read(UC_X86_REG_RCX)!=0x7d5500000000 or uc.reg_read(UC_X86_REG_RDX)!=0 or uc.reg_read(UC_X86_REG_R9)!=60 or not child_stack<=sp<=child_stack+0x200000-8 or not child_stack<=out<=child_stack+0x200000-60:raise ValueError('unexpected D3D12 profile checkpoint')
    state['synthetic_d3d12_capable_profile']=True;state.setdefault('synthetic_d3d12_assumptions',[]).append({'method':'CheckFeatureSupport','assumption':'hypothetical capable GPU profile, fabricated feature and format values; no observed hardware','host_api_called':False})
   if a.assume_d3d12_supported_formats:
    sp=uc.reg_read(UC_X86_REG_RSP);out=uc.reg_read(UC_X86_REG_R8)
    if pc!=0x7d55000020d0 or uc.reg_read(UC_X86_REG_RCX)!=0x7d5500000000 or uc.reg_read(UC_X86_REG_RDX)!=3 or uc.reg_read(UC_X86_REG_R9)!=12 or not child_stack<=sp<=child_stack+0x200000-8 or not child_stack<=out<=child_stack+0x200000-12 or struct.unpack('<I',uc.mem_read(out,4))[0]!=2:raise ValueError('unexpected D3D12 format checkpoint')
    state['synthetic_d3d12_supported_formats']=True;state.setdefault('synthetic_d3d12_assumptions',[]).append({'method':'CheckFeatureSupport','feature':'FORMAT_SUPPORT','assumption':'hypothetical sample/load, texture2d, render target and typed UAV capabilities for queried formats, not observed hardware','host_api_called':False})
   if a.assume_d3d12_unsupported_formats:
    sp=uc.reg_read(UC_X86_REG_RSP);out=uc.reg_read(UC_X86_REG_R8)
    if pc!=0x7d55000020d0 or uc.reg_read(UC_X86_REG_RCX)!=0x7d5500000000 or uc.reg_read(UC_X86_REG_RDX)!=3 or uc.reg_read(UC_X86_REG_R9)!=12 or not child_stack<=sp<=child_stack+0x200000-8 or not child_stack<=out<=child_stack+0x200000-12 or struct.unpack('<I',uc.mem_read(out,4))[0]!=2:raise ValueError('unexpected D3D12 format checkpoint')
    state['synthetic_d3d12_unsupported_formats']=True;state.setdefault('synthetic_d3d12_assumptions',[]).append({'method':'CheckFeatureSupport','feature':'FORMAT_SUPPORT','assumption':'hypothetical success with no format support bits, not observed hardware','host_api_called':False})
   if a.assume_d3d12_shader_model_6:
    sp=uc.reg_read(UC_X86_REG_RSP);obj=uc.reg_read(UC_X86_REG_RCX);feature=uc.reg_read(UC_X86_REG_RDX);out=uc.reg_read(UC_X86_REG_R8);size=uc.reg_read(UC_X86_REG_R9)
    if pc!=0x7d55000020d0 or obj!=0x7d5500000000 or feature!=7 or size!=4 or not child_stack<=sp<=child_stack+0x200000-8 or not child_stack<=out<=child_stack+0x200000-size or bytes(uc.mem_read(out,4))!=struct.pack('<I',0x60):raise ValueError('unexpected D3D12 shader model checkpoint')
    state.setdefault('synthetic_d3d12_assumptions',[]).append({'method':'CheckFeatureSupport','feature':'SHADER_MODEL','assumption':'hypothetical shader model 6.0 success, not observed hardware','host_api_called':False});uc.reg_write(UC_X86_REG_RAX,0);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc)
   if a.assume_d3d12_minimal_options:
    sp=uc.reg_read(UC_X86_REG_RSP);obj=uc.reg_read(UC_X86_REG_RCX);feature=uc.reg_read(UC_X86_REG_RDX);out=uc.reg_read(UC_X86_REG_R8);size=uc.reg_read(UC_X86_REG_R9)
    if pc!=0x7d55000020d0 or obj!=0x7d5500000000 or (feature,size) not in ((0,60),(8,24)) or not child_stack<=sp<=child_stack+0x200000-8 or not child_stack<=out<=child_stack+0x200000-size:raise ValueError('unexpected D3D12 options checkpoint')
    uc.mem_write(out,b'\0'*size);state.setdefault('synthetic_d3d12_assumptions',[]).append({'method':'CheckFeatureSupport','feature':{0:'D3D12_OPTIONS',8:'D3D12_OPTIONS1'}[feature],'assumption':'hypothetical all-zero capability structure with successful return, not observed hardware','host_api_called':False});uc.reg_write(UC_X86_REG_RAX,0);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc)
   if a.assume_nvapi_missing:
    sp=uc.reg_read(UC_X86_REG_RSP);ptr=uc.reg_read(UC_X86_REG_RCX);flags=uc.reg_read(UC_X86_REG_R8);payload='nvapi64.dll\0'.encode('utf-16le')
    if imports.get(pc,'').lower()!='kernel32.dll!loadlibraryexw' or uc.reg_read(UC_X86_REG_RDX)!=0 or flags!=0x800 or not child_stack<=sp<=child_stack+0x200000-8 or not base+0x32c84000<=ptr<=base+0x392a6be1-len(payload) or bytes(uc.mem_read(ptr,len(payload)))!=payload:raise ValueError('unexpected NVAPI load checkpoint')
    state.setdefault('synthetic_module_assumptions',[]).append({'module':'nvapi64.dll','assumption':'hypothetical module not found; no host driver access','host_api_called':False});uc.mem_write(teb+0x68,struct.pack('<I',126));uc.reg_write(UC_X86_REG_RAX,0);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc)
   if a.assume_version_build_ge:
    sp=uc.reg_read(UC_X86_REG_RSP);ptr=uc.reg_read(UC_X86_REG_RCX);kind=uc.reg_read(UC_X86_REG_RDX);mask=uc.reg_read(UC_X86_REG_R8)
    if imports.get(pc,'').lower()!='kernel32.dll!verifyversioninfow' or kind!=4 or mask!=0xc0 or not child_stack<=sp<=child_stack+0x200000-8 or not child_stack<=ptr<=child_stack+0x200000-20 or struct.unpack('<5I',uc.mem_read(ptr,20)) not in ((0,0,0,14308,0),(0,0,0,9200,0)):raise ValueError('unexpected version verification checkpoint')
    state.setdefault('synthetic_version_assumptions',[]).append({'method':'VerifyVersionInfoW','requested_build':struct.unpack('<I',uc.mem_read(ptr+12,4))[0],'synthetic_build':19045,'structure_size':0,'assumption':'hypothetical success for requested build despite zero size; native Windows behavior unverified','host_api_called':False});uc.reg_write(UC_X86_REG_RAX,1);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc)
   if a.assume_second_device_release:
    sp=uc.reg_read(UC_X86_REG_RSP)
    if pc!=0x7d5800002020 or uc.reg_read(UC_X86_REG_RCX)!=0x7d5800000000 or not child_stack<=sp<=child_stack+0x200000-8:raise ValueError('unexpected second-device release checkpoint')
    state.setdefault('synthetic_d3d12_assumptions',[]).append({'method':'second ID3D12Device::Release','assumption':'hypothetical final reference, sentinel retained','host_api_called':False});uc.reg_write(UC_X86_REG_RAX,0);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc)
   if a.assume_second_shader_model:
    sp=uc.reg_read(UC_X86_REG_RSP);out=uc.reg_read(UC_X86_REG_R8)
    if pc!=0x7d58000020d0 or uc.reg_read(UC_X86_REG_RCX)!=0x7d5800000000 or uc.reg_read(UC_X86_REG_RDX)!=7 or uc.reg_read(UC_X86_REG_R9)!=4 or not child_stack<=sp<=child_stack+0x200000-8 or not child_stack<=out<=child_stack+0x200000-4 or bytes(uc.mem_read(out,4))!=struct.pack('<I',0x66):raise ValueError('unexpected second-device shader model checkpoint')
    state.setdefault('synthetic_d3d12_assumptions',[]).append({'method':'second ID3D12Device::CheckFeatureSupport','feature':'SHADER_MODEL','assumption':'hypothetical shader model 6.6 success, not observed hardware','host_api_called':False});uc.reg_write(UC_X86_REG_RAX,0);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc)
   if a.trace_second_d3d12_device:
    sp=uc.reg_read(UC_X86_REG_RSP);adapter=uc.reg_read(UC_X86_REG_RCX);level=uc.reg_read(UC_X86_REG_RDX);iid=uc.reg_read(UC_X86_REG_R8);out=uc.reg_read(UC_X86_REG_R9)
    if pc!=exception_mem+0x70f0 or adapter!=0x7d5400000000 or level!=0xc000 or not child_stack<=sp<=child_stack+0x200000-8 or not base+0x32c84000<=iid<=base+0x392a6be1-16 or bytes(uc.mem_read(iid,16)).hex()!='f1199818b61d574bbe541821339b85f7' or not child_stack<=out<=child_stack+0x200000-8:raise ValueError('unexpected second D3D12 device checkpoint')
    fake=0x7d5800000000;uc.mem_map(fake,0x3000);uc.mem_write(fake,struct.pack('<Q',fake+0x1000));uc.mem_write(fake+0x1000,b''.join(struct.pack('<Q',fake+0x2000+i*16) for i in range(256)));uc.mem_write(fake+0x2000,b'\x90'*0x1000);uc.mem_write(out,struct.pack('<Q',fake))
    state['synthetic_second_d3d12_device']={'object':hex(fake),'interface':'ID3D12Device','assumption':'hypothetical second device success; all methods stop, no GPU or host D3D12','host_api_called':False};uc.reg_write(UC_X86_REG_RAX,0);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc)
   if a.trace_d3d12_device:
    sp=uc.reg_read(UC_X86_REG_RSP);adapter=uc.reg_read(UC_X86_REG_RCX);level=uc.reg_read(UC_X86_REG_RDX);iid=uc.reg_read(UC_X86_REG_R8);out=uc.reg_read(UC_X86_REG_R9)
    if pc!=exception_mem+0x70f0 or adapter!=0x7d5400000000 or level!=0xc000 or not child_stack<=sp<=child_stack+0x200000-8 or not base+0x32c84000<=iid<=base+0x392a6be1-16 or bytes(uc.mem_read(iid,16)).hex()!='f1199818b61d574bbe541821339b85f7' or not child_stack<=out<=child_stack+0x200000-8:raise ValueError('unexpected D3D12 device checkpoint')
    fake=0x7d5500000000;uc.mem_map(fake,0x3000);uc.mem_write(fake,struct.pack('<Q',fake+0x1000));uc.mem_write(fake+0x1000,b''.join(struct.pack('<Q',fake+0x2000+i*16) for i in range(256)));uc.mem_write(fake+0x2000,b'\x90'*0x1000);uc.mem_write(out,struct.pack('<Q',fake))
    state['synthetic_d3d12_device']={'object':hex(fake),'interface':'ID3D12Device','assumption':'hypothetical device creation success; all methods stop, no GPU or host D3D12','host_api_called':False};uc.reg_write(UC_X86_REG_RAX,0);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc)
   if a.synthetic_dxgi_descriptor:
    sp=uc.reg_read(UC_X86_REG_RSP);obj=uc.reg_read(UC_X86_REG_RCX);out=uc.reg_read(UC_X86_REG_RDX)
    if pc!=0x7d54000020a0 or obj!=0x7d5400000000 or not child_stack<=sp<=child_stack+0x200000-8 or not child_stack<=out<=child_stack+0x200000-312:raise ValueError('unexpected DXGI descriptor checkpoint')
    label='Synthetic Offline Adapter'.encode('utf-16le')+b'\0\0';payload=struct.pack('<256sIIIIQQQIiI4x',label,0x10de,0x1e04,0,0,8*1024**3,0,0,1,0,0)
    if len(payload)!=312:raise ValueError('unexpected DXGI descriptor size')
    uc.mem_write(out,payload);state.setdefault('synthetic_dxgi_assumptions',[]).append({'interface':'IDXGIAdapter1','method':'GetDesc1','assumption':'hypothetical NVIDIA-compatible identifiers, 8 GiB dedicated memory, no actual GPU','host_api_called':False});uc.reg_write(UC_X86_REG_RAX,0);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc)
   if a.synthetic_dxgi_output_refcount:
    sp=uc.reg_read(UC_X86_REG_RSP)
    if pc!=0x7d5600002010 or uc.reg_read(UC_X86_REG_RCX)!=0x7d5600000000 or not child_stack<=sp<=child_stack+0x200000-8:raise ValueError('unexpected DXGI output AddRef checkpoint')
    state['synthetic_dxgi_output_refcount_enabled']=True;state['synthetic_dxgi_output_refs']=1;state.setdefault('synthetic_dxgi_assumptions',[]).append({'interface':'IDXGIOutput','assumption':'synthetic COM reference count starting at one; inert output retained','host_api_called':False})
   if a.synthetic_dxgi_one_mode:
    sp=uc.reg_read(UC_X86_REG_RSP);obj=uc.reg_read(UC_X86_REG_RCX);fmt=uc.reg_read(UC_X86_REG_RDX);flags=uc.reg_read(UC_X86_REG_R8);count=uc.reg_read(UC_X86_REG_R9)
    if pc!=0x7d5600002080 or obj!=0x7d5600000000 or fmt!=28 or flags!=3 or not child_stack<=sp<=child_stack+0x200000-0x30 or not child_stack<=count<=child_stack+0x200000-4:raise ValueError('unexpected DXGI mode list checkpoint')
    out=struct.unpack('<Q',uc.mem_read(sp+0x28,8))[0];capacity=struct.unpack('<I',uc.mem_read(count,4))[0]
    if capacity<1 or not child_stack<=out<=child_stack+0x200000-28:raise ValueError('unexpected mode output')
    uc.mem_write(out,struct.pack('<7I',1920,1080,60,1,28,1,1));uc.mem_write(count,struct.pack('<I',1));state.setdefault('synthetic_dxgi_assumptions',[]).append({'method':'IDXGIOutput::GetDisplayModeList','assumption':'hypothetical single 1920x1080 60 Hz mode; no host display','host_api_called':False});uc.reg_write(UC_X86_REG_RAX,0);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc)
   if a.synthetic_dxgi_output_desc:
    sp=uc.reg_read(UC_X86_REG_RSP);obj=uc.reg_read(UC_X86_REG_RCX);out=uc.reg_read(UC_X86_REG_RDX)
    if pc!=0x7d5600002070 or obj!=0x7d5600000000 or not child_stack<=sp<=child_stack+0x200000-8 or not child_stack<=out<=child_stack+0x200000-96:raise ValueError('unexpected DXGI output description checkpoint')
    label='Synthetic Display'.encode('utf-16le')+b'\0\0';payload=struct.pack('<64s4iIIQ',label,0,0,1920,1080,1,1,0x7d5700000000)
    uc.mem_write(out,payload);state.setdefault('synthetic_dxgi_assumptions',[]).append({'method':'IDXGIOutput::GetDesc','assumption':'hypothetical attached 1920x1080 output and inert monitor handle; no display or host API','host_api_called':False});uc.reg_write(UC_X86_REG_RAX,0);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc)
   if a.trace_dxgi_output:
    sp=uc.reg_read(UC_X86_REG_RSP);obj=uc.reg_read(UC_X86_REG_RCX);index=uc.reg_read(UC_X86_REG_RDX);out=uc.reg_read(UC_X86_REG_R8)
    if pc!=0x7d5400002070 or obj!=0x7d5400000000 or index!=0 or not child_stack<=sp<=child_stack+0x200000-8 or not child_stack<=out<=child_stack+0x200000-8:raise ValueError('unexpected DXGI output checkpoint')
    fake=0x7d5600000000;uc.mem_map(fake,0x3000);uc.mem_write(fake,struct.pack('<Q',fake+0x1000));uc.mem_write(fake+0x1000,b''.join(struct.pack('<Q',fake+0x2000+i*16) for i in range(256)));uc.mem_write(fake+0x2000,b'\x90'*0x1000);uc.mem_write(out,struct.pack('<Q',fake))
    state['synthetic_dxgi_output']={'object':hex(fake),'assumption':'hypothetical one output sentinel; all methods stop, no host display access','host_api_called':False};uc.reg_write(UC_X86_REG_RAX,0);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc)
   if a.assume_dxgi_single_output:
    sp=uc.reg_read(UC_X86_REG_RSP);obj=uc.reg_read(UC_X86_REG_RCX);index=uc.reg_read(UC_X86_REG_RDX);out=uc.reg_read(UC_X86_REG_R8)
    if pc!=0x7d5400002070 or obj!=0x7d5400000000 or index!=1 or not child_stack<=sp<=child_stack+0x200000-8 or not child_stack<=out<=child_stack+0x200000-8:raise ValueError('unexpected second DXGI output checkpoint')
    uc.mem_write(out,struct.pack('<Q',0));state.setdefault('synthetic_dxgi_assumptions',[]).append({'method':'IDXGIAdapter1::EnumOutputs','index':1,'assumption':'hypothetical single-output environment, DXGI_ERROR_NOT_FOUND','host_api_called':False});uc.reg_write(UC_X86_REG_RAX,0x887a0002);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc)
   if a.assume_dxgi_no_output:
    sp=uc.reg_read(UC_X86_REG_RSP);obj=uc.reg_read(UC_X86_REG_RCX);index=uc.reg_read(UC_X86_REG_RDX);out=uc.reg_read(UC_X86_REG_R8)
    if pc!=0x7d5400002070 or obj!=0x7d5400000000 or index!=0 or not child_stack<=sp<=child_stack+0x200000-8 or not child_stack<=out<=child_stack+0x200000-8:raise ValueError('unexpected DXGI output enumeration checkpoint')
    uc.mem_write(out,struct.pack('<Q',0));state.setdefault('synthetic_dxgi_assumptions',[]).append({'interface':'IDXGIAdapter1','method':'EnumOutputs','index':0,'result':'DXGI_ERROR_NOT_FOUND','assumption':'hypothetical headless adapter, no host GPU','host_api_called':False});uc.reg_write(UC_X86_REG_RAX,0x887a0002);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc)
   if a.trace_dxgi_adapter:
    sp=uc.reg_read(UC_X86_REG_RSP);obj=uc.reg_read(UC_X86_REG_RCX);index=uc.reg_read(UC_X86_REG_RDX);preference=uc.reg_read(UC_X86_REG_R8);iid=uc.reg_read(UC_X86_REG_R9)
    if pc!=0x7d53000021d0 or obj!=0x7d5300000000 or index!=0 or preference!=2 or not child_stack<=sp<=child_stack+0x200000-0x30 or not base+0x32c84000<=iid<=base+0x392a6be1-16 or bytes(uc.mem_read(iid,16)).hex()!='618f03293938264691fd086879011a05':raise ValueError('unexpected DXGI adapter checkpoint')
    out=struct.unpack('<Q',uc.mem_read(sp+0x28,8))[0]
    if not child_stack<=out<=child_stack+0x200000-8:raise ValueError('unexpected DXGI adapter output')
    fake=0x7d5400000000;uc.mem_map(fake,0x3000);uc.mem_write(fake,struct.pack('<Q',fake+0x1000));uc.mem_write(fake+0x1000,b''.join(struct.pack('<Q',fake+0x2000+i*16) for i in range(256)));uc.mem_write(fake+0x2000,b'\x90'*0x1000);uc.mem_write(out,struct.pack('<Q',fake))
    state['synthetic_dxgi_adapter']={'object':hex(fake),'interface':'IDXGIAdapter1','assumption':'hypothetical single adapter sentinel; all methods stop, no GPU or host DXGI','host_api_called':False};uc.reg_write(UC_X86_REG_RAX,0);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc)
   if a.trace_dxgi_factory6:
    sp=uc.reg_read(UC_X86_REG_RSP);obj=uc.reg_read(UC_X86_REG_RCX);iid=uc.reg_read(UC_X86_REG_RDX);out=uc.reg_read(UC_X86_REG_R8)
    if pc!=0x7d5300002000 or obj!=0x7d5300000000 or not child_stack<=sp<=child_stack+0x200000-8 or not base+0x32c84000<=iid<=base+0x392a6be1-16 or bytes(uc.mem_read(iid,16)).hex()!='4f69b6c109ffa944b03c77900a0a1d17' or not child_stack<=out<=child_stack+0x200000-8:raise ValueError('unexpected DXGI QueryInterface checkpoint')
    uc.mem_write(out,struct.pack('<Q',obj));state['synthetic_dxgi_factory'].update(interface='IDXGIFactory6',query_assumption='hypothetical QueryInterface success, no DXGI or GPU');uc.reg_write(UC_X86_REG_RAX,0);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc)
   if a.trace_dxgi_factory:
    sp=uc.reg_read(UC_X86_REG_RSP);iid=uc.reg_read(UC_X86_REG_RCX);out=uc.reg_read(UC_X86_REG_RDX)
    if pc!=exception_mem+0x70e0 or not child_stack<=sp<=child_stack+0x200000-8 or not base+0x32c84000<=iid<=base+0x392a6be1-16 or bytes(uc.mem_read(iid,16)).hex()!='78ae0a776ff2ba4da829253c83d1b387' or not child_stack<=out<=child_stack+0x200000-8:raise ValueError('unexpected DXGI factory checkpoint')
    fake=0x7d5300000000;uc.mem_map(fake,0x3000);uc.mem_write(fake,struct.pack('<Q',fake+0x1000));uc.mem_write(fake+0x1000,b''.join(struct.pack('<Q',fake+0x2000+i*16) for i in range(256)));uc.mem_write(fake+0x2000,b'\x90'*0x1000);uc.mem_write(out,struct.pack('<Q',fake))
    state['synthetic_dxgi_factory']={'object':hex(fake),'iid':'770aae78-f26f-4dba-a829-253c83d1b387','assumption':'inspection-only COM sentinel, no GPU or host DXGI','host_api_called':False};uc.reg_write(UC_X86_REG_RAX,0);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc)
   if a.synthetic_input_actions:
    if pc!=0x7d5200002090 or uc.reg_read(UC_X86_REG_RCX)!=0x7d5200000000:raise ValueError('unexpected synthetic input action checkpoint')
    state['synthetic_input_actions_enabled']=True
   if a.resume_cached_steam_context:
    sp=uc.reg_read(UC_X86_REG_RSP);ptr=uc.reg_read(UC_X86_REG_RCX);symbol=state.get('virtual_steam_markers',{}).get(hex(pc))
    if symbol!='SteamInternal_ContextInit' or ptr!=0x1744bce90 or not stack<=sp<=stack+0x200000-8:raise ValueError('unexpected cached Steam context')
    generation,slot=struct.unpack('<QQ',bytes(uc.mem_read(ptr+8,16)))
    if generation!=0 or slot!=0x7d5200000000:raise ValueError('unexpected cached Steam interface')
    if any(ptr+8<point+0x40 and point<ptr+16 for point in watch_points):raise ValueError('cached Steam context overlaps watchpoint')
    uc.mem_write(ptr+8,struct.pack('<Q',1));state.setdefault('synthetic_steam_contexts',{})[hex(ptr)]={'slot':hex(slot),'generation':1,'assumption':'synthetic cached interface; no Steam session'}
    uc.reg_write(UC_X86_REG_RAX,ptr+16);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc)
   if a.assume_input_init_success:
    sp=uc.reg_read(UC_X86_REG_RSP)
    if pc!=0x7d5200002000 or uc.reg_read(UC_X86_REG_RCX)!=0x7d5200000000 or uc.reg_read(UC_X86_REG_RDX)!=0 or not stack<=sp<=stack+0x200000-8:raise ValueError('unexpected Steam input init checkpoint')
    state.setdefault('synthetic_steam_assumptions',[]).append({'interface':'SteamInput006','slot':0,'method':'Init','return':True,'assumption':'hypothetical successful input initialization; no Steam or host controllers','host_api_called':False});uc.reg_write(UC_X86_REG_RAX,1);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc)
   if a.assume_steam_user_handle:
    sp=uc.reg_read(UC_X86_REG_RSP);symbol=state.get('virtual_steam_markers',{}).get(hex(pc))
    if symbol!='SteamAPI_GetHSteamUser' or not stack<=sp<=stack+0x200000-8:raise ValueError('unexpected Steam user handle checkpoint')
    state.setdefault('synthetic_steam_assumptions',[]).append({'symbol':symbol,'return':1,'assumption':'synthetic nonzero user handle; no Steam user or session','host_api_called':False})
    uc.reg_write(UC_X86_REG_RAX,1);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc)
   if a.virtual_xinput_module:
    xinput_raw=a.virtual_xinput_module.read_bytes();xinput_digest=hashlib.sha256(xinput_raw).hexdigest()
    if xinput_digest!='5f41070a6f2afd762caece55c932355210719de07d3361077701d85b9fc8542f':raise ValueError('unexpected local XInput module')
    xinput_pe=pefile.PE(data=xinput_raw,fast_load=True);xinput_pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']]);exports=[e.name.decode('ascii') for e in xinput_pe.DIRECTORY_ENTRY_EXPORT.symbols if e.name and not e.forwarder]
    state['virtual_xinput_module']={'sha256':xinput_digest,'exports':exports,'assumption':'local system PE export names only, not historical game-system identity; no native DLL or device access'}
    if not any(lo<=0x7d7100000000 and 0x7d7100001000<=hi+1 for lo,hi,_ in uc.mem_regions()):uc.mem_map(0x7d7100000000,0x1000);uc.mem_write(0x7d7100000000,b'\x90'*0x1000)
   if a.virtual_oodle_module:
    oodle_raw=a.virtual_oodle_module.read_bytes();oodle_digest=hashlib.sha256(oodle_raw).hexdigest()
    if oodle_digest!='24f182bb2127c007df04cc56063ceec5999a7dd714c133920310caa47295572a':raise ValueError('unexpected preserved Oodle module')
    oodle_pe=pefile.PE(data=oodle_raw,fast_load=True);oodle_pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']]);exports=[e.name.decode('ascii') for e in oodle_pe.DIRECTORY_ENTRY_EXPORT.symbols if e.name and not e.forwarder]
    state['virtual_oodle_module']={'sha256':oodle_digest,'exports':exports,'assumption':'export names only; no native DLL execution'}
    if not any(lo<=0x7d7000000000 and 0x7d7000001000<=hi+1 for lo,hi,_ in uc.mem_regions()):uc.mem_map(0x7d7000000000,0x1000);uc.mem_write(0x7d7000000000,b'\x90'*0x1000)
   if a.handoff_worker_release:
    worker=state.get('dynamic_worker_experiment',{});sp=uc.reg_read(UC_X86_REG_RSP);handle=hex(uc.reg_read(UC_X86_REG_RCX));amount=uc.reg_read(UC_X86_REG_RDX);previous=uc.reg_read(UC_X86_REG_R8);sem=state.get('fake_semaphores',{}).get(handle)
    if imports.get(pc,'').lower()!='kernel32.dll!releasesemaphore' or worker.get('entry')!='0x170f53470' or worker.get('parent_wait_handle')!=handle or not sem or sem['count']!=0 or sem['maximum']!=1 or amount!=1 or not child_stack<=sp<=child_stack+0x200000-8 or not child_stack<=previous<=child_stack+0x200000-4:raise ValueError('unexpected worker semaphore release')
    parent_root=Path(worker['parent_checkpoint']);parent_manifest=json.loads((parent_root/'manifest.json').read_text(encoding='utf-8'));raw=(parent_root/'context.bin').read_bytes()
    if parent_manifest['identity']!=checkpoint_identity or hashlib.sha256(raw).hexdigest()!=parent_manifest['context_sha256']:raise ValueError('parent context identity or digest mismatch')
    uc.mem_write(previous,struct.pack('<I',0));ctx=uc.context_save()
    if len(raw)!=ctx.size:raise ValueError('incompatible parent context')
    ctypes.memmove(ctx.context,raw,len(raw));uc.context_restore(ctx);parent_sp=uc.reg_read(UC_X86_REG_RSP);parent_pc=uc.reg_read(UC_X86_REG_RIP)
    if imports.get(parent_pc,'').lower()!='kernel32.dll!waitforsingleobjectex' or hex(uc.reg_read(UC_X86_REG_RCX))!=handle or not stack<=parent_sp<=stack+0x200000-8:raise ValueError('parent wait does not match worker release')
    state.setdefault('synthetic_schedule',[]).append({'action':'handoff worker semaphore release to blocked parent','handle':handle,'previous_count':0,'worker_checkpoint':str(a.resume_checkpoint),'parent_checkpoint':str(parent_root),'assumption':'immediate waiter wake; shared TLS, reused child stack, catalog failure and worker timing synthetic','host_api_called':False})
    state['deferred_worker_paused']={'checkpoint':str(a.resume_checkpoint),'reason':'paused at ReleaseSemaphore; previous-count output written; call return pending'};state.pop('dynamic_worker_experiment',None)
    set_teb_stack(stack);uc.reg_write(UC_X86_REG_RAX,0);uc.reg_write(UC_X86_REG_RSP,parent_sp+8);pc=struct.unpack('<Q',uc.mem_read(parent_sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc)
   if a.run_deferred_worker_no_catalog:
    sp=uc.reg_read(UC_X86_REG_RSP);deferred=state.get('deferred_dynamic_worker',{});handle=hex(uc.reg_read(UC_X86_REG_RCX))
    if imports.get(pc,'').lower()!='kernel32.dll!waitforsingleobjectex' or handle!='0x7b0000000020' or state.get('fake_semaphores',{}).get(handle,{}).get('count')!=0 or deferred.get('entry')!='0x170f53470' or deferred.get('argument')!='0x0' or not stack<=sp<=stack+0x200000-8:raise ValueError('unexpected deferred-worker scheduling checkpoint')
    if not any(lo<=child_stack and child_stack+0x200000<=hi+1 for lo,hi,_ in uc.mem_regions()):raise ValueError('expected synthetic worker stack')
    state['dynamic_worker_experiment']={'entry':'0x170f53470','argument':'0x0','parent_call_stack':hex(sp),'parent_wait_handle':handle,'parent_checkpoint':str(a.resume_checkpoint),'assumption':'deferred worker runs after blocked parent; shared TLS, reused worker stack, no thread attach'}
    state['synthetic_no_catalog']=True;state.setdefault('synthetic_trust_assumptions',[]).append({'api':'CryptCATAdminAcquireContext2','assumption':'hypothetical unavailable catalog for scheduled worker','host_api_called':False})
    uc.mem_write(child_stack,bytes(0x200000));set_teb_stack(child_stack);worker_sp=child_stack+0x1feff8;uc.mem_write(worker_sp,struct.pack('<Q',ret));uc.reg_write(UC_X86_REG_RSP,worker_sp)
    for reg in (UC_X86_REG_RAX,UC_X86_REG_RBX,UC_X86_REG_RBP,UC_X86_REG_RSI,UC_X86_REG_RDI,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9,UC_X86_REG_R10,UC_X86_REG_R11,UC_X86_REG_R12,UC_X86_REG_R13,UC_X86_REG_R14,UC_X86_REG_R15):uc.reg_write(reg,0)
    uc.reg_write(UC_X86_REG_RCX,0);uc.reg_write(UC_X86_REG_EFLAGS,0x202);pc=0x170f53470;uc.reg_write(UC_X86_REG_RIP,pc)
   if a.assume_no_catalog:
    sp=uc.reg_read(UC_X86_REG_RSP);out=uc.reg_read(UC_X86_REG_RCX);module=next(m for m in state['synthetic_peb_modules'] if m['name']=='wintrust.dll')
    if pc!=int(module['base'],16)+0x3650 or not child_stack<=sp<=child_stack+0x200000-8 or not child_stack<=out<=child_stack+0x200000-8:raise ValueError('unexpected catalog context checkpoint')
    state['synthetic_no_catalog']=True;state.setdefault('synthetic_trust_assumptions',[]).append({'api':'CryptCATAdminAcquireContext2','return':False,'assumption':'hypothetical unavailable catalog; no host trust API','host_api_called':False});uc.reg_write(UC_X86_REG_RAX,0);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc)
   if a.resume_parent_context:
    worker=state.get('dynamic_worker_experiment',{});wait=hex(uc.reg_read(UC_X86_REG_RCX));worker_pc=uc.reg_read(UC_X86_REG_RIP)
    duration=uc.reg_read(UC_X86_REG_RCX);sleep=imports.get(worker_pc,'').lower()=='kernel32.dll!sleep' and worker.get('entry')=='0x170c151a0' and 0<duration<=10000
    if not sleep and (imports.get(worker_pc,'').lower()!='kernel32.dll!waitforsingleobjectex' or worker.get('entry')!='0x171b86650'):raise ValueError('worker not at expected wait')
    blocked=sleep or (wait in state.get('fake_semaphores',{}) and state['fake_semaphores'][wait]['count']==0) or (wait in state.get('fake_events',{}) and state['fake_events'][wait]['signaled']==0)
    if sleep:wait=f'sleep:{duration}ms'
    if not blocked:raise ValueError('worker wait is not unsignaled')
    parent_root=a.resume_parent_context;parent_manifest=json.loads((parent_root/'manifest.json').read_text(encoding='utf-8'));raw=(parent_root/'context.bin').read_bytes()
    if parent_manifest['identity']!=checkpoint_identity or hashlib.sha256(raw).hexdigest()!=parent_manifest['context_sha256']:raise ValueError('parent context identity or digest mismatch')
    ctx=uc.context_save()
    if len(raw)!=ctx.size:raise ValueError('incompatible parent context')
    ctypes.memmove(ctx.context,raw,len(raw));uc.context_restore(ctx);sp=uc.reg_read(UC_X86_REG_RSP);parent_pc=uc.reg_read(UC_X86_REG_RIP);handle=hex(uc.reg_read(UC_X86_REG_RCX));threads=[t for t in state.get('synthetic_suspended_threads',[]) if t['handle']==handle]
    if imports.get(parent_pc,'').lower()!='kernel32.dll!resumethread' or len(threads)!=1 or threads[0]['suspend_count']!=1 or hex(threads[0]['argument'])!=worker.get('argument') or not stack<=sp<=stack+0x200000-8:raise ValueError('parent context does not match worker')
    threads[0].update(suspend_count=0,wait_handle=wait,worker_context_checkpoint=str(a.resume_checkpoint),assumption='worker ran immediately to observed wait or sleep; memory retained, shared TLS and thread attach approximated')
    state.setdefault('synthetic_schedule',[]).append({'action':'restore parent after worker wait','worker':handle,'wait_handle':wait,'parent_context':str(parent_root),'worker_checkpoint':str(a.resume_checkpoint)})
    set_teb_stack(stack);uc.reg_write(UC_X86_REG_RAX,1);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc);state.pop('dynamic_worker_experiment',None)
   if a.watch_additional_registry:
    state['additional_registry_watch']={'file':str(a.watch_additional_registry),'sha256':hashlib.sha256(a.watch_additional_registry.read_bytes()).hexdigest(),'assumption':'additional passive guest-write observations and modeled-write stops'}
    observed=json.loads(a.watch_additional_registry.read_text(encoding='utf-8-sig'))
    def watched_read(uc,access,address,size,value,user):
     samples=state.setdefault('additional_registry_reads',[])
     for point in intersections(user,address,size):
      if len(samples)<100000:samples.append({'object':hex(point),'address':hex(address),'size':size,'rip':hex(uc.reg_read(UC_X86_REG_RIP)),'instruction':state['instructions'],'registers':{name:hex(uc.reg_read(reg)) for name,reg in (('rax',UC_X86_REG_RAX),('rbx',UC_X86_REG_RBX),('rcx',UC_X86_REG_RCX),('rdx',UC_X86_REG_RDX),('rsi',UC_X86_REG_RSI),('rdi',UC_X86_REG_RDI),('rbp',UC_X86_REG_RBP),('rsp',UC_X86_REG_RSP),('r8',UC_X86_REG_R8),('r9',UC_X86_REG_R9),('r13',UC_X86_REG_R13),('r15',UC_X86_REG_R15))}})
    points=sorted({int(c['pointer'],16) for row in observed['rows'] for c in row['registry_candidates']})
    for lo,hi in group_ranges(points):uc.hook_add(UC_HOOK_MEM_READ,watched_read,[p for p in points if lo<=p<=hi],lo,hi)
   if a.assume_worker_waits:
    sp=uc.reg_read(UC_X86_REG_RSP);handle=hex(uc.reg_read(UC_X86_REG_RCX));threads=[t for t in state.get('synthetic_suspended_threads',[]) if t['handle']==handle]
    if imports.get(pc,'').lower()!='kernel32.dll!resumethread' or len(threads)!=1 or threads[0]['suspend_count']!=1 or threads[0]['argument'] not in (2,5) or not stack<=sp<=stack+0x200000-8:raise ValueError('unexpected worker resume checkpoint')
    wait_handle='0x7b0000000010' if threads[0]['argument']==2 else '0x7c0000000090'
    if threads[0]['argument']==2 and state.get('fake_semaphores',{}).get(wait_handle,{}).get('count')!=0 or threads[0]['argument']==5 and state.get('fake_events',{}).get(wait_handle,{}).get('signaled')!=0:raise ValueError('worker wait object is not in observed state')
    threads[0]['suspend_count']=0;threads[0]['assumption']='worker assumed blocked at unsignaled object observed in isolated replay; worker-side effects not merged';threads[0]['wait_handle']=wait_handle
    uc.reg_write(UC_X86_REG_RAX,1);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc)
   if a.trace_suspended_worker:
    sp=uc.reg_read(UC_X86_REG_RSP);handle=hex(uc.reg_read(UC_X86_REG_RCX));threads=[t for t in state.get('synthetic_suspended_threads',[]) if t['handle']==handle]
    if imports.get(pc,'').lower()!='kernel32.dll!resumethread' or len(threads)!=1 or threads[0]['suspend_count']!=1 or not stack<=sp<=stack+0x200000-8:raise ValueError('unexpected suspended worker checkpoint')
    t=threads[0];entry=int(t['entry'],16);arg=t['argument']
    if not any(lo<=child_stack and child_stack+0x200000<=hi+1 for lo,hi,_ in uc.mem_regions()):raise ValueError('expected synthetic worker stack')
    state['dynamic_worker_experiment']={'entry':hex(entry),'argument':hex(arg),'parent_call_stack':hex(sp),'assumption':'isolated immediate suspended-worker replay; shared synthetic TLS and no concurrent parent or thread attach'}
    uc.mem_write(child_stack,bytes(0x200000));set_teb_stack(child_stack);worker_sp=child_stack+0x1feff8;uc.mem_write(worker_sp,struct.pack('<Q',ret));uc.reg_write(UC_X86_REG_RSP,worker_sp)
    for reg in (UC_X86_REG_RAX,UC_X86_REG_RBX,UC_X86_REG_RBP,UC_X86_REG_RSI,UC_X86_REG_RDI,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9,UC_X86_REG_R10,UC_X86_REG_R11,UC_X86_REG_R12,UC_X86_REG_R13,UC_X86_REG_R14,UC_X86_REG_R15):uc.reg_write(reg,0)
    uc.reg_write(UC_X86_REG_RCX,arg);uc.reg_write(UC_X86_REG_EFLAGS,0x202);uc.reg_write(UC_X86_REG_RIP,entry);pc=entry
   if a.synthetic_appdata_path:
    sp=uc.reg_read(UC_X86_REG_RSP)
    if pc!=exception_mem+0x7090 or not stack<=sp<=stack+0x200000-0x30 or uc.reg_read(UC_X86_REG_RCX)!=0 or uc.reg_read(UC_X86_REG_RDX)!=0x1a or uc.reg_read(UC_X86_REG_R8)!=0 or uc.reg_read(UC_X86_REG_R9)!=0:raise ValueError('unexpected synthetic shell folder checkpoint')
    out=struct.unpack('<Q',uc.mem_read(sp+0x28,8))[0];value='C:\\Preservation\\AppData'.encode('utf-16le')+b'\0\0'
    if not stack<=out<=stack+0x200000-len(value):raise ValueError('unexpected shell folder destination')
    uc.mem_write(out,value);state.setdefault('synthetic_shell_assumptions',[]).append({'folder':'CSIDL_APPDATA','path':'C:\\Preservation\\AppData','host_api_called':False});uc.reg_write(UC_X86_REG_RAX,0);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc)
   if a.assume_not_steam_deck:
    sp=uc.reg_read(UC_X86_REG_RSP)
    if pc!=0x7d5000002220 or not stack<=sp<=stack+0x200000-8 or uc.reg_read(UC_X86_REG_RCX)!=0x7d5000000000 or state.get('synthetic_steam_interface',{}).get('version')!='SteamUtils010':raise ValueError('unexpected Steam Deck method checkpoint')
    state.setdefault('synthetic_steam_assumptions',[]).append({'interface':'SteamUtils010','slot':34,'method':'IsSteamRunningOnSteamDeck','return':False,'assumption':'hypothetical non-Deck client','host_api_called':False})
    uc.reg_write(UC_X86_REG_RAX,0);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc)
   if a.trace_steam_interface:
    sp=uc.reg_read(UC_X86_REG_RSP);symbol=state.get('virtual_steam_markers',{}).get(hex(pc));version_ptr=uc.reg_read(UC_X86_REG_RDX)
    if symbol!='SteamInternal_FindOrCreateUserInterface' or not stack<=sp<=stack+0x200000-8 or not base+0x32c84000<=version_ptr<=base+0x33534000-64:raise ValueError('unexpected Steam interface checkpoint')
    version=bytes(uc.mem_read(version_ptr,64)).split(b'\0',1)[0].decode('ascii')
    if version not in ('SteamUtils010','SteamInput006'):raise ValueError('unexpected Steam interface version')
    if version=='SteamInput006' and uc.reg_read(UC_X86_REG_RCX)!=1:raise ValueError('unexpected synthetic Steam user handle')
    fake=0x7d5000000000 if version=='SteamUtils010' else 0x7d5200000000;state_key='synthetic_steam_interface' if version=='SteamUtils010' else 'synthetic_steam_input'
    if not state.get(state_key):uc.mem_map(fake,0x3000);uc.mem_write(fake,struct.pack('<Q',fake+0x1000));uc.mem_write(fake+0x1000,b''.join(struct.pack('<Q',fake+0x2000+i*16) for i in range(256)));uc.mem_write(fake+0x2000,b'\x90'*0x1000)
    state[state_key]={'version':version,'object':hex(fake),'assumption':'inspection-only sentinel, every method stops; no Steam client or service','host_api_called':False}
    uc.reg_write(UC_X86_REG_RAX,fake);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc)
   if a.trace_steam_context_callback:
    sp=uc.reg_read(UC_X86_REG_RSP);symbol=state.get('virtual_steam_markers',{}).get(hex(pc));context=uc.reg_read(UC_X86_REG_RCX)
    if symbol!='SteamInternal_ContextInit' or not stack+0x40<=sp<=stack+0x200000-8 or not base+0x33534000<=context<=base+0x392a6be1-24:raise ValueError('unexpected Steam context checkpoint')
    callback,counter,slot=struct.unpack('<QQQ',bytes(uc.mem_read(context,24)))
    if not base+0x1000<=callback<base+0x32c84000 or counter or slot:raise ValueError('unexpected Steam context fields')
    state['pending_steam_context_callback']={'context':hex(context),'callback':hex(callback),'parent_sp':hex(sp),'return':hex(struct.unpack('<Q',uc.mem_read(sp,8))[0]),'assumption':'invoke guest callback immediately with synthetic context, no Steam interface initialized'}
    uc.mem_write(sp-0x30,struct.pack('<Q',exception_mem+0x8f00));uc.reg_write(UC_X86_REG_RSP,sp-0x30);uc.reg_write(UC_X86_REG_RCX,context+16);uc.reg_write(UC_X86_REG_RIP,callback);pc=callback
   if a.assume_steam_init_success:
    sp=uc.reg_read(UC_X86_REG_RSP);symbol=state.get('virtual_steam_markers',{}).get(hex(pc));error_ptr=uc.reg_read(UC_X86_REG_RDX)
    if symbol!='SteamInternal_SteamAPI_Init' or error_ptr!=0 or not stack<=sp<=stack+0x200000-8:raise ValueError('unexpected Steam init checkpoint')
    state.setdefault('synthetic_steam_assumptions',[]).append({'symbol':symbol,'return':0,'assumption':'hypothetical successful initialization, no Steam session exists','host_api_called':False})
    uc.reg_write(UC_X86_REG_RAX,0);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc)
   if a.assume_steam_no_restart:
    sp=uc.reg_read(UC_X86_REG_RSP);symbol=state.get('virtual_steam_markers',{}).get(hex(pc));appid=uc.reg_read(UC_X86_REG_RCX)&0xffffffff
    if symbol!='SteamAPI_RestartAppIfNecessary' or not stack<=sp<=stack+0x200000-8:raise ValueError('unexpected Steam restart checkpoint')
    state.setdefault('synthetic_steam_assumptions',[]).append({'symbol':symbol,'appid':appid,'return':False,'assumption':'explore no-relaunch branch without Steam; not an initialized Steam session','host_api_called':False})
    uc.reg_write(UC_X86_REG_RAX,0);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc)
   if a.virtual_steam_module:
    steam_raw=a.virtual_steam_module.read_bytes();steam_digest=hashlib.sha256(steam_raw).hexdigest()
    if steam_digest!='9d6d2972c1571a2a058d79a8376e26a33d33813f29d93c3ca6e35adaddcd56de':raise ValueError('unexpected preserved Steam module')
    steam_pe=pefile.PE(data=steam_raw,fast_load=True);steam_pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']]);steam_exports=[entry.name.decode('ascii') for entry in steam_pe.DIRECTORY_ENTRY_EXPORT.symbols if entry.name and not entry.forwarder]
    state['virtual_steam_module']={'sha256':steam_digest,'exports':steam_exports,'assumption':'PE export names and file existence only; no native DLL execution or Steam connection'}
   if a.virtual_sku_config:
    raw=a.virtual_sku_config.read_bytes();digest=hashlib.sha256(raw).hexdigest()
    if digest!='d40b2410762b63b2ce42c8d79a9388314288228bc456cdff7796900da89e170f':raise ValueError('unexpected preserved sku config')
    state['virtual_sku_config']={'sha256':digest,'data':raw.hex(),'position':0,'assumption':'explicitly preloaded preserved config; no guest filesystem access'}
   if a.defer_dynamic_worker:
    sp=uc.reg_read(UC_X86_REG_RSP);entry=uc.reg_read(UC_X86_REG_R8);arg=uc.reg_read(UC_X86_REG_R9)
    expected=int(next(m for m in state['synthetic_peb_modules'] if m['name']=='kernel32.dll')['base'],16)+next(x.address for x in kp.DIRECTORY_ENTRY_EXPORT.symbols if x.name==b'CreateThread')
    if pc!=expected or entry!=0x170f53470 or arg!=0 or not stack<=sp<=stack+0x200000-0x38:raise ValueError('unexpected deferred worker checkpoint')
    flags=struct.unpack('<Q',uc.mem_read(sp+0x28,8))[0];tidptr=struct.unpack('<Q',uc.mem_read(sp+0x30,8))[0]
    if flags!=0 or not stack<=tidptr<=stack+0x200000-4:raise ValueError('unexpected deferred worker arguments')
    state['deferred_dynamic_worker']={'entry':hex(entry),'argument':hex(arg),'handle':'0x7d3000000001','assumption':'worker omitted while exploring parent; not evidence of native scheduling'}
    uc.mem_write(tidptr,struct.pack('<I',3));uc.reg_write(UC_X86_REG_RAX,0x7d3000000001);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc)
   if a.trace_dynamic_worker:
    sp=uc.reg_read(UC_X86_REG_RSP);entry=uc.reg_read(UC_X86_REG_R8);arg=uc.reg_read(UC_X86_REG_R9)
    if pc!=int(next(m for m in state['synthetic_peb_modules'] if m['name']=='kernel32.dll')['base'],16)+next(x.address for x in kp.DIRECTORY_ENTRY_EXPORT.symbols if x.name==b'CreateThread') or entry!=0x170f53470 or arg!=0:raise ValueError('unexpected dynamic worker checkpoint')
    if not any(lo<=child_stack and child_stack+0x200000<=hi+1 for lo,hi,_ in uc.mem_regions()):raise ValueError('expected synthetic worker stack')
    state['dynamic_worker_experiment']={'entry':hex(entry),'argument':hex(arg),'parent_call_stack':hex(sp),'assumption':'isolated immediate worker; shared synthetic TLS and no concurrent parent; thread attach not modeled'}
    set_teb_stack(child_stack);worker_sp=child_stack+0x1feff8;uc.mem_write(worker_sp,struct.pack('<Q',ret));uc.reg_write(UC_X86_REG_RSP,worker_sp)
    for reg in (UC_X86_REG_RAX,UC_X86_REG_RBX,UC_X86_REG_RBP,UC_X86_REG_RSI,UC_X86_REG_RDI,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9,UC_X86_REG_R10,UC_X86_REG_R11,UC_X86_REG_R12,UC_X86_REG_R13,UC_X86_REG_R14,UC_X86_REG_R15):uc.reg_write(reg,0)
    uc.reg_write(UC_X86_REG_RCX,arg);uc.reg_write(UC_X86_REG_EFLAGS,0x202);uc.reg_write(UC_X86_REG_RIP,entry);pc=entry
   while True:
    try:uc.emu_start(pc,0,count=a.count,timeout=a.timeout_ms*1000)
    except UcError:
     if state.pop('pending_fake_catalog',False):
      sp=uc.reg_read(UC_X86_REG_RSP);out=uc.reg_read(UC_X86_REG_RCX);calls=state.setdefault('synthetic_trust_assumptions',[])
      if not child_stack<=sp<=child_stack+0x200000-8 or not child_stack<=out<=child_stack+0x200000-8 or len(calls)>=256:state['stop']={'kind':'unsupported_synthetic_catalog'};break
      calls.append({'api':'CryptCATAdminAcquireContext2','return':False,'assumption':'hypothetical unavailable catalog','host_api_called':False});uc.reg_write(UC_X86_REG_RAX,0);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc);state['stop']=None;continue
     if state.pop('pending_fake_system_directory',False):
      sp=uc.reg_read(UC_X86_REG_RSP);out=uc.reg_read(UC_X86_REG_RCX);capacity=uc.reg_read(UC_X86_REG_RDX);value='C:\\Windows\\System32'.encode('utf-16le')+b'\0\0'
      if not child_stack<=sp<=child_stack+0x200000-8 or not child_stack<=out<=child_stack+0x200000-len(value) or not len(value)//2<=capacity<=4096:state['stop']={'kind':'unsupported_fake_system_directory','address':hex(out),'capacity':capacity};break
      uc.mem_write(out,value);state.setdefault('fake_worker_operations',[]).append({'operation':'GetSystemDirectoryW','value':'C:\\Windows\\System32','assumption':'fixed synthetic path','host_api_called':False});uc.reg_write(UC_X86_REG_RAX,len(value)//2-1);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc);state['stop']=None;continue
     if state.pop('pending_fake_ntquery_system_information',False):
      sp=uc.reg_read(UC_X86_REG_RSP);kind=uc.reg_read(UC_X86_REG_RCX);out=uc.reg_read(UC_X86_REG_RDX);length=uc.reg_read(UC_X86_REG_R8);returned=uc.reg_read(UC_X86_REG_R9)
      if not stack<=sp<=stack+0x200000-8 or (kind,length) not in ((0x91,2),(0x67,8)) or not stack<=out<=stack+0x200000-length or not stack<=returned<=stack+0x200000-4:state['stop']={'kind':'unsupported_fake_ntquery_system_information','class':hex(kind),'length':length};break
      if kind==0x67 and struct.unpack('<I',bytes(uc.mem_read(out,4)))[0]!=8:state['stop']={'kind':'unsupported_fake_code_integrity_header'};break
      payload=b'\x01\x01' if kind==0x91 else struct.pack('<II',8,1);uc.mem_write(out,payload);uc.mem_write(returned,struct.pack('<I',length));state.setdefault('fake_ntquery_system_information',[]).append({'class':hex(kind),'assumption':'synthetic secure boot enabled and capable' if kind==0x91 else 'synthetic code integrity enabled','host_api_called':False});uc.reg_write(UC_X86_REG_RAX,0);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc);state['stop']=None;continue
     if state.pop('pending_fake_loadlibraryexw',False):
      sp=uc.reg_read(UC_X86_REG_RSP);ptr=uc.reg_read(UC_X86_REG_RCX);file=uc.reg_read(UC_X86_REG_RDX);flags=uc.reg_read(UC_X86_REG_R8)
      if not stack<=sp<=stack+0x200000-8 or not base+0x32c84000<=ptr<=base+0x33534000-256 or file!=0 or flags!=0x800:state['stop']={'kind':'unsupported_fake_loadlibraryexw','pointer':hex(ptr),'flags':hex(flags)};break
      raw=bytes(uc.mem_read(ptr,256));end=next((i for i in range(0,len(raw)-1,2) if raw[i:i+2]==b'\0\0'),-1);name=raw[:end].decode('utf-16le').lower() if end>=0 else ''
      if name not in ('user32.dll','shlwapi.dll','gdi32.dll','shell32.dll','ole32.dll','oleaut32.dll','d3d11.dll','d3d9.dll','dxgi.dll','winmm.dll','msacm32.dll','winhttp.dll','wininet.dll','setupapi.dll','imm32.dll','d3d12.dll','wintrust.dll','wlanapi.dll'):state['stop']={'kind':'unsupported_fake_loadlibraryexw','name':name};break
      libs=state.setdefault('fake_library_handles',{});result=libs.setdefault(name,0x7d1000000000+len(libs)*0x1000);state.setdefault('fake_library_loads',[]).append({'name':name,'flags':hex(flags),'host_api_called':False});uc.reg_write(UC_X86_REG_RAX,result);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc);state['stop']=None;continue
     if state.pop('pending_fake_ntprotect_virtual_memory',False):
      sp=uc.reg_read(UC_X86_REG_RSP);process=uc.reg_read(UC_X86_REG_RCX);baseptr=uc.reg_read(UC_X86_REG_RDX);sizeptr=uc.reg_read(UC_X86_REG_R8);newprot=uc.reg_read(UC_X86_REG_R9)&0xffffffff
      if not stack<=sp<=stack+0x200000-0x30 or process!=0xffffffffffffffff or not stack<=baseptr<=stack+0x200000-8 or not stack<=sizeptr<=stack+0x200000-8:state['stop']={'kind':'unsupported_fake_ntprotect_virtual_memory'};break
      oldptr=struct.unpack('<Q',bytes(uc.mem_read(sp+0x28,8)))[0];requested=struct.unpack('<Q',bytes(uc.mem_read(baseptr,8)))[0];size=struct.unpack('<Q',bytes(uc.mem_read(sizeptr,8)))[0];start=requested&~0xfff;end=(requested+size+4095)&~4095
      sysmod=next((m for m in state.get('synthetic_peb_modules',[]) if int(m['base'],16)<=requested and requested+size<=int(m['base'],16)+m['size']),None)
      oldptr_valid=stack<=oldptr<=stack+0x200000-4 or base+0x33534000<=oldptr<=base+0x392a6be1-4
      if oldptr_valid and any(oldptr<point+0x40 and point<oldptr+4 for point in watch_points):state['stop']={'kind':'watched_fake_ntprotect_output','address':hex(oldptr)};break
      if sysmod and newprot in (0x40,0x20) and 1<=size<=4096 and oldptr_valid:
       old=0x20 if newprot==0x40 else 0x40;uc.mem_protect(start,end-start,UC_PROT_READ|UC_PROT_WRITE if newprot==0x40 else UC_PROT_READ);uc.mem_write(oldptr,struct.pack('<I',old));uc.mem_write(baseptr,struct.pack('<Q',start));uc.mem_write(sizeptr,struct.pack('<Q',end-start));state.setdefault('fake_system_protections',[]).append({'module':sysmod['name'],'address':hex(requested),'size':size,'requested':hex(newprot),'actual':'read/write, no execute' if newprot==0x40 else 'read only, no execute','host_api_called':False});uc.reg_write(UC_X86_REG_RAX,0);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc);state['stop']=None;continue
      if newprot!=0x20 or not stack<=oldptr<=stack+0x200000-4 or not 1<=size<=0x1000000 or not any(lo<=start<end<=hi for lo,hi in state.get('fake_virtual_commits',[])):state['stop']={'kind':'unsupported_fake_ntprotect_request','address':hex(requested),'size':size,'protection':hex(newprot),'old_protection_pointer':hex(oldptr),'module':sysmod['name'] if sysmod else None};break
      for page in range(start,end,4096):
       if page in pages:uc.mem_protect(page,4096,UC_PROT_READ)
      state.setdefault('fake_virtual_exec_requests',[]).append((start,end));uc.mem_write(oldptr,struct.pack('<I',4));uc.mem_write(baseptr,struct.pack('<Q',start));uc.mem_write(sizeptr,struct.pack('<Q',end-start));state.setdefault('fake_ntprotections',[]).append({'address':hex(start),'size':end-start,'requested':'execute/read','actual':'read only; execution disabled','host_api_called':False});uc.reg_write(UC_X86_REG_RAX,0);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc);state['stop']=None;continue
     if state.pop('pending_fake_ntallocate_virtual_memory',False):
      sp=uc.reg_read(UC_X86_REG_RSP);process=uc.reg_read(UC_X86_REG_RCX);baseptr=uc.reg_read(UC_X86_REG_RDX);zero=uc.reg_read(UC_X86_REG_R8);sizeptr=uc.reg_read(UC_X86_REG_R9)
      baseptr_valid=stack<=baseptr<=stack+0x200000-8 or base+0x33534000<=baseptr<=base+0x392a6be1-8
      if not stack<=sp<=stack+0x200000-0x38 or process!=0xffffffffffffffff or zero!=0 or not baseptr_valid or not stack<=sizeptr<=stack+0x200000-8:state['stop']={'kind':'unsupported_fake_ntallocate_virtual_memory','base_pointer':hex(baseptr),'size_pointer':hex(sizeptr),'zero_bits':hex(zero),'process':hex(process)};break
      if any(baseptr<point+0x40 and point<baseptr+8 for point in watch_points):state['stop']={'kind':'watched_fake_ntallocate_output','address':hex(baseptr)};break
      kind,prot=struct.unpack('<QQ',bytes(uc.mem_read(sp+0x28,16)));requested=struct.unpack('<Q',bytes(uc.mem_read(baseptr,8)))[0];size=struct.unpack('<Q',bytes(uc.mem_read(sizeptr,8)))[0];kind&=0xffffffff;prot&=0xffffffff;start=requested&~0xfff;end=(requested+size+4095)&~4095
      if kind!=0x3000 or prot!=4 or not 1<=size<=0x1000000:state['stop']={'kind':'unsupported_fake_ntallocate_request','address':hex(requested),'size':size,'type':hex(kind),'protection':hex(prot)};break
      if requested==0:
       count=state.get('fake_ntautomatic_allocations',0)
       if count>=16:state['stop']={'kind':'fake_ntautomatic_allocation_limit'};break
       start=0x7d4000000000+count*0x1000000;end=start+((size+4095)&~4095);state['fake_ntautomatic_allocations']=count+1
      occupied=[(lo,hi+1) for lo,hi,_ in uc.mem_regions()]+[(int(r['address'],16),int(r['address'],16)+r['size']) for r in state.get('fake_virtual_reservations',[])]+[(lo,hi) for lo,hi in state.get('fake_virtual_commits',[])]
      if not (0x7e0000000000<=start<end<=0x7f0000000000 or requested==0 and 0x7d4000000000<=start<end<=0x7d4010000000) or any(start<hi and lo<end for lo,hi in occupied):
       state.setdefault('fake_ntallocations',[]).append({'address':hex(start),'size':end-start,'status':'conflicting addresses','host_api_called':False});uc.reg_write(UC_X86_REG_RAX,0xc0000018);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc);state['stop']=None;continue
      state.setdefault('fake_virtual_commits',[]).append((start,end));uc.mem_write(baseptr,struct.pack('<Q',start));uc.mem_write(sizeptr,struct.pack('<Q',end-start));state.setdefault('fake_ntallocations',[]).append({'address':hex(start),'size':end-start,'host_api_called':False});uc.reg_write(UC_X86_REG_RAX,0);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc);state['stop']=None;continue
     if state.pop('pending_fake_ntquery_virtual_memory',False):
      sp=uc.reg_read(UC_X86_REG_RSP);process=uc.reg_read(UC_X86_REG_RCX);address=uc.reg_read(UC_X86_REG_RDX);kind=uc.reg_read(UC_X86_REG_R8);out=uc.reg_read(UC_X86_REG_R9)
      if not stack<=sp<=stack+0x200000-0x38 or process!=0xffffffffffffffff or kind!=0 or not stack<=out<=stack+0x200000-48:state['stop']={'kind':'unsupported_fake_ntquery_virtual_memory'};break
      length,returned=struct.unpack('<QQ',bytes(uc.mem_read(sp+0x28,16)));module=next((m for m in state['synthetic_peb_modules'] if int(m['base'],16)<=address<int(m['base'],16)+m['size']),None)
      if length!=48 or not stack<=returned<=stack+0x200000-8:state['stop']={'kind':'unsupported_fake_ntquery_virtual_memory','address':hex(address),'length':length};break
      if module is None:
       allocated=next(((lo,hi) for lo,hi in state.get('fake_virtual_commits',[]) if lo<=address<hi),None)
       if allocated:
        lo,hi=allocated;uc.mem_write(out,struct.pack('<QQIIQIIII',lo,lo,4,0,hi-lo,0x1000,4,0x20000,0));uc.mem_write(returned,struct.pack('<Q',48));state.setdefault('fake_ntquery_virtual_memory',[]).append({'address':hex(address),'assumption':'private synthetic committed range','host_api_called':False});uc.reg_write(UC_X86_REG_RAX,0);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc);state['stop']=None;continue
       occupied=[(lo,hi+1) for lo,hi,_ in uc.mem_regions()]+[(int(r['address'],16),int(r['address'],16)+r['size']) for r in state.get('fake_virtual_reservations',[])]+[(lo,hi) for lo,hi in state.get('fake_virtual_commits',[])];prior=max((hi for lo,hi in occupied if hi<=address),default=None);following=min((lo for lo,hi in occupied if lo>address),default=0x800000000000)
       if prior is None or following is None or not prior<=address<following or any(lo<=address<hi for lo,hi in occupied):state['stop']={'kind':'unsupported_fake_ntquery_free','address':hex(address)};break
       uc.mem_write(out,struct.pack('<QQIIQIIII',prior,0,0,0,following-prior,0x10000,1,0,0));uc.mem_write(returned,struct.pack('<Q',48));state.setdefault('fake_ntquery_virtual_memory',[]).append({'address':hex(address),'assumption':'free synthetic gap between modeled DLLs','host_api_called':False});uc.reg_write(UC_X86_REG_RAX,0);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc);state['stop']=None;continue
      mb=int(module['base'],16);raw=Path('C:/Windows/System32',module['name']).read_bytes()
      if hashlib.sha256(raw).hexdigest()!=module['sha256']:raise ValueError('system module changed')
      mp=pefile.PE(data=raw,fast_load=True);sec=next((s for s in mp.sections if s.VirtualAddress<=address-mb<((s.VirtualAddress+max(s.Misc_VirtualSize,s.SizeOfRawData)+4095)&~4095)),None)
      if address-mb<mp.OPTIONAL_HEADER.SizeOfHeaders:start=mb;end=mb+((mp.OPTIONAL_HEADER.SizeOfHeaders+4095)&~4095);protection=2
      elif sec is not None:
       start=mb+(sec.VirtualAddress&~0xfff);end=mb+((sec.VirtualAddress+max(sec.Misc_VirtualSize,sec.SizeOfRawData)+4095)&~4095);executable=bool(sec.Characteristics&0x20000000);writable=bool(sec.Characteristics&0x80000000);readable=bool(sec.Characteristics&0x40000000);protection=(0x40 if writable else 0x20 if readable else 0x10) if executable else (4 if writable else 2 if readable else 1)
      else:state['stop']={'kind':'unsupported_fake_ntquery_section','address':hex(address)};break
      uc.mem_write(out,struct.pack('<QQIIQIIII',start,mb,0x20,0,end-start,0x1000,protection,0x1000000,0));uc.mem_write(returned,struct.pack('<Q',48));state.setdefault('fake_ntquery_virtual_memory',[]).append({'address':hex(address),'module':module['name'],'nominal_protection':hex(protection),'host_api_called':False});uc.reg_write(UC_X86_REG_RAX,0);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc);state['stop']=None;continue
     if state.pop('pending_fake_dll_notification',False):
      sp=uc.reg_read(UC_X86_REG_RSP);flags=uc.reg_read(UC_X86_REG_RCX);callback=uc.reg_read(UC_X86_REG_RDX);context=uc.reg_read(UC_X86_REG_R8);cookie=uc.reg_read(UC_X86_REG_R9)
      if flags!=0 or not base+0x1000<=callback<base+0x32c84000 or not stack<=sp<=stack+0x200000-8 or not stack<=cookie<=stack+0x200000-8:state['stop']={'kind':'unsupported_fake_dll_notification'};break
      uc.mem_write(cookie,struct.pack('<Q',0x7d3000000000));state.setdefault('fake_dll_notifications',[]).append({'callback':hex(callback),'context':hex(context),'cookie':hex(cookie),'host_api_called':False,'notifications_delivered':False});uc.reg_write(UC_X86_REG_RAX,0);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc);state['stop']=None;continue
     heap_call=state.pop('pending_fake_heap_call',None)
     if heap_call:
      sp=uc.reg_read(UC_X86_REG_RSP);args=[uc.reg_read(r) for r in (UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9)]
      if not stack<=sp<=stack+0x200000-8 or (heap_call=='information' and args!=[0,1,0,0]) or (heap_call=='create' and args[:3]!=[0,0x100000,0]):state['stop']={'kind':'unsupported_fake_heap_call','call':heap_call,'args':[hex(x) for x in args]};break
      result=1 if heap_call=='information' else 0x7d0000001000;state.setdefault('fake_system_heap_calls',[]).append({'call':heap_call,'args':[hex(x) for x in args],'result':hex(result),'host_api_called':False});uc.reg_write(UC_X86_REG_RAX,result);uc.reg_write(UC_X86_REG_RSP,sp+8);pc=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RIP,pc);state['stop']=None;continue
     fault=state.pop('pending_fault',None)
     if fault is None or not deliver_fault(fault):raise
     pc=uc.reg_read(UC_X86_REG_RIP);continue
    break
  else:
   targets=list(enumerate(callbacks)) if a.loader_sequence else [(a.index,callbacks[a.index])]
   if a.entry_after_loader:targets.append(('entry',base+pe.OPTIONAL_HEADER.AddressOfEntryPoint))
   for index,entry_pc in targets:
    if a.loader_sequence:
     uc.reg_write(UC_X86_REG_RSP,stack+0x1feff8);uc.mem_write(stack+0x1feff8,struct.pack('<Q',ret));uc.reg_write(UC_X86_REG_RCX,0 if index=='entry' else base);uc.reg_write(UC_X86_REG_RDX,0 if index=='entry' else 1);uc.reg_write(UC_X86_REG_R8,0);uc.reg_write(UC_X86_REG_R9,0);state['stop']=None
    pc=entry_pc
    while True:
     try:uc.emu_start(pc,0,count=a.count,timeout=a.timeout_ms*1000)
     except UcError:
      fault=state.pop('pending_fault',None)
      if fault is None or not deliver_fault(fault):raise
      pc=uc.reg_read(UC_X86_REG_RIP);continue
     break
    if not a.loader_sequence:break
    checkpoint={'index':index,'callback':hex(entry_pc),'stop':state['stop'] or {'kind':'budget_or_return','rip':hex(uc.reg_read(UC_X86_REG_RIP))},'cumulative_instructions':state['instructions'],'cumulative_image_writes':state['image_writes'],'tls_sha256':hashlib.sha256(bytes(uc.mem_read(tls_block,0x100000))).hexdigest()}
    state.setdefault('loader_sequence',[]).append(checkpoint)
    if checkpoint['stop']['kind']!='synthetic_return':break
   if a.follow_thread and (state.get('stop') or {}).get('import','').lower()=='kernel32.dll!createthread':
    thread_start=uc.reg_read(UC_X86_REG_R8);thread_arg=uc.reg_read(UC_X86_REG_R9)
    parent_context=uc.context_save();parent_sp=uc.reg_read(UC_X86_REG_RSP);parent_return=struct.unpack('<Q',uc.mem_read(parent_sp,8))[0];thread_id_ptr=struct.unpack('<Q',uc.mem_read(parent_sp+0x30,8))[0]
    state['fake_worker']={'start':hex(thread_start),'argument':hex(thread_arg),'tls':'shared fake TLS; thread-attach callbacks not modeled'}
    uc.mem_map(child_stack,0x200000);set_teb_stack(child_stack);sp=child_stack+0x1feff8;uc.mem_write(sp,struct.pack('<Q',ret));uc.reg_write(UC_X86_REG_RSP,sp)
    for reg in (UC_X86_REG_RAX,UC_X86_REG_RBX,UC_X86_REG_RBP,UC_X86_REG_RSI,UC_X86_REG_RDI,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9,UC_X86_REG_R10,UC_X86_REG_R11,UC_X86_REG_R12,UC_X86_REG_R13,UC_X86_REG_R14,UC_X86_REG_R15):uc.reg_write(reg,0)
    uc.reg_write(UC_X86_REG_RCX,thread_arg);uc.reg_write(UC_X86_REG_EFLAGS,0x202);state['stop']=None;state['in_fake_worker']=True;pc=thread_start
    while True:
     try:uc.emu_start(pc,0,count=a.count,timeout=a.timeout_ms*1000)
     except UcError:
      fault=state.pop('pending_fault',None)
      if fault is None or not deliver_fault(fault):raise
      pc=uc.reg_read(UC_X86_REG_RIP);continue
     break
    if a.resume_parent and (state.get('stop') or {}).get('kind')=='synthetic_return':
     state['fake_worker_outcome']={'stop':state['stop'],'aes_completed':state.get('aes_completed',0),'rdata_sha256':hashlib.sha256(bytes(uc.mem_read(base+0x32c84000,9107968))).hexdigest(),'worker_stack_sha256':hashlib.sha256(bytes(uc.mem_read(child_stack,0x200000))).hexdigest()}
     if thread_id_ptr:state['stop']={'kind':'unmodeled_thread_id_pointer','address':hex(thread_id_ptr)}
     else:
      set_teb_stack(stack);uc.context_restore(parent_context);uc.reg_write(UC_X86_REG_RAX,1);uc.reg_write(UC_X86_REG_RSP,parent_sp+8);state['stop']=None;state['in_fake_worker']=False;state['in_fake_parent']=True;pc=parent_return
      while True:
       try:uc.emu_start(pc,0,count=a.count,timeout=a.timeout_ms*1000)
       except UcError:
        fault=state.pop('pending_fault',None)
        if fault is None or not deliver_fault(fault):raise
        pc=uc.reg_read(UC_X86_REG_RIP);continue
       break
    if a.follow_second_thread and (state.get('stop') or {}).get('import','').lower()=='kernel32.dll!createthread' and state.get('fake_worker_closes'):
     thread_start=uc.reg_read(UC_X86_REG_R8);thread_arg=uc.reg_read(UC_X86_REG_R9)
     second_parent_context=uc.context_save();second_parent_sp=uc.reg_read(UC_X86_REG_RSP);second_parent_return=struct.unpack('<Q',uc.mem_read(second_parent_sp,8))[0];second_thread_id_ptr=struct.unpack('<Q',uc.mem_read(second_parent_sp+0x30,8))[0]
     state['fake_second_worker']={'start':hex(thread_start),'argument':hex(thread_arg),'tls':'shared fake TLS; thread-attach callbacks not modeled'}
     uc.mem_unmap(child_stack,0x200000);uc.mem_map(child_stack,0x200000);set_teb_stack(child_stack);sp=child_stack+0x1feff8;uc.mem_write(sp,struct.pack('<Q',ret));uc.reg_write(UC_X86_REG_RSP,sp)
     for reg in (UC_X86_REG_RAX,UC_X86_REG_RBX,UC_X86_REG_RBP,UC_X86_REG_RSI,UC_X86_REG_RDI,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9,UC_X86_REG_R10,UC_X86_REG_R11,UC_X86_REG_R12,UC_X86_REG_R13,UC_X86_REG_R14,UC_X86_REG_R15):uc.reg_write(reg,0)
     uc.reg_write(UC_X86_REG_RCX,thread_arg);uc.reg_write(UC_X86_REG_EFLAGS,0x202);state['stop']=None;state['in_fake_parent']=False;state['in_fake_worker']=True;state['in_fake_second_worker']=True;pc=thread_start
     while True:
      try:uc.emu_start(pc,0,count=a.count,timeout=a.timeout_ms*1000)
      except UcError:
       fault=state.pop('pending_fault',None)
       if fault is None or not deliver_fault(fault):raise
       pc=uc.reg_read(UC_X86_REG_RIP);continue
      break
     if a.resume_second_parent and (state.get('stop') or {}).get('kind')=='synthetic_return':
      state['fake_second_worker_outcome']={'stop':state['stop'],'cache_calls':len(state.get('fake_worker_cache_calls',[])),'image_writes':state['image_writes']}
      if second_thread_id_ptr and not stack<=second_thread_id_ptr<=stack+0x200000-4:state['stop']={'kind':'unsafe_second_thread_id_pointer','address':hex(second_thread_id_ptr)}
      else:
       if second_thread_id_ptr:
        uc.mem_write(second_thread_id_ptr,struct.pack('<I',2));state['fake_second_thread_id']={'address':hex(second_thread_id_ptr),'value':2}
       set_teb_stack(stack);uc.context_restore(second_parent_context);uc.reg_write(UC_X86_REG_RAX,2);uc.reg_write(UC_X86_REG_RSP,second_parent_sp+8);state['stop']=None;state['in_fake_worker']=False;state['in_fake_second_worker']=False;state['in_fake_parent']=True;pc=second_parent_return
       while True:
        try:uc.emu_start(pc,0,count=a.count,timeout=a.timeout_ms*1000)
        except UcError:
         fault=state.pop('pending_fault',None)
         if fault is None or not deliver_fault(fault):raise
         pc=uc.reg_read(UC_X86_REG_RIP);continue
        break
 except UcError as ex:
  if state['stop'] is None:state['stop']={'kind':'unicorn_error','message':str(ex),'rip':hex(uc.reg_read(UC_X86_REG_RIP))}
 if state['stop'] is None:state['stop']={'kind':'budget_or_return','rip':hex(uc.reg_read(UC_X86_REG_RIP))}
 if a.save_checkpoint and state['stop'].get('kind')=='constructor_checkpoint':state['saved_checkpoint']=save_checkpoint(uc,a.save_checkpoint,state,recent,checkpoint_identity)
 if a.save_at_stop and state['stop'].get('kind') in ('budget_or_return','import_marker','system_export','exception_limit','unsupported_fake_ntallocate_virtual_memory','unsupported_virtual_sku_format','dynamic_import_required','steam_api_call_required','steam_interface_method_required','synthetic_shell_folder_call','synthetic_timer_caps_call','unsupported_fake_semaphore_wait','synthetic_processor_info_call','synthetic_com_init_call','synthetic_worker_sleep','oodle_api_call_required','xinput_api_call_required','synthetic_dxgi_factory_call','dxgi_interface_method_required','dxgi_adapter_method_required','synthetic_d3d12_create_device_call','d3d12_device_method_required','synthetic_messagebox_call','dxgi_output_method_required','second_d3d12_device_method_required','unsupported_fake_worker_format_args','synthetic_loadicon_call','synthetic_loadcursor_call','synthetic_stockobject_call','synthetic_registerclass_call','synthetic_createwindow_call','synthetic_setwindowlong_call','synthetic_setwindowtext_call','synthetic_adjustrect_call','synthetic_setwindowpos_call','synthetic_getwindowlong_call','synthetic_getwindowrect_call','synthetic_getwindowlongptr_call','synthetic_getclientrect_call','synthetic_clienttoscreen_call','synthetic_monitorfromwindow_call','synthetic_getmonitorinfo_call','synthetic_setwindowlonga_call'):state['saved_stop_checkpoint']=save_checkpoint(uc,a.save_at_stop,state,recent,checkpoint_identity)
 if a.hash_worker_rdata and state.get('in_fake_worker'):state['worker_rdata_sha256']=hashlib.sha256(bytes(uc.mem_read(base+0x32c84000,9107968))).hexdigest()
 if a.hash_parent_text and state.get('in_fake_parent'):
  digest=hashlib.sha256()
  for off in range(0,851977728,8*1024*1024):digest.update(bytes(uc.mem_read(base+0x1000+off,min(8*1024*1024,851977728-off))))
  state['parent_text_sha256']=digest.hexdigest()
 if a.export_parent_data and state.get('parent_data_events'):
  with a.export_parent_data.open('xb') as out:
   digest=hashlib.sha256()
   for off in range(0,0x5d72be1,8*1024*1024):
    chunk=bytes(uc.mem_read(base+0x33534000+off,min(8*1024*1024,0x5d72be1-off)));out.write(chunk);digest.update(chunk)
  state['parent_data_sha256']=digest.hexdigest()
 if a.export_parent_vmp and state.get('parent_vmp_events'):
  raw=bytes(uc.mem_read(base+0x39600000,0x676200));state['parent_vmp_sha256']=hashlib.sha256(raw).hexdigest()
  with a.export_parent_vmp.open('xb') as out:out.write(raw)
 if a.export_parent_aux and any(e['section']=='_RDATA' for e in state.get('parent_vmp_events',[])):
  raw=bytes(uc.mem_read(base+0x39c77000,0x22c00));state['parent_aux_sha256']=hashlib.sha256(raw).hexdigest()
  with a.export_parent_aux.open('xb') as out:out.write(raw)
 if a.export_second_text:
  if state.get('in_fake_second_worker') and state['stop'].get('kind')=='synthetic_return':
   with a.export_second_text.open('xb') as out:
    digest=hashlib.sha256()
    for off in range(0,851977728,8*1024*1024):
     chunk=bytes(uc.mem_read(base+0x1000+off,min(8*1024*1024,851977728-off)));out.write(chunk);digest.update(chunk)
   state['second_text_sha256']=digest.hexdigest()
  else:state['second_text_export_status']='not_written_worker_not_returned'
 if state.get('in_fake_worker'):
  worker_stack=bytes(uc.mem_read(child_stack,0x200000));state['worker_stack_sha256']=hashlib.sha256(worker_stack).hexdigest()
  if a.export_worker_stack:
   with a.export_worker_stack.open('xb') as out:out.write(worker_stack)
 state['modeled_teb_stack']=a.model_teb_stack;state['tls_sha256']=hashlib.sha256(bytes(uc.mem_read(tls_block,0x100000))).hexdigest();state['stack_sha256']=hashlib.sha256(bytes(uc.mem_read(stack,0x200000))).hexdigest();state['registers']={name:hex(uc.reg_read(reg)) for name,reg in (('rax',UC_X86_REG_RAX),('rbx',UC_X86_REG_RBX),('rcx',UC_X86_REG_RCX),('rdx',UC_X86_REG_RDX),('rsp',UC_X86_REG_RSP),('rip',UC_X86_REG_RIP),('rsi',UC_X86_REG_RSI),('rdi',UC_X86_REG_RDI),('rbp',UC_X86_REG_RBP),('r8',UC_X86_REG_R8),('r9',UC_X86_REG_R9),('r10',UC_X86_REG_R10),('r11',UC_X86_REG_R11),('r12',UC_X86_REG_R12),('r13',UC_X86_REG_R13),('r14',UC_X86_REG_R14),('r15',UC_X86_REG_R15),('eflags',UC_X86_REG_EFLAGS))};state['sparse']=a.sparse;state['fast']=a.fast;state['fixed_tsc']=a.fixed_tsc;state['eager_image']=a.eager_image;state['stub_veh']=a.stub_veh;state['traced_dispatch']=a.trace_dispatch;state['trace_range']=a.trace_range;state['inline_dispatch']=a.inline_dispatch;state.update(index=a.index,callback=hex(callbacks[a.index]),modeled_tls_template_bytes=tlslen,mapped_pages=len(pages),recent=list(recent),elapsed_seconds=round(time.monotonic()-start,3),warning='Fake loader, synthetic TLS and inert imports; callback sequence (when requested) approximates loader calls and is not a Windows loader trace.')
 print(json.dumps(state))
