"""Bounded synthetic native probe: original PE sections plus private modeled text/rdata, no host APIs."""
import argparse,collections,hashlib,json,mmap,struct,time
from pathlib import Path
import pefile
from synthetic_avx import try_avx
from synthetic_checkpoint import save as save_checkpoint, restore as restore_checkpoint
from unicorn import Uc,UcError,UC_ARCH_X86,UC_MODE_64,UC_HOOK_CODE,UC_HOOK_INTR,UC_HOOK_MEM_INVALID,UC_HOOK_INSN_INVALID,UC_HOOK_MEM_WRITE,UC_HOOK_MEM_READ,UC_PROT_ALL,UC_PROT_READ,UC_MEM_READ_UNMAPPED,UC_MEM_WRITE_UNMAPPED
from unicorn.x86_const import *
p=argparse.ArgumentParser();p.add_argument('pe',type=Path);p.add_argument('text',type=Path);p.add_argument('rdata',type=Path);p.add_argument('--start',required=True,type=lambda s:int(s,0));p.add_argument('--target',required=True,type=lambda s:int(s,0));p.add_argument('--rcx',type=lambda s:int(s,0),default=1);p.add_argument('--count',type=int,default=1000000);p.add_argument('--timeout-ms',type=int,default=20000);p.add_argument('--model-tls',action='store_true');p.add_argument('--model-tls-template',action='store_true');p.add_argument('--model-object',action='store_true');p.add_argument('--seed-general',action='store_true');p.add_argument('--trace-dispatch',action='store_true');p.add_argument('--inline-dispatch',action='store_true');p.add_argument('--stub-getcurrentprocess',action='store_true');p.add_argument('--stub-flush',action='store_true');p.add_argument('--stub-srw-lock',action='store_true');p.add_argument('--stub-crt-basics',action='store_true');p.add_argument('--modeled-data',type=Path);p.add_argument('--modeled-vmp',type=Path);p.add_argument('--modeled-aux',type=Path);p.add_argument('--model-veh',action='store_true');p.add_argument('--model-teb-stack',action='store_true');p.add_argument('--model-peb-modules',action='store_true');p.add_argument('--model-peb-system-modules',action='store_true');p.add_argument('--model-system-heap-info',action='store_true');p.add_argument('--checkpoint-before-import');p.add_argument('--save-stop-checkpoint',type=Path);p.add_argument('--resume-stop-checkpoint',type=Path);p.add_argument('--trace-peb-reads',action='store_true');p.add_argument('--watch-stack-address',type=lambda x:int(x,0));p.add_argument('--trace-image-reads',action='store_true');p.add_argument('--trace-image-writes',action='store_true');p.add_argument('--max-image-write-samples',type=int,default=1000)
p.add_argument('--registry-data-checkpoint', type=Path, help='replace modeled .data with a verified synthetic checkpoint region')
p.add_argument('--r14', type=lambda value: int(value, 0), help='initial R14 for bounded mid-function probes')
p.add_argument('--r8', type=lambda value: int(value, 0), help='initial third argument for bounded probes')
p.add_argument('--r9', type=lambda value: int(value, 0), help='initial fourth argument for bounded probes')
p.add_argument('--rdx', type=lambda value: int(value, 0), help='initial second argument for bounded probes')
p.add_argument('--shared-descriptor-probe', type=lambda value: int(value, 0), help='select a shared type for the isolated collection reader')
p.add_argument('--descriptor-init-trace', type=Path, help='initializer write evidence for the isolated collection reader')
p.add_argument('--bitset-fixture', choices=('clear','set'), help='synthetic membership branch experiment for 8080BAF7')
p.add_argument('--bitset-layout-value', type=lambda value: int(value, 0), help='seed one strided counter in the set-bit fixture')
p.add_argument('--bitset-skip-secondary', action='store_true', help='test the observed -1 secondary selector in the layout fixture')
p.add_argument('--a23f-field-fixture', action='store_true', help='probe the two A23F field-copy wrappers with distinct input DWORDs')
p.add_argument('--a23f-serialized-component', type=Path, help='probe row 7 using one verified serialized A23F record')
p.add_argument('--a23f-package-entry-fixture', action='store_true', help='supply one synthetic package index entry for the verified component')
p.add_argument('--a23f-type-check', type=lambda value: int(value, 0), help='substitute the second type argument at the observed row 7 check')
p.add_argument('--a23f-null-service-control', action='store_true', help='exercise the fallback with a synthetic service whose virtual method returns null')
p.add_argument('--a23f-lookup-key-control', type=lambda value: int(value, 0), help='probe the fallback lookup with one constructed key')
p.add_argument('--a23f-lookup-table-asset', type=Path, help='use the verified startup-globals table for the lookup control')
p.add_argument('--a23f-service-tag-control', type=lambda value: int(value, 0), help='probe the recovered virtual method with a constructed tag source')
p.add_argument('--a23f-startup-service-fixture', type=Path, help='replay row 7 with the recovered service and preserved startup assets')
p.add_argument('--a23f-startup-key', type=lambda value: int(value, 0), help='supply a DWORD key to the row 7 startup fixture')
p.add_argument('--vault-objective-wrapper', type=Path, help='probe a B8F1 native method with the preserved Vault 1 wrapper')
p.add_argument('--registry-heap-pages', action='store_true', help='map verified synthetic registry heap pages on demand')
p.add_argument('--vault-listener-entry-fixture', type=Path, help='supply the verified serialized listener in one synthetic package entry')
p.add_argument('--vault-listener-layout-value', type=lambda value: int(value, 0), help='test one constructed lookup DWORD at layout index zero')
p.add_argument('--vault-listener-layout-selector', type=lambda value: int(value, 0), help='test the layout selector and its bit-30 branch')
p.add_argument('--vault-listener-native-table-control', action='store_true', help='supply the recovered A23F table through a synthetic package mapping')
p.add_argument('--row7-mode1-fixture', action='store_true', help='map scratch page for rbx completion guard at 0x152702122 and patch Mode 1 pair 14')
p.add_argument('--row7-mode1-investment-tag', type=lambda value: int(value, 0), default=0x80AA2163, help='investment tag for Mode 1 pair 14 (default 0x80AA2163)')
p.add_argument('--vault-ecs-fixture', action='store_true', help='initialize synthetic ECS world fixture at 0x7FF00000 and bind to 0x1755bb480')
a=p.parse_args()
if not 1<=a.count<=100000000 or not 1<=a.timeout_ms<=180000 or not 1<=a.max_image_write_samples<=20000:raise ValueError('invalid bounds')
if a.watch_stack_address is not None and not 0x700000000000<=a.watch_stack_address<=0x7000001ffff8:raise ValueError('bad stack watch')
if a.checkpoint_before_import and not a.save_stop_checkpoint:raise ValueError('import checkpoint requires output')
if (a.save_stop_checkpoint or a.resume_stop_checkpoint) and not a.model_veh:raise ValueError('private stop checkpoint requires VEH model')
checkpoint_args={k:(str(v.resolve()) if isinstance(v,Path) else v) for k,v in vars(a).items() if k not in ('checkpoint_before_import','save_stop_checkpoint','resume_stop_checkpoint','count','timeout_ms')}
# A passive stack watch does not change the modeled machine state.
checkpoint_args['watch_stack_address']=None
checkpoint_args['trace_peb_reads']=False
for option in ('shared_descriptor_probe','descriptor_init_trace','bitset_fixture','bitset_layout_value'):
 if checkpoint_args[option] is None:checkpoint_args.pop(option)
if not a.a23f_field_fixture:checkpoint_args.pop('a23f_field_fixture')
if a.a23f_serialized_component is None:checkpoint_args.pop('a23f_serialized_component')
if not a.a23f_package_entry_fixture:checkpoint_args.pop('a23f_package_entry_fixture')
elif a.a23f_serialized_component is None:raise ValueError('package fixture requires the serialized component')
if a.a23f_type_check is None:checkpoint_args.pop('a23f_type_check')
elif not a.a23f_package_entry_fixture or a.a23f_type_check not in (0x8080a240,0x8080baf7,0x8080a23f):
 raise ValueError('type check control requires the package fixture and a selected comparison type')
if not a.a23f_null_service_control:checkpoint_args.pop('a23f_null_service_control')
elif not (a.a23f_package_entry_fixture and a.registry_data_checkpoint):
 raise ValueError('null service control requires the row 7 package fixture and checkpoint')
if a.a23f_lookup_key_control is None:checkpoint_args.pop('a23f_lookup_key_control')
elif not (a.start==0x17038efa0 and a.model_object and a.rcx==0x760000000010 and
          a.rdx==0x760000000200 and 0<=a.a23f_lookup_key_control<=0xffffffff):
 raise ValueError('lookup control requires the isolated lookup entry and modeled arguments')
if a.a23f_lookup_table_asset is None:checkpoint_args.pop('a23f_lookup_table_asset')
elif a.a23f_lookup_key_control is None:
 raise ValueError('lookup table asset requires a lookup key control')
if a.a23f_service_tag_control is None:checkpoint_args.pop('a23f_service_tag_control')
elif not (a.start==0x16efee9b0 and a.model_object and a.registry_data_checkpoint and
          0<=a.a23f_service_tag_control<=0xffffffff):
 raise ValueError('service tag control requires the recovered method and checkpoint')
if a.a23f_startup_service_fixture is None:checkpoint_args.pop('a23f_startup_service_fixture')
elif not (a.a23f_package_entry_fixture and a.registry_data_checkpoint and not a.a23f_null_service_control and
          a.rdx==0x760000000200 and a.a23f_startup_key is not None):
 raise ValueError('startup service fixture requires the row 7 package control, checkpoint and key')
if a.a23f_startup_key is None:checkpoint_args.pop('a23f_startup_key')
elif not a.a23f_startup_service_fixture or not 0<=a.a23f_startup_key<=0xffffffff:
 raise ValueError('startup key requires the startup service fixture and a DWORD')
if a.vault_objective_wrapper is None:checkpoint_args.pop('vault_objective_wrapper')
elif not (a.model_object and a.rcx==0x760000003530 and not a.a23f_serialized_component and
          not a.vault_listener_entry_fixture):
 raise ValueError('objective wrapper requires the isolated Vault 1 component view')
if not a.registry_heap_pages:checkpoint_args.pop('registry_heap_pages')
if a.vault_listener_entry_fixture is None:checkpoint_args.pop('vault_listener_entry_fixture')
elif not (a.registry_data_checkpoint and a.registry_heap_pages and a.model_object and
          a.start==0x171a407d0 and a.rdx==4 and a.r8==0x80b3b7f2 and not a.a23f_serialized_component):
 raise ValueError('listener fixture requires the registered callback, operation 4, Vault listener key and registry pages')
if a.vault_listener_layout_value is None:checkpoint_args.pop('vault_listener_layout_value')
elif not a.vault_listener_entry_fixture or not 0<=a.vault_listener_layout_value<=0xffffffff:
 raise ValueError('listener layout control requires a listener fixture and a DWORD')
if a.vault_listener_layout_selector is None:checkpoint_args.pop('vault_listener_layout_selector')
elif a.vault_listener_layout_value is None or not 0<=a.vault_listener_layout_selector<=0xffffffff:
 raise ValueError('listener layout selector requires a layout control and a DWORD')
if not a.vault_listener_native_table_control:checkpoint_args.pop('vault_listener_native_table_control')
elif a.vault_listener_layout_selector!=0x4000059c or a.vault_listener_layout_value!=0:
 raise ValueError('native table control requires the selected empty bucket and zero layout DWORD')
if not a.bitset_skip_secondary:checkpoint_args.pop('bitset_skip_secondary')
if a.bitset_skip_secondary and a.bitset_layout_value is None:
 raise ValueError('secondary selector experiment requires a layout fixture')
if a.r14 is None:
 checkpoint_args.pop('r14')
if a.r8 is None:
 checkpoint_args.pop('r8')
if a.r9 is None:
 checkpoint_args.pop('r9')
if a.rdx is None:
 checkpoint_args.pop('rdx')
elif a.a23f_field_fixture:
 raise ValueError('field fixture supplies its own second argument')
if not a.vault_ecs_fixture:
 checkpoint_args.pop('vault_ecs_fixture')
if a.registry_data_checkpoint is None:
 checkpoint_args.pop('registry_data_checkpoint')
checkpoint_identity=hashlib.sha256(json.dumps(checkpoint_args,sort_keys=True).encode()).hexdigest()

for path,want in [(a.pe,'d5c2fb538f4020a71060b553127259fcd5d3131beb89a4ec26a7d6ccfa9dfbfd'),(a.text,('e003a16dc5e495ee9b0b1b3824a46c9553e0bcbd038b432eddb3a55d7d450dca','1c8f2a6e3cc77ad5b373afb368959968c78e571706974db051a32fabd0af459e')),(a.rdata,'e440e65ec21b63abf6edfd87868ab25d89946b54f8e53216a954eb62b7f10e42')]:
 with path.open('rb') as f:
  if hashlib.file_digest(f,'sha256').hexdigest() not in ((want,) if isinstance(want,str) else want):raise ValueError('unexpected input identity')
modeled_data=a.modeled_data.read_bytes() if a.modeled_data else None
if modeled_data is not None and (len(modeled_data)!=0x5d72be1 or hashlib.sha256(modeled_data).hexdigest()!='a9043bd1c26a144598e7b1f55ea3a9a2da5eddbae8b4cea95fad57537b91da49'):raise ValueError('unexpected modeled data')
if a.registry_data_checkpoint:
 if not a.modeled_data:raise ValueError('checkpoint overlay requires modeled data')
 root=a.registry_data_checkpoint.resolve()
 manifest=json.loads((root/'manifest.json').read_text(encoding='utf-8'))
 region=next(r for r in manifest['regions'] if r['start']==0x173534000)
 region_file=(root/region['file']).resolve()
 if not region_file.is_relative_to(root):raise ValueError('checkpoint region escapes directory')
 raw=region_file.read_bytes()
 if len(raw)!=region['size'] or len(raw)<0x5d72be1 or hashlib.sha256(raw).hexdigest()!=region['sha256']:
  raise ValueError('checkpoint .data region digest or size mismatch')
 modeled_data=raw[:0x5d72be1]
 checkpoint_args['registry_data_region_sha256']=region['sha256']
 checkpoint_identity=hashlib.sha256(json.dumps(checkpoint_args,sort_keys=True).encode()).hexdigest()
row7_scratch = 0x7FFF0000
listener_layout=0x760000006000
null_service=0x760000006400
null_service_table=0x760000006500
service_tag_source=0x760000006600
if a.a23f_service_tag_control is not None or a.a23f_startup_service_fixture:
 overlay=bytearray(modeled_data)
 offset=0x174f6f240-0x173534000
 if any(overlay[offset:offset+8]):raise ValueError('service tag control would replace an existing pointer')
 struct.pack_into('<Q',overlay,offset,service_tag_source)
 modeled_data=bytes(overlay)
if a.a23f_null_service_control or a.a23f_startup_service_fixture:
 overlay=bytearray(modeled_data)
 offset=0x1767f3338-0x173534000
 if any(overlay[offset:offset+8]):raise ValueError('null service control would replace an existing service')
 struct.pack_into('<Q',overlay,offset,null_service)
 modeled_data=bytes(overlay)
if a.vault_listener_layout_value is not None:
 overlay=bytearray(modeled_data)
 offset=0x174e970d8-0x173534000
 if any(overlay[offset:offset+0x20]):raise ValueError('listener layout fixture would replace existing data')
 struct.pack_into('<Q',overlay,offset,listener_layout)
 struct.pack_into('<II',overlay,offset+0x18,4,0xffffffff)
 if a.vault_listener_layout_selector is not None:
  if struct.unpack_from('<I',overlay,offset+0x2c)[0]!=0xffffffff:
   raise ValueError('unexpected existing listener layout selector')
  struct.pack_into('<I',overlay,offset+0x2c,a.vault_listener_layout_selector)
 modeled_data=bytes(overlay)
if a.vault_ecs_fixture and modeled_data is not None:
 overlay=bytearray(modeled_data)
 off_ecs=0x1755bb480-0x173534000
 struct.pack_into('<Q',overlay,off_ecs,0x7FF00000)
 modeled_data=bytes(overlay)
if a.row7_mode1_fixture and modeled_data is not None:
 overlay=bytearray(modeled_data)
 off_598=0x178b44598-0x173534000
 off_5ac=0x178b445ac-0x173534000
 off_3b28=0x176723b28-0x173534000
 off_3b3c=0x176723b3c-0x173534000
 struct.pack_into('<Q',overlay,off_598,row7_scratch+0x800)
 struct.pack_into('<I',overlay,off_5ac,0x2ef1fb20)
 struct.pack_into('<Q',overlay,off_3b28,0x178f80000 ^ 0x16ef1fb20)
 struct.pack_into('<I',overlay,off_3b3c,0x2ef1fb20)
 modeled_data=bytes(overlay)
reader_pages={}
reader_offset=None
fixture_context=0x760000004000
fixture_layout=fixture_context+0x1000
fixture_counter=fixture_layout+4*0xc31
if a.bitset_layout_value is not None and (a.bitset_fixture!='set' or not 0<=a.bitset_layout_value<=255):
 raise ValueError('layout value requires the set-bit fixture and an 8-bit counter')
if a.shared_descriptor_probe is not None:
 descriptor_bases={0x8080baf7:0x17681fe88,0x8080b8e2:0x1768201b8,0x8080b8a0:0x176820350}
 if not a.registry_data_checkpoint or not a.descriptor_init_trace or a.start!=0x170de8e80 or a.r14!=0x172d81300:
  raise ValueError('shared descriptor probe requires the checkpoint overlay, initializer trace and reader entry')
 descriptor=descriptor_bases[a.shared_descriptor_probe]
 reader_offset=descriptor-0x17681fe10
 writes=json.loads(a.descriptor_init_trace.read_text(encoding='utf-8-sig'))['image_write_samples']
 expected={descriptor:4,descriptor+8:8,descriptor+16:4}
 found={int(w['address'],16):w for w in writes if int(w['address'],16) in expected}
 if set(found)!=set(expected) or int(found[descriptor]['value'],16)!=a.shared_descriptor_probe:
  raise ValueError('initializer trace does not contain selected descriptor')
 overlay=bytearray(modeled_data)
 for address,width in expected.items():
  write=found[address]
  if write['size']!=width or not 0x14583629e<=int(write['rip'],16)<0x1458382f1:
   raise ValueError('unexpected descriptor write provenance')
  offset=address-0x173534000
  overlay[offset:offset+width]=int(write['value'],16).to_bytes(width,'little')
 if a.bitset_fixture:
  if a.shared_descriptor_probe!=0x8080baf7 or not a.modeled_vmp:
   raise ValueError('fixture requires type 8080BAF7 and transformed .vmp0')
  offset=0x174e970d0-0x173534000
  if overlay[offset:offset+8]!=bytes(8):raise ValueError('fixture would replace an existing context')
  struct.pack_into('<Q',overlay,offset,fixture_context)
  if a.bitset_layout_value is not None:
   if any(overlay[offset+8:offset+0x28]):raise ValueError('layout fixture would replace existing data')
   struct.pack_into('<Q',overlay,offset+8,fixture_layout)
   struct.pack_into('<II',overlay,offset+0x20,4,255)
   if a.bitset_skip_secondary:
    if overlay[offset+0x38:offset+0x3c]!=bytes(4):raise ValueError('unexpected existing secondary selector')
    struct.pack_into('<i',overlay,offset+0x38,-1)
 modeled_data=bytes(overlay)
 reader_pages={r['start']:r for r in manifest['regions'] if r['size']==4096 and r['permissions']==3 and 0x7a0000000000<=r['start']<0x7b0000000000}
 checkpoint_args['descriptor_init_trace_sha256']=hashlib.sha256(a.descriptor_init_trace.read_bytes()).hexdigest()
 checkpoint_identity=hashlib.sha256(json.dumps(checkpoint_args,sort_keys=True).encode()).hexdigest()
elif a.descriptor_init_trace or a.bitset_fixture:
 raise ValueError('initializer trace requires a shared descriptor selection')
if a.a23f_serialized_component or a.registry_heap_pages:
 if not a.registry_data_checkpoint:raise ValueError('saved bucket pages require a checkpoint overlay')
 reader_pages={r['start']:r for r in manifest['regions'] if r['size']==4096 and r['permissions']==3
               and 0x7a0000000000<=r['start']<0x7b0000000000}
modeled_vmp=a.modeled_vmp.read_bytes() if a.modeled_vmp else None
if modeled_vmp is not None and (len(modeled_vmp)!=0x676200 or hashlib.sha256(modeled_vmp).hexdigest()!='7aa5f1d4e1182373ee9275af90f37e5dbba75c85a0c1d6580803f2c25c0a9742'):raise ValueError('unexpected modeled vmp')
modeled_aux=a.modeled_aux.read_bytes() if a.modeled_aux else None
if modeled_aux is not None and (len(modeled_aux)!=0x22c00 or hashlib.sha256(modeled_aux).hexdigest()!='83044bacd2d84f03664c72dca238d674f085a4e025065bdf38002adbd93e87d6'):raise ValueError('unexpected modeled aux')
pe=pefile.PE(str(a.pe),fast_load=True);pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_TLS']]);import_names=[]
for d in pe.DIRECTORY_ENTRY_IMPORT:
 for i in d.imports:import_names.append(d.dll.decode('ascii')+'!'+(i.name.decode('ascii') if i.name else '#'+str(i.ordinal)))
if len(import_names)!=544 or import_names[188].lower()!='kernel32.dll!getcurrentprocess' or import_names[177].lower()!='kernel32.dll!flushinstructioncache':raise ValueError('unexpected import marker mapping')
base=pe.OPTIONAL_HEADER.ImageBase;sections=[(s.VirtualAddress,max(s.Misc_VirtualSize,s.SizeOfRawData),s.PointerToRawData,s.SizeOfRawData,s.Name.rstrip(b'\0').decode()) for s in pe.sections];stack=0x700000000000;teb=0x710000000000;marker=0x720000000000;return_marker=0x730000000000;uc=Uc(UC_ARCH_X86,UC_MODE_64);uc.mem_map(stack,0x200000);uc.mem_map(teb,0x2000);uc.mem_map(marker,0x3000);uc.mem_map(return_marker,0x1000);uc.mem_write(return_marker,b'\x90');uc.reg_write(UC_X86_REG_RSP,stack+0x1feff8);uc.mem_write(stack+0x1feff8,struct.pack('<Q',return_marker));uc.reg_write(UC_X86_REG_RCX,a.rcx);uc.reg_write(UC_X86_REG_GS_BASE,teb);uc.reg_write(UC_X86_REG_EFLAGS,0x202)
if a.row7_mode1_fixture:
 uc.mem_map(row7_scratch, 4096, 7)
 uc.mem_write(row7_scratch, bytes(4096))
if a.vault_ecs_fixture:
 from vault_ecs_fixture import populate_ecs_fixture
 populate_ecs_fixture(uc)
if a.bitset_fixture:
 uc.mem_map(fixture_context,4096,3)
 uc.mem_write(fixture_context+8,struct.pack('<Q',fixture_context+0x40))
 uc.mem_write(fixture_context+0x50,struct.pack('<Q',fixture_context+0x80))
 if a.bitset_fixture=='set':
  field=0xc31
  uc.mem_write(fixture_context+0x80+4*(field>>5),struct.pack('<I',1<<(field&31)))
if a.bitset_layout_value is not None:
 uc.mem_map(fixture_layout,0x4000,3)
 uc.mem_write(fixture_counter,struct.pack('<I',a.bitset_layout_value))
if reader_offset is not None:
 uc.reg_write(UC_X86_REG_R15,reader_offset)
if a.r14 is not None:
 uc.reg_write(UC_X86_REG_R14,a.r14)
if a.r8 is not None:
 uc.reg_write(UC_X86_REG_R8,a.r8)
if a.r9 is not None:
 uc.reg_write(UC_X86_REG_R9,a.r9)
if a.rdx is not None:
 uc.reg_write(UC_X86_REG_RDX,a.rdx)
if a.model_teb_stack:
 uc.mem_write(teb+0x30,struct.pack('<Q',teb));uc.mem_write(teb+8,struct.pack('<QQ',stack+0x200000,stack))
fake_system_modules=[]
if a.model_peb_system_modules and not a.model_peb_modules:raise ValueError('system module model requires PEB model')
if a.model_system_heap_info and not a.model_peb_system_modules:raise ValueError('system heap marker requires modeled system modules')
if a.model_peb_modules:
 if not a.model_teb_stack:raise ValueError('PEB model requires synthetic TEB')
 peb=teb+0x1000;ldr=teb+0x1200;uc.mem_write(teb+0x60,struct.pack('<Q',peb));uc.mem_write(peb+0x10,struct.pack('<QQ',base,ldr));uc.mem_write(ldr,struct.pack('<I',0x58))
 modules=[('Marathon.exe',base,pe.OPTIONAL_HEADER.SizeOfImage,'C:\\Preservation\\Marathon.exe')]
 if a.model_peb_system_modules:
  for i,name in enumerate(('ntdll.dll','kernel32.dll','kernelbase.dll')):
   path=Path('C:/Windows/System32')/name;raw=path.read_bytes();system_pe=pefile.PE(data=raw,fast_load=True);module_base=0x7e0000000000+i*0x10000000;image_size=system_pe.OPTIONAL_HEADER.SizeOfImage
   if image_size>0x10000000:raise ValueError('system module too large')
   uc.mem_map(module_base,(image_size+4095)&~4095,UC_PROT_READ);headers=system_pe.OPTIONAL_HEADER.SizeOfHeaders;uc.mem_write(module_base,raw[:headers])
   for sec in system_pe.sections:
    if sec.SizeOfRawData:uc.mem_write(module_base+sec.VirtualAddress,raw[sec.PointerToRawData:sec.PointerToRawData+sec.SizeOfRawData])
   module_info={'name':name,'base':hex(module_base),'size':image_size,'sha256':hashlib.sha256(raw).hexdigest(),'execution':'disabled'}
   if name=='ntdll.dll' and a.model_system_heap_info:
    system_pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']]);found=[x for x in system_pe.DIRECTORY_ENTRY_EXPORT.symbols if x.name==b'LdrRegisterDllNotification']
    if len(found)!=1 or found[0].forwarder:raise ValueError('unexpected DLL notification export')
    module_info['dll_notification_export']=hex(module_base+found[0].address)
   if name=='kernel32.dll' and a.model_system_heap_info:
    system_pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']]);exp=system_pe.DIRECTORY_ENTRY_EXPORT;matches=[x for x in exp.symbols if x.name==b'HeapSetInformation']
    if len(matches)!=1 or matches[0].forwarder:raise ValueError('unexpected HeapSetInformation export')
    marker_rva=((image_size+4095)&~4095)+0x1000;system_marker=module_base+marker_rva;uc.mem_map(system_marker,0x1000,UC_PROT_ALL)
    for symbol,offset,key in ((b'HeapSetInformation',0,'fake_heap_information_marker'),(b'HeapCreate',0x10,'fake_heap_create_marker')):
     found=[x for x in exp.symbols if x.name==symbol]
     if len(found)!=1 or found[0].forwarder:raise ValueError('unexpected synthetic heap export')
     uc.mem_write(system_marker+offset,b'\x90');entry_rva=exp.struct.AddressOfFunctions+4*(found[0].ordinal-exp.struct.Base);uc.mem_write(module_base+entry_rva,struct.pack('<I',marker_rva+offset));module_info[key]=hex(system_marker+offset)
    uc.mem_write(system_marker+0x20,b'\x90');module_info['fake_heap_alloc_marker']=hex(system_marker+0x20)
   modules.append((name,module_base,image_size,'C:\\Windows\\System32\\'+name));fake_system_modules.append(module_info)
 for i,(name,module_base,module_size,full) in enumerate(modules):
  entry=teb+0x1300+i*0x100;full_name=teb+0x1700+i*0x100;base_name=full_name+0x80
  uc.mem_write(entry+0x30,struct.pack('<Q',module_base));uc.mem_write(entry+0x40,struct.pack('<I',module_size))
  for field,buffer,value in ((0x48,full_name,full),(0x58,base_name,name)):
   raw=value.encode('utf-16le');uc.mem_write(buffer,raw+b'\0\0');uc.mem_write(entry+field,struct.pack('<HH4xQ',len(raw),len(raw)+2,buffer))
 for off in (0x10,0x20,0x30):
  head=ldr+off;links=[teb+0x1300+i*0x100+(off-0x10) for i in range(len(modules))]
  uc.mem_write(head,struct.pack('<QQ',links[0],links[-1]))
  for i,link in enumerate(links):uc.mem_write(link,struct.pack('<QQ',links[i+1] if i+1<len(links) else head,links[i-1] if i else head))
if a.seed_general and not a.model_object:raise ValueError('--seed-general requires --model-object')
if a.model_tls_template and not a.model_tls:raise ValueError('TLS template requires --model-tls')
if (a.trace_dispatch or a.inline_dispatch) and not a.model_tls:raise ValueError('dispatch options require --model-tls')
if a.model_object:uc.mem_map(0x760000000000,0x10000)
if a.a23f_startup_service_fixture:
 startup=(a.a23f_startup_service_fixture/'80A6A052.bin').read_bytes()
 investment=(a.a23f_startup_service_fixture/'80A6A004.bin').read_bytes()
 if hashlib.sha256(startup).hexdigest()!='e461e1937fc88f56c6cb84d28c89a89c4d81acbdaf79f288a872dff97b85f446':
  raise ValueError('unexpected startup globals')
 if hashlib.sha256(investment).hexdigest()!='19945bae0ccfebb7eccbacf5b557135cd476022869b1cc1c8fe5d5e5d6b53939':
  raise ValueError('unexpected investment globals')
 investment_base=0x760001000000
 investment_entry=0x760000006900
 uc.mem_map(investment_base,(len(investment)+4095)&~4095)
 uc.mem_write(investment_base,investment)
 uc.mem_write(investment_entry,struct.pack('<QQQ',0,(investment_entry-investment_base)&0xffffffffffffffff,0))
 uc.mem_write(service_tag_source-0x20,startup)
 uc.mem_write(null_service,struct.pack('<Q',0x172d886d0))
 uc.mem_write(a.rdx,struct.pack('<I',a.a23f_startup_key))
if a.a23f_service_tag_control is not None:
 uc.mem_write(service_tag_source+0x40,struct.pack('<I',a.a23f_service_tag_control))
if a.a23f_null_service_control:
 uc.mem_write(null_service,struct.pack('<Q',null_service_table))
 uc.mem_write(null_service_table+0x48,struct.pack('<Q',0x16ef1edc0))
if a.a23f_lookup_key_control is not None:
 if a.a23f_lookup_table_asset:
  lookup_asset=a.a23f_lookup_table_asset.read_bytes()
  lookup_digest=hashlib.sha256(lookup_asset).hexdigest()
  if lookup_digest!='19945bae0ccfebb7eccbacf5b557135cd476022869b1cc1c8fe5d5e5d6b53939':
   raise ValueError('unexpected startup-globals table asset')
  lookup_base=0x760001000000
  uc.mem_map(lookup_base,(len(lookup_asset)+4095)&~4095)
  uc.mem_write(lookup_base,lookup_asset)
  uc.reg_write(UC_X86_REG_RCX,lookup_base+8)
 else:
  uc.mem_write(a.rcx+0x10,struct.pack('<I',1))
  uc.mem_write(a.rcx+0x18,struct.pack('<q',0x18))
  uc.mem_write(a.rcx+0x48,struct.pack('<I',0x11223344))
 uc.mem_write(a.rdx,struct.pack('<I',a.a23f_lookup_key_control))
if a.vault_listener_layout_value is not None:
 uc.mem_write(listener_layout,struct.pack('<I',a.vault_listener_layout_value))
package_fixture=None
package_component=0x760000002000
if a.vault_objective_wrapper:
 wrapper_component=a.vault_objective_wrapper.read_bytes()
 if hashlib.sha256(wrapper_component).hexdigest()!='70ccaa2ce14425d4603690cf043ad0c69921af49b607bf1d7dea94a0389741cc':
  raise ValueError('unexpected objective wrapper component')
 uc.mem_write(package_component,wrapper_component)
if a.a23f_serialized_component:
 if not a.model_object or a.start!=0x16f765b80 or not (
     a.rcx==0x760000000010 or (a.a23f_package_entry_fixture and a.rcx==package_component+0x1b58)):
  raise ValueError('serialized fixture requires the row 7 entry and modeled object')
 component=a.a23f_serialized_component.read_bytes()
 if hashlib.sha256(component).hexdigest()!='70ccaa2ce14425d4603690cf043ad0c69921af49b607bf1d7dea94a0389741cc':
  raise ValueError('unexpected serialized component')
 record=component[0x1b58:0x1b80]
 if struct.unpack_from('<III',record)!=(0x80b37fed,0x8080a23f,0x230):
  raise ValueError('unexpected serialized record')
 if a.rcx==0x760000000010:
  uc.mem_write(a.rcx,record)
 if a.a23f_package_entry_fixture:
  package_fixture=(component,0x740,0x1fed,0xfeef059c)
if a.vault_listener_entry_fixture:
 listener=a.vault_listener_entry_fixture.read_bytes()
 if hashlib.sha256(listener).hexdigest()!='3b1e5cbaa459f1e438e4a7723b30eb1d06863399db551c7a54a867024961a43d':
  raise ValueError('unexpected Vault listener bytes')
 package_fixture=(listener,0x7c0,0x17f2,0xfeef059e)
if package_fixture:
 payload,bucket_offset,entry_index,bucket_header=package_fixture
 package_entry=0x76000000f000
 if len(payload)>package_entry-package_component:raise ValueError('payload overlaps synthetic index entry')
 uc.mem_write(package_component,payload)
 uc.mem_write(package_entry,struct.pack('<QQQ',0,package_entry-package_component,0))
if a.vault_listener_native_table_control:
 table_record=0x760000006100
 table_entry=0x760000006200
 uc.mem_write(table_record,struct.pack('<Q',0x172d76d20))
 uc.mem_write(table_entry,struct.pack('<QQQ',0,table_entry-table_record,0))
if a.a23f_field_fixture:
 if not a.model_object or a.rcx!=0x760000000010 or a.start not in (0x16f1a0a90,0x16f159160,0x16fe1c610,0x16f41e4c0):
  raise ValueError('fixture requires a selected field wrapper and modeled object')
 uc.mem_write(a.rcx+0x20,struct.pack('<II',0x11223344,0x55667788))
 uc.reg_write(UC_X86_REG_RDX,0x760000000100)

if a.seed_general:
 for reg in (UC_X86_REG_RBX,UC_X86_REG_RBP,UC_X86_REG_RSI,UC_X86_REG_RDI,UC_X86_REG_R8,UC_X86_REG_R9,UC_X86_REG_R10,UC_X86_REG_R11,UC_X86_REG_R12,UC_X86_REG_R13,UC_X86_REG_R14,UC_X86_REG_R15):uc.reg_write(reg,0x760000000010)
if a.model_tls:
 tls_table=0x740000000000;tls_block=0x750000000000;tls_size=0x100000 if a.model_tls_template else 0x20000;uc.mem_map(tls_table,0x10000);uc.mem_map(tls_block,tls_size);uc.mem_write(tls_table,struct.pack('<Q',tls_block)*8192);uc.mem_write(teb+0x58,struct.pack('<Q',tls_table))
 if a.model_tls_template:
  t=pe.DIRECTORY_ENTRY_TLS.struct;n=t.EndAddressOfRawData-t.StartAddressOfRawData
  if not 0<=n<=tls_size:raise ValueError('unexpected TLS template size')
  with a.pe.open('rb') as f:f.seek(pe.get_offset_from_rva(t.StartAddressOfRawData-base));template=f.read(n)
  if len(template)!=n:raise ValueError('short TLS template')
  uc.mem_write(tls_block,template)
exception_mem=0x770000000000;handler_ret=return_marker+0x100
if a.model_veh:
 if not a.modeled_data:raise ValueError('VEH model requires modeled data')
 uc.mem_map(exception_mem,0x10000)
state={'instructions':0,'stop':None,'writes':0};
if a.a23f_serialized_component:
 state['synthetic_a23f_serialized_fixture']={'offset':'0x1b58','length':40,
                                           'in_component':a.rcx==package_component+0x1b58}
if a.vault_objective_wrapper:
 state['synthetic_vault_objective_wrapper']={'component':'80B37FED','offset':'0x1530','metadata_slot':'0x15'}
if a.a23f_null_service_control:
 state['synthetic_a23f_null_service']={'object':hex(null_service),'table':hex(null_service_table),
                                      'null_return_stub':'0x16ef1edc0'}
if a.a23f_lookup_key_control is not None:
 state['synthetic_a23f_lookup']={'key':hex(a.a23f_lookup_key_control)}
 if a.a23f_lookup_table_asset:
  state['synthetic_a23f_lookup'].update(asset_base=hex(lookup_base),asset_sha256=lookup_digest)
 else:
  state['synthetic_a23f_lookup']['stored_key']='0x11223344'
if a.a23f_service_tag_control is not None:
 state['synthetic_a23f_service_tag']=hex(a.a23f_service_tag_control)
if a.a23f_startup_service_fixture:
 state['synthetic_a23f_startup_service']={'key':hex(a.a23f_startup_key),'asset':hex(investment_base),
                                         'source':hex(service_tag_source),'vtable':'0x172d886d0'}
if a.a23f_package_entry_fixture:
 state['synthetic_a23f_package_entry']={'bucket':'0x7a01036b5740','entry':hex(package_entry),
                                      'component':hex(package_component),'stride':24,'mask':-1}
if a.vault_listener_entry_fixture:
 state['synthetic_vault_listener_entry']={'bucket':'0x7a01036b57c0','entry':hex(package_entry),
                                        'listener':hex(package_component),'stride':24,'mask':-1}
if a.vault_listener_layout_value is not None:
 state['synthetic_vault_listener_layout']={'address':hex(listener_layout),'index':0,'value':a.vault_listener_layout_value}
 if a.vault_listener_layout_selector is not None:
  state['synthetic_vault_listener_layout']['selector']=hex(a.vault_listener_layout_selector)
if a.vault_listener_native_table_control:
 state['synthetic_vault_listener_table']={'bucket':'0x7a01036b5780','record':hex(table_record),
                                        'table':'0x172d76d20','entry':hex(table_entry)}
if a.bitset_fixture:state['synthetic_bitset_fixture']=a.bitset_fixture
if a.bitset_skip_secondary:state['synthetic_secondary_selector']=-1
if a.bitset_layout_value is not None:
 state['synthetic_layout_counter']={'address':hex(fixture_counter),'initial':a.bitset_layout_value,'writes':[]}
recent=collections.deque(maxlen=100);pages=set()
with a.pe.open('rb') as f,a.text.open('rb') as t,a.rdata.open('rb') as r,mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ) as im,mmap.mmap(t.fileno(),0,access=mmap.ACCESS_READ) as text,mmap.mmap(r.fileno(),0,access=mmap.ACCESS_READ) as data:
 def invalid(uc,access,addr,size,value,user):
  rva=addr-base;sec=next((s for s in sections if s[0]<=rva<s[0]+s[1]),None)
  if sec is None and 0<=rva<pe.OPTIONAL_HEADER.SizeOfHeaders:
   page=addr&~0xfff
   if page in pages:state['stop']={'kind':'mapped_failure','address':hex(addr)};return False
   uc.mem_map(page,4096,UC_PROT_ALL);pages.add(page);start=page-base;end=min(pe.OPTIONAL_HEADER.SizeOfHeaders,start+4096);uc.mem_write(page,im[start:end]);return True
  if sec is None and access in (UC_MEM_READ_UNMAPPED,UC_MEM_WRITE_UNMAPPED):
   page=addr&~0xfff
   region=reader_pages.get(page)
   mapped=state.setdefault('descriptor_reader_pages',[]) if reader_pages else []
   if region and page not in pages and len(mapped)<128:
    region_file=(root/region['file']).resolve()
    if not region_file.is_relative_to(root):raise ValueError('reader page escapes checkpoint directory')
    content=region_file.read_bytes()
    if len(content)!=4096 or hashlib.sha256(content).hexdigest()!=region['sha256']:
     raise ValueError('reader page digest or size mismatch')
    if package_fixture and page==0x7a01036b5000:
     if struct.unpack_from('<8Q',content,bucket_offset)!=(bucket_header,0,0,0,0,0,0,0):
      raise ValueError('package bucket differs from verified empty layout')
     overlay=bytearray(content)
     struct.pack_into('<Q',overlay,bucket_offset+8,package_entry-24*entry_index)
     struct.pack_into('<Ii',overlay,bucket_offset+0x30,24,-1)
     if a.vault_listener_native_table_control:
      if struct.unpack_from('<8Q',content,0x780)!=(0xfeef059d,0,0,0,0,0,0,0):
       raise ValueError('unexpected listener table bucket baseline')
      struct.pack_into('<Q',overlay,0x788,table_entry)
      struct.pack_into('<Ii',overlay,0x7b0,24,-1)
     content=bytes(overlay)
    if a.a23f_startup_service_fixture and page==0x7a01036b3000:
     if struct.unpack_from('<8Q',content,0xdc0)!=(0xfeef0536,0,0,0,0,0,0,0):
      raise ValueError('unexpected investment bucket baseline')
     overlay=bytearray(content)
     struct.pack_into('<Q',overlay,0xdc8,investment_entry-24*4)
     struct.pack_into('<Ii',overlay,0xdf0,24,-1)
     content=bytes(overlay)
    uc.mem_map(page,4096,3)
    uc.mem_write(page,content)
    pages.add(page)
    mapped.append(hex(page))
    return True
  if sec is None and a.model_veh:
   page=addr&~0xfff
   if any(start<=page and page+4096<=end for start,end in state.get('fake_virtual_commits',[])):
    if page in pages:state['stop']={'kind':'mapped_failure','address':hex(addr)};return False
    uc.mem_map(page,4096,UC_PROT_ALL);pages.add(page);state['fake_virtual_pages']=state.get('fake_virtual_pages',0)+1;return True
  if sec is None:
   state['stop']={'kind':'unmapped','address':hex(addr),'rip':hex(uc.reg_read(UC_X86_REG_RIP))}
   if a.model_veh and not state.get('handling_exception'):state['pending_fault']={'address':addr,'rip':uc.reg_read(UC_X86_REG_RIP),'access':access}
   return False
  page=addr&~0xfff
  if page in pages:state['stop']={'kind':'mapped_failure','address':hex(addr)};return False
  uc.mem_map(page,4096,UC_PROT_ALL);pages.add(page);v,_,raw,rawsize,name=sec;lo=max(page-base,v);hi=min(page-base+4096,v+rawsize)
  if name=='.data' and modeled_data is not None:
   hi=min(page-base+4096,v+len(modeled_data));uc.mem_write(base+lo,modeled_data[lo-v:hi-v])
  elif name=='.vmp0' and modeled_vmp is not None:
   hi=min(page-base+4096,v+len(modeled_vmp));uc.mem_write(base+lo,modeled_vmp[lo-v:hi-v])
  elif name=='_RDATA' and modeled_aux is not None:
   hi=min(page-base+4096,v+len(modeled_aux));uc.mem_write(base+lo,modeled_aux[lo-v:hi-v])
  elif hi>lo:
   payload=text[lo-v:hi-v] if name=='.text' else data[lo-v:hi-v] if name=='.rdata' else im[raw+lo-v:raw+hi-v]
   uc.mem_write(base+lo,payload)
  return True
 def code(uc,addr,size,user):
  state['instructions']+=1;recent.append(hex(addr))
  if a.a23f_package_entry_fixture and addr==0x16f765c57:
   actual=uc.reg_read(UC_X86_REG_RCX)
   expected=uc.reg_read(UC_X86_REG_RDX)
   if (actual,expected)!=(0x8080a240,0x8080bac7):
    state['stop']={'kind':'unexpected_a23f_type_check','actual':hex(actual),'expected':hex(expected)}
    uc.emu_stop()
    return
   if a.a23f_type_check is not None:
    uc.reg_write(UC_X86_REG_RDX,a.a23f_type_check)
   state['a23f_type_check']={'actual':hex(actual),'original_expected':hex(expected),
                             'tested_expected':hex(uc.reg_read(UC_X86_REG_RDX))}
  if a.a23f_package_entry_fixture and addr==0x16f765c5c and 'a23f_type_check' in state:
   state['a23f_type_check']['al']=uc.reg_read(UC_X86_REG_RAX)&0xff
  if reader_offset is not None:
   changes=state.setdefault('descriptor_reader_argument_changes',[])
   values={name:hex(uc.reg_read(reg)) for name,reg in
           (('rax',UC_X86_REG_RAX),('rcx',UC_X86_REG_RCX),('r8',UC_X86_REG_R8))}
   if len(changes)<1000 and (not changes or any(changes[-1][name]!=value for name,value in values.items())):
    changes.append({'rip':hex(addr),'previous':recent[-2] if len(recent)>1 else None,**values})
   if addr==0x17060fcd4:
    table=uc.reg_read(UC_X86_REG_RAX)
    offset=uc.reg_read(UC_X86_REG_RCX)
    state.setdefault('descriptor_reader_secondary_slots',[]).append({
     'table':hex(table),'offset':hex(offset),'slot':hex(table+offset+0x10),
     'record_word':hex(uc.reg_read(UC_X86_REG_RDX)&0xffff)})
   if addr in (0x171a43d6b,0x171a43d70,0x14fc3ecfa,0x148764853):
    accesses=state.setdefault('descriptor_reader_record_access',[])
    if len(accesses)<32:
     accesses.append({'rip':hex(addr),'rax':hex(uc.reg_read(UC_X86_REG_RAX)),
                      'rcx':hex(uc.reg_read(UC_X86_REG_RCX)),'rdx':hex(uc.reg_read(UC_X86_REG_RDX))})
  if 2540<=len(state.get('modeled_faults',[]))<2600:
   rcx_value=uc.reg_read(UC_X86_REG_RCX);events=state.setdefault('late_rcx_changes',[])
   if not events or events[-1]['value']!=hex(rcx_value):
    if len(events)>=1000:del events[0]
    events.append({'rip':hex(addr),'value':hex(rcx_value),'rsp':hex(uc.reg_read(UC_X86_REG_RSP))})
   rbx_value=uc.reg_read(UC_X86_REG_RBX);events=state.setdefault('late_rbx_changes',[])
   if not events or events[-1]['value']!=hex(rbx_value):
    if len(events)>=1000:del events[0]
    events.append({'rip':hex(addr),'value':hex(rbx_value),'rsp':hex(uc.reg_read(UC_X86_REG_RSP))})
  if a.row7_mode1_fixture:
   if addr in (0x15270211a, 0x156ad5a8a, 0x1470fd5b4, 0x154671871):
    sp=uc.reg_read(UC_X86_REG_RSP)
    top_val=struct.unpack('<Q',uc.mem_read(sp,8))[0]
    if top_val==0:
     uc.mem_write(sp,struct.pack('<Q',row7_scratch))
   elif addr in (0x152702122, 0x156ad5a92, 0x1470fd5bc, 0x154671883, 0x16f477441):
    if uc.reg_read(UC_X86_REG_RBX)==0:
     uc.reg_write(UC_X86_REG_RBX,row7_scratch)
   elif addr==0x17123f0ed:
    tag_val=a.row7_mode1_investment_tag
    uc.mem_write(0x174527f2c,struct.pack('<II',0x8080a1f5,tag_val))
   elif addr==0x14757e415:
    if not (row7_scratch <= uc.reg_read(UC_X86_REG_RSI) < row7_scratch + 4096):
     uc.reg_write(UC_X86_REG_RSI,row7_scratch+0x800)
    if not (row7_scratch <= uc.reg_read(UC_X86_REG_RBX) < row7_scratch + 4096):
     uc.reg_write(UC_X86_REG_RBX,row7_scratch+0x400)
    if not (row7_scratch <= uc.reg_read(UC_X86_REG_RDI) < row7_scratch + 4096):
     uc.reg_write(UC_X86_REG_RDI,row7_scratch+0x600)
   elif addr==0x151e6a6f6:
    uc.reg_write(UC_X86_REG_RIP,0x15c39f8ef)
   elif addr==0x145845900:
    uc.reg_write(UC_X86_REG_RAX,0x14fe32a9b - 0x1458458f9)
   elif addr==0x147ec7887:
    if uc.reg_read(UC_X86_REG_RDI)==0:
     empty_arr=row7_scratch+0x900
     uc.mem_write(empty_arr+0x18,struct.pack('<Q',row7_scratch+0x980))
     uc.mem_write(empty_arr+0x20,struct.pack('<II',0,0))
     uc.reg_write(UC_X86_REG_RDI,empty_arr)
   elif addr==0x14590b0ab:
    svc_obj=row7_scratch+0x700
    svc_vt=row7_scratch+0x780
    uc.mem_write(svc_obj,struct.pack('<Q',svc_vt))
    uc.mem_write(svc_vt+0x20,struct.pack('<Q',a.target))
    uc.reg_write(UC_X86_REG_RCX,svc_obj)
    uc.reg_write(UC_X86_REG_RIP,0x14590b0af)
  if a.trace_dispatch and addr==0x162478533:
   events=state.setdefault('dispatch_events',[])
   if len(events)<10000:events.append({'source':list(recent)[-2] if len(recent)>1 else None,'dispatcher':hex(addr),'continuation':hex(struct.unpack('<Q',uc.mem_read(tls_block+0x1210,8))[0]),'instruction':state['instructions']})
  if a.inline_dispatch and addr==0x162478533:
   sp=uc.reg_read(UC_X86_REG_RSP)
   if not stack+88<=sp<=stack+0x200000-8:state['stop']={'kind':'unsafe_inline_stack'};uc.emu_stop();return
   target=struct.unpack('<Q',uc.mem_read(tls_block+0x1210,8))[0];writes=[(sp-8,target),(sp-16,uc.reg_read(UC_X86_REG_RAX)),(sp-24,0x162478547),(sp-32,uc.reg_read(UC_X86_REG_EFLAGS)),(sp-40,uc.reg_read(UC_X86_REG_RCX)),(sp-48,uc.reg_read(UC_X86_REG_RDX)),(sp-88,0x171a1191c)]
   for address,value in writes:uc.mem_write(address,struct.pack('<Q',value))
   state['writes']+=8;uc.reg_write(UC_X86_REG_RIP,target);return
  if a.stub_crt_basics and addr in (0x16ef75d84,0x16ef75d88):
   expected=b'\xc5\xfc\x11\x01' if addr==0x16ef75d84 else b'\xc5\xfc\x11\x41\x20';ptr=uc.reg_read(UC_X86_REG_RCX)+(0 if addr==0x16ef75d84 else 32)
   if bytes(uc.mem_read(addr,len(expected)))!=expected or uc.reg_read(UC_X86_REG_YMM0)!=0 or not stack<=ptr<=stack+0x200000-32:state['stop']={'kind':'unsafe_fake_ymm_store','address':hex(addr)};uc.emu_stop();return
   uc.mem_write(ptr,bytes(32));state.setdefault('fake_zero_vector_stores',[]).append({'rip':hex(addr),'address':hex(ptr)});uc.reg_write(UC_X86_REG_RIP,addr+len(expected));return
  if a.stub_crt_basics and addr==0x1574d5ea7:
   expected=b'\xc5\xfc\x11\x44\x24\x50';ptr=uc.reg_read(UC_X86_REG_RSP)+0x50
   if bytes(uc.mem_read(addr,len(expected)))!=expected or uc.reg_read(UC_X86_REG_YMM0)!=0 or not stack<=ptr<=stack+0x200000-32:state['stop']={'kind':'unsafe_fake_ymm_store','address':hex(addr)};uc.emu_stop();return
   uc.mem_write(ptr,bytes(32));state.setdefault('fake_zero_vector_stores',[]).append({'rip':hex(addr),'address':hex(ptr)});uc.reg_write(UC_X86_REG_RIP,addr+len(expected));return
  if a.stub_crt_basics and addr in (0x15efdc261,0x15efdc267,0x15efdc26c):
   specs={0x15efdc261:(b'\xc5\xfc\x11\x44\x24\x60',UC_X86_REG_RSP,0x60),0x15efdc267:(b'\xc5\xfc\x11\x45\x80',UC_X86_REG_RBP,-0x80),0x15efdc26c:(b'\xc5\xfc\x11\x45\xa0',UC_X86_REG_RBP,-0x60)};expected,reg,offset=specs[addr];ptr=uc.reg_read(reg)+offset
   if bytes(uc.mem_read(addr,len(expected)))!=expected or uc.reg_read(UC_X86_REG_YMM0)!=0 or not stack<=ptr<=stack+0x200000-32:state['stop']={'kind':'unsafe_fake_ymm_store','address':hex(addr)};uc.emu_stop();return
   uc.mem_write(ptr,bytes(32));state.setdefault('fake_zero_vector_stores',[]).append({'rip':hex(addr),'address':hex(ptr)});uc.reg_write(UC_X86_REG_RIP,addr+len(expected));return
  if a.stub_crt_basics and addr==0x16ef80ac4:
   expected=b'\xc5\xfc\x11\x01';ptr=uc.reg_read(UC_X86_REG_RCX)
   if bytes(uc.mem_read(addr,len(expected)))!=expected or uc.reg_read(UC_X86_REG_YMM0)!=0 or not 0x173534000<=ptr<=0x1792a6be1-32:state['stop']={'kind':'unsafe_fake_ymm_store','address':hex(addr)};uc.emu_stop();return
   if ptr&~0xfff not in pages:invalid(uc,0,ptr,32,0,None)
   uc.mem_write(ptr,bytes(32));state.setdefault('fake_zero_vector_stores',[]).append({'rip':hex(addr),'address':hex(ptr)});uc.reg_write(UC_X86_REG_RIP,addr+len(expected));return
  if a.stub_crt_basics and addr in (0x157e2ca31,0x157e2ca36):
   expected=b'\xc5\xfc\x11\x40\x20' if addr==0x157e2ca31 else b'\xc5\xfc\x11\x40\x40';ptr=uc.reg_read(UC_X86_REG_RAX)+(0x20 if addr==0x157e2ca31 else 0x40)
   if bytes(uc.mem_read(addr,len(expected)))!=expected or uc.reg_read(UC_X86_REG_YMM0)!=0 or not 0x790000000000<=ptr<=0x790000000000+state.get('fake_heap_used',0)-32:state['stop']={'kind':'unsafe_fake_ymm_store','address':hex(addr)};uc.emu_stop();return
   uc.mem_write(ptr,bytes(32));state.setdefault('fake_zero_vector_stores',[]).append({'rip':hex(addr),'address':hex(ptr)});uc.reg_write(UC_X86_REG_RIP,addr+len(expected));return
  if a.stub_crt_basics and addr in (0x14aed5c3f,0x14aed5c44,0x14aed5c49,0x14aed5c4e):
   specs={0x14aed5c3f:(b'\xc5\xfc\x11\x43\x20',0x20),0x14aed5c44:(b'\xc5\xfc\x11\x43\x40',0x40),0x14aed5c49:(b'\xc5\xfc\x11\x43\x60',0x60),0x14aed5c4e:(b'\xc5\xfc\x11\x83\x80\x00\x00\x00',0x80)};expected,offset=specs[addr];ptr=uc.reg_read(UC_X86_REG_RBX)+offset
   if bytes(uc.mem_read(addr,len(expected)))!=expected or uc.reg_read(UC_X86_REG_YMM0)!=0 or not 0x790000000000<=ptr<=0x790000000000+state.get('fake_heap_used',0)-32:state['stop']={'kind':'unsafe_fake_ymm_store','address':hex(addr)};uc.emu_stop();return
   uc.mem_write(ptr,bytes(32));state.setdefault('fake_zero_vector_stores',[]).append({'rip':hex(addr),'address':hex(ptr)});uc.reg_write(UC_X86_REG_RIP,addr+len(expected));return
  if a.stub_crt_basics and addr==0x15175f9cc:
   expected=b'\xc5\xfc\x11\x45\xef';ptr=uc.reg_read(UC_X86_REG_RBP)-0x11
   if bytes(uc.mem_read(addr,len(expected)))!=expected or uc.reg_read(UC_X86_REG_YMM0)!=0 or not stack<=ptr<=stack+0x200000-32:state['stop']={'kind':'unsafe_fake_ymm_store','address':hex(addr)};uc.emu_stop();return
   uc.mem_write(ptr,bytes(32));state.setdefault('fake_zero_vector_stores',[]).append({'rip':hex(addr),'address':hex(ptr)});uc.reg_write(UC_X86_REG_RIP,addr+len(expected));return
  if a.stub_crt_basics and addr in (0x151dd8b17,0x151dd8b1e):
   loading=addr==0x151dd8b17;expected=b'\xc4\xc1\x7c\x10\x44\x24\x10' if loading else b'\xc4\xc1\x7c\x11\x46\x10';ptr=uc.reg_read(UC_X86_REG_R12 if loading else UC_X86_REG_R14)+0x10
   if bytes(uc.mem_read(addr,len(expected)))!=expected or not (stack<=ptr<=stack+0x200000-32 if loading else 0x790000000000<=ptr<=0x790000000000+state.get('fake_heap_used',0)-32):state['stop']={'kind':'unsafe_fake_ymm_copy','address':hex(addr)};uc.emu_stop();return
   if loading:uc.reg_write(UC_X86_REG_YMM0,int.from_bytes(uc.mem_read(ptr,32),'little'))
   else:uc.mem_write(ptr,uc.reg_read(UC_X86_REG_YMM0).to_bytes(32,'little'))
   state.setdefault('fake_vector_copies',[]).append({'rip':hex(addr),'address':hex(ptr)});uc.reg_write(UC_X86_REG_RIP,addr+len(expected));return
  if a.stub_crt_basics and addr in (0x152665f38,0x152665f3c):
   loading=addr==0x152665f38;expected=b'\xc5\xfc\x10\x07' if loading else b'\xc5\xfc\x11\x03';ptr=uc.reg_read(UC_X86_REG_RDI if loading else UC_X86_REG_RBX)
   if bytes(uc.mem_read(addr,4))!=expected or not (stack<=ptr<=stack+0x200000-32 if loading else 0x790000000000<=ptr<=0x790000000000+state.get('fake_heap_used',0)-32):state['stop']={'kind':'unsafe_fake_ymm_copy','address':hex(addr)};uc.emu_stop();return
   if loading:uc.reg_write(UC_X86_REG_YMM0,int.from_bytes(uc.mem_read(ptr,32),'little'))
   else:uc.mem_write(ptr,uc.reg_read(UC_X86_REG_YMM0).to_bytes(32,'little'))
   state.setdefault('fake_vector_copies',[]).append({'rip':hex(addr),'address':hex(ptr)});uc.reg_write(UC_X86_REG_RIP,addr+4);return
  if a.stub_crt_basics and addr in (0x160679c33,0x160679c38):
   offset=0x50 if addr==0x160679c33 else 0x70;expected=bytes.fromhex('c5fc114350' if offset==0x50 else 'c5fc114370');ptr=uc.reg_read(UC_X86_REG_RBX)+offset
   if bytes(uc.mem_read(addr,5))!=expected or uc.reg_read(UC_X86_REG_YMM0)!=0 or not 0x790000000000<=ptr<=0x790000000000+state.get('fake_heap_used',0)-32:state['stop']={'kind':'unsafe_fake_ymm_store','address':hex(addr)};uc.emu_stop();return
   uc.mem_write(ptr,bytes(32));state.setdefault('fake_zero_vector_stores',[]).append({'rip':hex(addr),'address':hex(ptr)});uc.reg_write(UC_X86_REG_RIP,addr+5);return
  if a.stub_crt_basics and addr in (0x16ef75d80,0x1574d5ea3,0x16ef80ac0,0x157e2ca1e,0x15175f9c8,0x160679c2f):
   if bytes(uc.mem_read(addr,4))!=b'\xc5\xf9\xef\xc0':state['stop']={'kind':'unsafe_fake_vpxor','address':hex(addr)};uc.emu_stop();return
   uc.reg_write(UC_X86_REG_YMM0,0);state.setdefault('fake_vector_zeroes',[]).append(hex(addr));uc.reg_write(UC_X86_REG_RIP,addr+4);return
  if a.stub_crt_basics and addr in (0x172c53a61,0x172c53a67):
   loading=addr==0x172c53a61;expected=bytes.fromhex('c4c17c1040b8' if loading else 'c4817c114402b8');ptr=uc.reg_read(UC_X86_REG_R8)-0x48+(0 if loading else uc.reg_read(UC_X86_REG_R10))
   if bytes(uc.mem_read(addr,len(expected)))!=expected or not 0x790000000000<=ptr<=0x790000000000+state.get('fake_heap_used',0)-32:state['stop']={'kind':'unsafe_fake_ymm_copy','address':hex(addr)};uc.emu_stop();return
   if loading:uc.reg_write(UC_X86_REG_YMM0,int.from_bytes(uc.mem_read(ptr,32),'little'))
   else:uc.mem_write(ptr,uc.reg_read(UC_X86_REG_YMM0).to_bytes(32,'little'))
   state.setdefault('fake_vector_copies',[]).append({'rip':hex(addr),'address':hex(ptr)});uc.reg_write(UC_X86_REG_RIP,addr+len(expected));return
  if a.model_veh and addr==handler_ret:state['stop']={'kind':'synthetic_handler_return'};uc.emu_stop();return
  if (a.stub_crt_basics or a.model_veh) and addr in (0x16f9507ff,0x16f95081f,0x16f95083f,0x16f95085f,0x16f95087f):
   index=(addr-0x16f9507ff)//0x20;expected=bytes.fromhex('c5fc1005')+struct.pack('<I',0x4b61709+index*0x10);ptr=0x1744b1f10+index*0x30
   if bytes(uc.mem_read(addr,8))!=expected:state['stop']={'kind':'unsafe_fake_ymm_copy','address':hex(addr)};uc.emu_stop();return
   if ptr&~0xfff not in pages:invalid(uc,0,ptr,32,0,None)
   uc.reg_write(UC_X86_REG_YMM0,int.from_bytes(uc.mem_read(ptr,32),'little'));state.setdefault('fake_vector_copies',[]).append({'rip':hex(addr),'address':hex(ptr)});uc.reg_write(UC_X86_REG_RIP,addr+8);return
  if (a.stub_crt_basics or a.model_veh) and addr in (0x161addc2e,0x161e2e3ec,0x14e805be1,0x15b4ca09f,0x14fee27b8):
   offsets={0x161addc2e:0xb0,0x161e2e3ec:0xe0,0x14e805be1:0x110,0x15b4ca09f:0x140,0x14fee27b8:0x170};offset=offsets[addr];expected=bytes.fromhex('c5fc1181')+struct.pack('<I',offset);ptr=uc.reg_read(UC_X86_REG_RCX)+offset
   if bytes(uc.mem_read(addr,8))!=expected or not stack<=ptr<=stack+0x200000-32:state['stop']={'kind':'unsafe_fake_ymm_copy','address':hex(addr)};uc.emu_stop();return
   uc.mem_write(ptr,uc.reg_read(UC_X86_REG_YMM0).to_bytes(32,'little'));state.setdefault('fake_vector_copies',[]).append({'rip':hex(addr),'address':hex(ptr)});uc.reg_write(UC_X86_REG_RIP,addr+8);return
  if a.stub_crt_basics and addr in (0x15008a8a0,0x15008a8ab):
   loading=addr==0x15008a8a0;expected=bytes.fromhex('c5fc1045e7' if loading else 'c5fc114210');ptr=(uc.reg_read(UC_X86_REG_RBP)-0x19) if loading else (uc.reg_read(UC_X86_REG_RDX)+0x10)
   if bytes(uc.mem_read(addr,5))!=expected or not (stack<=ptr<=stack+0x200000-32 if loading else 0x790000000000<=ptr<=0x790000000000+state.get('fake_heap_used',0)-32):state['stop']={'kind':'unsafe_fake_ymm_copy','address':hex(addr)};uc.emu_stop();return
   if loading:uc.reg_write(UC_X86_REG_YMM0,int.from_bytes(uc.mem_read(ptr,32),'little'))
   else:uc.mem_write(ptr,uc.reg_read(UC_X86_REG_YMM0).to_bytes(32,'little'))
   state.setdefault('fake_vector_copies',[]).append({'rip':hex(addr),'address':hex(ptr)});uc.reg_write(UC_X86_REG_RIP,addr+5);return
  if a.model_veh and addr==0x7c0000000000 and state.get('fake_dynamic_mapped'):
   sp=uc.reg_read(UC_X86_REG_RSP);ptr=uc.reg_read(UC_X86_REG_RCX)
   if not stack<=sp<=stack+0x200000-8 or not 0x172c84000<=ptr<0x173534000-128:state['stop']={'kind':'unsafe_fake_window_message'};uc.emu_stop();return
   state.setdefault('fake_window_messages',[]).append({'name_pointer':hex(ptr),'result':0xc000});uc.reg_write(UC_X86_REG_RAX,0xc000);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
  if a.model_veh and addr==0x7c0000000010 and state.get('fake_dynamic_mapped'):
   sp=uc.reg_read(UC_X86_REG_RSP);ptr=uc.reg_read(UC_X86_REG_RCX)
   if not stack<=sp<=stack+0x200000-8 or not stack<=ptr<=stack+0x200000-1024:state['stop']={'kind':'unsafe_fake_path_remove'};uc.emu_stop();return
   raw=bytes(uc.mem_read(ptr,1024));end=next((i for i in range(0,len(raw)-1,2) if raw[i:i+2]==b'\0\0'),-1)
   if end<0:state['stop']={'kind':'unterminated_fake_path'};uc.emu_stop();return
   path=raw[:end].decode('utf-16le');cut=max(path.rfind('\\'),path.rfind('/'))
   if cut<0:result=0
   else:uc.mem_write(ptr,(path[:cut]+'\0').encode('utf-16le'));result=1
   state.setdefault('fake_path_remove',[]).append({'result':result});uc.reg_write(UC_X86_REG_RAX,result);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
  if a.model_veh and addr==0x7c0000000020 and state.get('fake_dynamic_mapped'):
   ptr=uc.reg_read(UC_X86_REG_RCX)
   if not stack<=ptr<=stack+0x200000-64:state['stop']={'kind':'unsafe_fake_file_operation'};uc.emu_stop();return
   b=bytes(uc.mem_read(ptr,64));op=struct.unpack_from('<I',b,8)[0];src=struct.unpack_from('<Q',b,16)[0];flags=struct.unpack_from('<H',b,32)[0]
   if op!=3 or not stack<=src<=stack+0x200000-2048:state['stop']={'kind':'unsupported_fake_file_operation','operation':op,'source':hex(src)};uc.emu_stop();return
   raw=bytes(uc.mem_read(src,2048));end=next((i for i in range(0,len(raw)-3,2) if raw[i:i+4]==b'\0\0\0\0'),-1)
   if end<0:state['stop']={'kind':'unterminated_fake_file_operation'};uc.emu_stop();return
   paths=raw[:end].decode('utf-16le').split('\0')
   if flags!=20 or paths!=['C:\\Temp\\Marathon\\*.*']:state['stop']={'kind':'unsupported_fake_file_operation','operation':op,'flags':flags,'synthetic_paths':paths};uc.emu_stop();return
   sp=uc.reg_read(UC_X86_REG_RSP)
   if not stack<=sp<=stack+0x200000-8:state['stop']={'kind':'unsafe_fake_file_operation_stack'};uc.emu_stop();return
   uc.mem_write(ptr+36,struct.pack('<I',0));state.setdefault('fake_file_operations',[]).append({'operation':'delete','synthetic_path':paths[0],'result':'empty synthetic directory','host_filesystem_access':False});uc.reg_write(UC_X86_REG_RAX,0);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
  if a.model_veh and addr==0x7c0000000030 and state.get('fake_dynamic_mapped'):
   guid=uc.reg_read(UC_X86_REG_RCX);sp=uc.reg_read(UC_X86_REG_RSP)
   if not 0x172c84000<=guid<=0x173534000-16:state['stop']={'kind':'unsafe_fake_known_folder_guid'};uc.emu_stop();return
   if guid&~0xfff not in pages:invalid(uc,0,guid,16,0,None)
   flags=uc.reg_read(UC_X86_REG_RDX);token=uc.reg_read(UC_X86_REG_R8);out=uc.reg_read(UC_X86_REG_R9);key=bytes(uc.mem_read(guid,16)).hex()
   if (key,flags) not in (('d09ad3fd8f23af46adb46c85480369c7',0x8000),('825dab62c1fdc34da9dd070d1d495d97',0)) or token!=0 or not stack<=out<=stack+0x200000-8 or not stack<=sp<=stack+0x200000-8:state['stop']={'kind':'unsupported_fake_known_folder','guid':key,'flags':hex(flags),'token':hex(token)};uc.emu_stop();return
   buf=exception_mem+0x7000;folder='Documents' if key.startswith('d09a') else 'ProgramData';uc.mem_write(buf,('C:\\Preservation\\'+folder+'\0').encode('utf-16le'));uc.mem_write(out,struct.pack('<Q',buf));state.setdefault('fake_known_folder_calls',[]).append({'guid':key,'path':'synthetic'});uc.reg_write(UC_X86_REG_RAX,0);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
  if a.model_veh and addr==0x7c0000000040 and state.get('fake_dynamic_mapped'):
   sp=uc.reg_read(UC_X86_REG_RSP);ptr=uc.reg_read(UC_X86_REG_RCX)
   if not stack<=sp<=stack+0x200000-8 or ptr!=exception_mem+0x7000:state['stop']={'kind':'unsafe_fake_cotaskmemfree'};uc.emu_stop();return
   state['fake_known_folder_freed']=True;uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
  if a.model_veh and addr==0x7c0000000050 and state.get('fake_dynamic_mapped'):
   sp=uc.reg_read(UC_X86_REG_RSP)
   if not stack<=sp<=stack+0x200000-8:state['stop']={'kind':'unsafe_fake_timegettime'};uc.emu_stop();return
   value=(state.get('fake_timegettime',100000)+1)&0xffffffff;state['fake_timegettime']=value;uc.reg_write(UC_X86_REG_RAX,value);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
  if a.model_system_heap_info and any(addr==int(m.get('fake_heap_information_marker','0'),16) for m in fake_system_modules):
   sp=uc.reg_read(UC_X86_REG_RSP);args=[uc.reg_read(r) for r in (UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9)]
   if not stack<=sp<=stack+0x200000-8 or args!=[0,1,0,0]:state['stop']={'kind':'unsupported_fake_heap_information','args':[hex(x) for x in args]};uc.emu_stop();return
   state.setdefault('fake_system_heap_info_calls',[]).append({'args':[hex(x) for x in args],'host_api_called':False});uc.reg_write(UC_X86_REG_RAX,1);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
  if a.model_system_heap_info and any(addr==int(m.get('fake_heap_create_marker','0'),16) for m in fake_system_modules):
   sp=uc.reg_read(UC_X86_REG_RSP);args=[uc.reg_read(r) for r in (UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8)]
   if not stack<=sp<=stack+0x200000-8 or args!=[0,0x100000,0]:state['stop']={'kind':'unsupported_fake_heap_create','args':[hex(x) for x in args]};uc.emu_stop();return
   result=0x7d0000001000;state.setdefault('fake_system_heap_create_calls',[]).append({'args':[hex(x) for x in args],'handle':hex(result),'host_api_called':False});uc.reg_write(UC_X86_REG_RAX,result);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
  if a.model_system_heap_info and any(addr==int(m.get('fake_heap_alloc_marker','0'),16) for m in fake_system_modules):
   sp=uc.reg_read(UC_X86_REG_RSP);handle=uc.reg_read(UC_X86_REG_RCX);flags=uc.reg_read(UC_X86_REG_RDX);n=uc.reg_read(UC_X86_REG_R8);heap=0x790000000000
   if not stack<=sp<=stack+0x200000-8 or handle!=0x7d0000001000 or flags not in (0,8) or not 1<=n<=0x1000000:state['stop']={'kind':'unsupported_fake_system_heap_alloc','handle':hex(handle),'flags':hex(flags),'size':n};uc.emu_stop();return
   if 'fake_heap_used' not in state:uc.mem_map(heap,0x1000000);state['fake_heap_used']=0
   off=(state['fake_heap_used']+15)&~15;end=off+n
   if end>0x1000000:state['stop']={'kind':'fake_heap_exhausted'};uc.emu_stop();return
   state['fake_heap_used']=end;result=heap+off;state.setdefault('fake_heap_allocations',{})[hex(result)]=n;state.setdefault('fake_system_heap_allocs',[]).append({'size':n,'flags':flags,'result':hex(result),'host_api_called':False});uc.reg_write(UC_X86_REG_RAX,result);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
  if addr==a.target:state['stop']={'kind':'target_reached','address':hex(addr)};uc.emu_stop();return
  if addr==return_marker:state['stop']={'kind':'synthetic_return','address':hex(addr)};uc.emu_stop();return
  if marker<=addr<marker+0x3000:
   index=(addr-marker)//16;name=import_names[index] if (addr-marker)%16==0 and index<len(import_names) else '<unknown>'
   if a.checkpoint_before_import and name.lower()==a.checkpoint_before_import.lower():
    state['stop']={'kind':'synthetic_import_checkpoint','import':name,'address':hex(addr)};uc.emu_stop();return

   if a.stub_crt_basics and name.lower().split('!')[-1] in ('_set_app_type','_set_fmode','__p__commode','_crt_atexit','_configure_narrow_argv','_initialize_narrow_environment','_configthreadlocale','setunhandledexceptionfilter','_set_new_mode'):
    sp=uc.reg_read(UC_X86_REG_RSP);short=name.lower().split('!')[-1];arg=uc.reg_read(UC_X86_REG_RCX)
    if not stack<=sp<=stack+0x200000-8:state['stop']={'kind':'unsafe_crt_stub'};uc.emu_stop();return
    state.setdefault('fake_crt_calls',[]).append({'name':name,'arg':hex(arg)});ret=struct.unpack('<Q',uc.mem_read(sp,8))[0]
    if short in ('_set_fmode','_crt_atexit','_configure_narrow_argv','_initialize_narrow_environment','setunhandledexceptionfilter','_set_new_mode'):uc.reg_write(UC_X86_REG_RAX,0)
    if short=='_configthreadlocale':uc.reg_write(UC_X86_REG_RAX,2)
    if short=='__p__commode':uc.reg_write(UC_X86_REG_RAX,teb+0x1000)
    uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,ret);return
   if a.stub_crt_basics and name.lower()=='kernel32.dll!initializeslisthead':
    sp=uc.reg_read(UC_X86_REG_RSP);ptr=uc.reg_read(UC_X86_REG_RCX)
    if ptr%16 or not (0x173534000<=ptr<=0x1792a6be1-16 or 0x790000000000<=ptr<=0x790000000000+state.get('fake_heap_used',0)-16):state['stop']={'kind':'unsafe_slist'};uc.emu_stop();return
    if 0x173534000<=ptr<0x1792a6be1 and ptr&~0xfff not in pages:invalid(uc,0,ptr,16,0,None)
    uc.mem_write(ptr,bytes(16));state.setdefault('fake_crt_calls',[]).append({'name':name,'arg':hex(ptr)});uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.stub_crt_basics and name.lower()=='api-ms-win-crt-convert-l1-1-0.dll!atoi':
    import re
    sp=uc.reg_read(UC_X86_REG_RSP);ptr=uc.reg_read(UC_X86_REG_RCX)
    if not (0x172c84000<=ptr<0x1792a6be1-128 or stack<=ptr<=stack+0x200000-128):state['stop']={'kind':'unsafe_fake_atoi'};uc.emu_stop();return
    if not stack<=ptr<stack+0x200000 and ptr&~0xfff not in pages:invalid(uc,0,ptr,128,0,None)
    raw=bytes(uc.mem_read(ptr,128));end=raw.find(b'\0')
    if end<0:state['stop']={'kind':'unterminated_fake_atoi'};uc.emu_stop();return
    value=raw[:end];match=re.match(rb'^\s*[+-]?[0-9]+',value);result=int(match.group()) if match else 0
    if not -0x80000000<=result<=0x7fffffff:state['stop']={'kind':'overflow_fake_atoi'};uc.emu_stop();return
    state.setdefault('fake_crt_calls',[]).append({'name':name,'input':value.decode('ascii','backslashreplace'),'result':result});uc.reg_write(UC_X86_REG_RAX,result&0xffffffff);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.stub_crt_basics and name.lower()=='api-ms-win-crt-string-l1-1-0.dll!strnlen':
    sp=uc.reg_read(UC_X86_REG_RSP);ptr=uc.reg_read(UC_X86_REG_RCX);n=uc.reg_read(UC_X86_REG_RDX)
    if n>0x100000 or not (0x172c84000<=ptr<=0x1792a6be1-n or stack<=ptr<=stack+0x200000-n or tls_block<=ptr<=tls_block+0x100000-n):state['stop']={'kind':'unsafe_fake_strnlen'};uc.emu_stop();return
    result=n;pos=0
    while pos<n:
     current=ptr+pos;page=current&~0xfff;size=min(n-pos,4096-(current&0xfff))
     if not (stack<=page<stack+0x200000 or tls_block<=page<tls_block+0x100000) and page not in pages:invalid(uc,0,page,1,0,None)
     raw=bytes(uc.mem_read(current,size));end=raw.find(b'\0')
     if end>=0:result=pos+end;break
     pos+=size
    state.setdefault('fake_crt_calls',[]).append({'name':name,'arg':hex(ptr),'limit':n,'result':result});uc.reg_write(UC_X86_REG_RAX,result);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.stub_crt_basics and name.lower()=='api-ms-win-crt-string-l1-1-0.dll!strncpy_s':
    sp=uc.reg_read(UC_X86_REG_RSP);dst=uc.reg_read(UC_X86_REG_RCX);size=uc.reg_read(UC_X86_REG_RDX);src=uc.reg_read(UC_X86_REG_R8);limit=uc.reg_read(UC_X86_REG_R9)
    if not 1<=size<=4096 or (limit!=0xffffffffffffffff and limit>=size) or not (0x173534000<=dst<=0x1792a6be1-size or stack<=dst<=stack+0x200000-size) or not (0x172c84000<=src<=0x1792a6be1-size or stack<=src<=stack+0x200000-size or tls_block<=src<=tls_block+0x100000-size):state['stop']={'kind':'unsafe_fake_strncpy'};uc.emu_stop();return
    for ptr in (src,dst):
     for page in range(ptr&~0xfff,(ptr+size+4095)&~0xfff,4096):
      if not (stack<=page<stack+0x200000 or tls_block<=page<tls_block+0x100000) and page not in pages:invalid(uc,0,page,1,0,None)
    raw=bytes(uc.mem_read(src,size));end=raw.find(b'\0');effective=size-1 if limit==0xffffffffffffffff else limit;truncated=limit==0xffffffffffffffff and (end<0 or end>effective);copied=raw[:effective] if end<0 else raw[:min(end,effective)];uc.mem_write(dst,copied+b'\0');result=80 if truncated else 0;state.setdefault('fake_crt_calls',[]).append({'name':name,'destination':hex(dst),'source':hex(src),'size':size,'result':result});uc.reg_write(UC_X86_REG_RAX,result);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.stub_crt_basics and name.lower()=='vcruntime140.dll!strstr':
    sp=uc.reg_read(UC_X86_REG_RSP);ptr=uc.reg_read(UC_X86_REG_RCX);needle=uc.reg_read(UC_X86_REG_RDX)
    if any(not (0x172c84000<=v<=0x1792a6be1-4096 or stack<=v<=stack+0x200000-4096) for v in (ptr,needle)):state['stop']={'kind':'unsafe_fake_strstr'};uc.emu_stop();return
    values=[]
    for v in (ptr,needle):
     for page in range(v&~0xfff,(v+4096+4095)&~0xfff,4096):
      if not (stack<=page<stack+0x200000 or tls_block<=page<tls_block+0x100000) and page not in pages:invalid(uc,0,page,1,0,None)
     raw=bytes(uc.mem_read(v,4096));end=raw.find(b'\0')
     if end<0:state['stop']={'kind':'unterminated_fake_strstr'};uc.emu_stop();return
     values.append(raw[:end])
    found=values[0].find(values[1]);result=0 if found<0 else ptr+found;state.setdefault('fake_crt_calls',[]).append({'name':name,'result':hex(result)});uc.reg_write(UC_X86_REG_RAX,result);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.stub_crt_basics and name.lower()=='api-ms-win-crt-stdio-l1-1-0.dll!__stdio_common_vsnprintf_s':
    sp=uc.reg_read(UC_X86_REG_RSP);opts=uc.reg_read(UC_X86_REG_RCX);dst=uc.reg_read(UC_X86_REG_RDX);size=uc.reg_read(UC_X86_REG_R8);limit=uc.reg_read(UC_X86_REG_R9)
    if opts not in (0,0x24) or limit!=0xffffffffffffffff or not 1<=size<=4096 or not stack<=sp<=stack+0x200000-0x40 or not (0x173534000<=dst<=0x1792a6be1-size or stack<=dst<=stack+0x200000-size or tls_block<=dst<=tls_block+0x100000-size):state['stop']={'kind':'unsafe_fake_format'};uc.emu_stop();return
    fmt,locale,va=struct.unpack('<QQQ',bytes(uc.mem_read(sp+0x28,24)))
    if locale or not stack<=va<=stack+0x200000-64 or not 0x172c84000<=fmt<=0x173534000-4096:state['stop']={'kind':'unsupported_fake_format_args'};uc.emu_stop();return
    args=struct.unpack('<8Q',bytes(uc.mem_read(va,64)));values=[]
    for v in (fmt,):
     if not 0x172c84000<=v<=0x173534000-4096:state['stop']={'kind':'unsupported_fake_format_pointer'};uc.emu_stop();return
     for page in range(v&~0xfff,(v+4096+4095)&~0xfff,4096):
      if not (stack<=page<stack+0x200000 or tls_block<=page<tls_block+0x100000) and page not in pages:invalid(uc,0,page,1,0,None)
     raw=bytes(uc.mem_read(v,4096));end=raw.find(b'\0')
     if end<0:state['stop']={'kind':'unterminated_fake_format'};uc.emu_stop();return
     values.append(raw[:end])
    if values[0] in (b'%s%s',b' %s',b'%s_%s@%s',b'%s@%s@%s'):
     for v in args[:2 if values[0]==b'%s%s' else 3 if values[0] in (b'%s_%s@%s',b'%s@%s@%s') else 1]:
      if not (0x172c84000<=v<=0x1792a6be1-4096 or stack<=v<=stack+0x200000-4096 or tls_block<=v<=tls_block+0x100000-4096):state['stop']={'kind':'unsupported_fake_format_pointer','pointer':hex(v)};uc.emu_stop();return
      for page in range(v&~0xfff,(v+4096+4095)&~0xfff,4096):
       if not (stack<=page<stack+0x200000 or tls_block<=page<tls_block+0x100000) and page not in pages:invalid(uc,0,page,1,0,None)
      raw=bytes(uc.mem_read(v,4096));end=raw.find(b'\0')
      if end<0:state['stop']={'kind':'unterminated_fake_format'};uc.emu_stop();return
      values.append(raw[:end])
     out=values[1]+values[2] if values[0]==b'%s%s' else values[1]+b'_'+values[2]+b'@'+values[3] if values[0]==b'%s_%s@%s' else values[1]+b'@'+values[2]+b'@'+values[3] if values[0]==b'%s@%s@%s' else b' '+values[1]
    elif values[0]==b'%02X:%02X:%02X:%02X:%02X:%02X:%02X%02X':out=(values[0].decode()%tuple(z&0xffffffff for z in args)).encode()
    elif values[0]==b'%07d':
     value=args[0]&0xffffffff;value=value if value<0x80000000 else value-0x100000000;out=f'{value:07d}'.encode()
    elif values[0]==b'+%d':
     value=args[0]&0xffffffff;value=value if value<0x80000000 else value-0x100000000;out=('+'+str(value)).encode()
    elif values[0] in (b'%016llX', b'%016llx'):
     out = (f'{args[0]&0xffffffffffffffff:016X}' if values[0]==b'%016llX' else f'{args[0]&0xffffffffffffffff:016x}').encode()
    elif b'%' not in values[0]:out=values[0]
    else:state['stop']={'kind':'unsupported_fake_format_value','format':values[0].decode('ascii','backslashreplace')};uc.emu_stop();return
    if len(out)>=size:state['stop']={'kind':'unsupported_fake_format_length'};uc.emu_stop();return
    for page in range(dst&~0xfff,(dst+size+4095)&~0xfff,4096):
     if not (stack<=page<stack+0x200000 or tls_block<=page<tls_block+0x100000) and page not in pages:invalid(uc,0,page,1,0,None)
    uc.mem_write(dst,out+b'\0');state.setdefault('fake_crt_calls',[]).append({'import':name,'format':values[0].decode('ascii'),'result':len(out)});uc.reg_write(UC_X86_REG_RAX,len(out));uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.stub_crt_basics and name.lower()=='api-ms-win-crt-string-l1-1-0.dll!strncmp':
    sp=uc.reg_read(UC_X86_REG_RSP);left=uc.reg_read(UC_X86_REG_RCX);right=uc.reg_read(UC_X86_REG_RDX);n=uc.reg_read(UC_X86_REG_R8)
    if not stack<=sp<=stack+0x200000-8 or n>4096 or any(not (0x172c84000<=v<=0x1792a6be1-n or stack<=v<=stack+0x200000-n) for v in (left,right)):state['stop']={'kind':'unsafe_fake_strncmp'};uc.emu_stop();return
    vals=[]
    for v in (left,right):
     for page in range(v&~0xfff,(v+n+4095)&~0xfff,4096):
      if not (stack<=page<stack+0x200000 or tls_block<=page<tls_block+0x100000) and page not in pages:invalid(uc,0,page,1,0,None)
     vals.append(bytes(uc.mem_read(v,n)))
    result=0
    for x,y in zip(*vals):
     if x!=y:result=x-y;break
     if not x:break
    state.setdefault('fake_crt_calls',[]).append({'import':name,'length':n,'result':result});uc.reg_write(UC_X86_REG_RAX,result&0xffffffff);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.stub_crt_basics and name.lower() in ('kernel32.dll!getcurrentprocessid','kernel32.dll!getcurrentthreadid'):
    sp=uc.reg_read(UC_X86_REG_RSP);state.setdefault('fake_crt_calls',[]).append({'name':name,'result':1});uc.reg_write(UC_X86_REG_RAX,1);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.stub_crt_basics and name.lower()=='api-ms-win-crt-time-l1-1-0.dll!_time64':
    sp=uc.reg_read(UC_X86_REG_RSP);ptr=uc.reg_read(UC_X86_REG_RCX)
    if not stack<=sp<=stack+0x200000-8 or ptr and not stack<=ptr<=stack+0x200000-8:state['stop']={'kind':'unsafe_fake_time64'};uc.emu_stop();return
    if ptr:uc.mem_write(ptr,struct.pack('<q',1600000000))
    state.setdefault('fake_crt_calls',[]).append({'import':name,'result':1600000000});uc.reg_write(UC_X86_REG_RAX,1600000000);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.stub_crt_basics and name.lower()=='api-ms-win-crt-time-l1-1-0.dll!_ctime64':
    sp=uc.reg_read(UC_X86_REG_RSP);ptr=uc.reg_read(UC_X86_REG_RCX)
    if not stack<=sp<=stack+0x200000-8 or not stack<=ptr<=stack+0x200000-8 or struct.unpack('<q',bytes(uc.mem_read(ptr,8)))[0]!=1600000000:state['stop']={'kind':'unsupported_fake_ctime64'};uc.emu_stop();return
    buf=teb+0x1100;uc.mem_write(buf,b'Sun Sep 13 12:26:40 2020\n\0');state.setdefault('fake_crt_calls',[]).append({'import':name,'fixed_utc':True});uc.reg_write(UC_X86_REG_RAX,buf);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.stub_crt_basics and name.lower()=='api-ms-win-crt-time-l1-1-0.dll!_gmtime64':
    sp=uc.reg_read(UC_X86_REG_RSP);ptr=uc.reg_read(UC_X86_REG_RCX)
    if not stack<=sp<=stack+0x200000-8 or not stack<=ptr<=stack+0x200000-8 or struct.unpack('<q',bytes(uc.mem_read(ptr,8)))[0]!=1600000000:state['stop']={'kind':'unsupported_fake_gmtime64'};uc.emu_stop();return
    buf=teb+0x1200;uc.mem_write(buf,struct.pack('<9i',40,26,12,13,8,120,0,256,0));state.setdefault('fake_crt_calls',[]).append({'import':name,'fixed_utc':True});uc.reg_write(UC_X86_REG_RAX,buf);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.stub_crt_basics and name.lower()=='vcruntime140.dll!memset':
    sp=uc.reg_read(UC_X86_REG_RSP);ptr=uc.reg_read(UC_X86_REG_RCX);value=uc.reg_read(UC_X86_REG_RDX)&255;n=uc.reg_read(UC_X86_REG_R8)
    if not stack<=sp<=stack+0x200000-8 or n>0x200000 or not (0x173534000<=ptr<=0x1792a6be1-n or stack<=ptr<=stack+0x200000-n or 0x790000000000<=ptr<=0x790000000000+state.get('fake_heap_used',0)-n or any(start<=ptr<=end-n for start,end in state.get('fake_virtual_commits',[]))):state['stop']={'kind':'unsafe_fake_memset'};uc.emu_stop();return
    for page in range(ptr&~0xfff,(ptr+n+4095)&~0xfff,4096):
     if not (stack<=page<stack+0x200000 or tls_block<=page<tls_block+0x100000 or 0x790000000000<=page<0x790000000000+0x1000000) and page not in pages:invalid(uc,0,page,1,0,None)
    uc.mem_write(ptr,bytes([value])*n);state.setdefault('fake_crt_calls',[]).append({'import':name,'destination':hex(ptr),'size':n,'value':value});uc.reg_write(UC_X86_REG_RAX,ptr);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.stub_crt_basics and name.lower()=='advapi32.dll!getusernamea':
    sp=uc.reg_read(UC_X86_REG_RSP);dst=uc.reg_read(UC_X86_REG_RCX);sizeptr=uc.reg_read(UC_X86_REG_RDX);value=b'preservation\0'
    if not stack<=sp<=stack+0x200000-8 or not stack<=sizeptr<=stack+0x200000-4 or not stack<=dst<=stack+0x200000-len(value) or struct.unpack('<I',bytes(uc.mem_read(sizeptr,4)))[0]<len(value):state['stop']={'kind':'unsafe_fake_username'};uc.emu_stop();return
    uc.mem_write(dst,value);uc.mem_write(sizeptr,struct.pack('<I',len(value)));state.setdefault('fake_crt_calls',[]).append({'import':name,'value':'synthetic'});uc.reg_write(UC_X86_REG_RAX,1);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.stub_crt_basics and name.lower()=='iphlpapi.dll!getadaptersaddresses':
    sp=uc.reg_read(UC_X86_REG_RSP)
    if not stack<=sp<=stack+0x200000-0x30:state['stop']={'kind':'unsafe_fake_adapter_query'};uc.emu_stop();return
    state.setdefault('fake_crt_calls',[]).append({'import':name,'result':'ERROR_NO_DATA','host_network_access':False});uc.reg_write(UC_X86_REG_RAX,232);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.stub_crt_basics and name.lower() in ('vcruntime140.dll!memcpy','vcruntime140.dll!memmove'):
    sp=uc.reg_read(UC_X86_REG_RSP);dst=uc.reg_read(UC_X86_REG_RCX);src=uc.reg_read(UC_X86_REG_RDX);n=uc.reg_read(UC_X86_REG_R8)
    if not stack<=sp<=stack+0x200000-8 or n>65536 or not (0x173534000<=dst<=0x179d3e000-n or stack<=dst<=stack+0x200000-n or 0x790000000000<=dst<=0x790000000000+state.get('fake_heap_used',0)-n or any(start<=dst<=end-n for start,end in state.get('fake_virtual_commits',[]))) or (n and not (0x172c84000<=src<=0x179d3e000-n or stack<=src<=stack+0x200000-n or 0x790000000000<=src<=0x790000000000+state.get('fake_heap_used',0)-n or any(start<=src<=end-n for start,end in state.get('fake_virtual_commits',[])))):state['stop']={'kind':'unsafe_fake_memcpy'};uc.emu_stop();return
    for ptr in (dst,src):
     for page in range(ptr&~0xfff,(ptr+n+4095)&~0xfff,4096):
      if not (stack<=page<stack+0x200000 or tls_block<=page<tls_block+0x100000 or 0x790000000000<=page<0x790000000000+0x1000000) and page not in pages:invalid(uc,0,page,1,0,None)
    uc.mem_write(dst,bytes(uc.mem_read(src,n)) if n else b'');state.setdefault('fake_crt_calls',[]).append({'import':name,'destination':hex(dst),'source':hex(src),'size':n});uc.reg_write(UC_X86_REG_RAX,dst);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.stub_crt_basics and name.lower()=='advapi32.dll!reggetvaluea':
    sp=uc.reg_read(UC_X86_REG_RSP);flags=uc.reg_read(UC_X86_REG_R9)
    if not stack<=sp<=stack+0x200000-0x40 or flags&0x20000000:state['stop']={'kind':'unsafe_fake_registry_query'};uc.emu_stop();return
    state.setdefault('fake_crt_calls',[]).append({'import':name,'result':'ERROR_FILE_NOT_FOUND','host_registry_access':False});uc.reg_write(UC_X86_REG_RAX,2);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.stub_crt_basics and name.lower()=='kernel32.dll!globalmemorystatusex':
    sp=uc.reg_read(UC_X86_REG_RSP);ptr=uc.reg_read(UC_X86_REG_RCX)
    if not stack<=sp<=stack+0x200000-8 or not stack<=ptr<=stack+0x200000-64 or struct.unpack('<I',bytes(uc.mem_read(ptr,4)))[0]!=64:state['stop']={'kind':'unsafe_fake_memory_status'};uc.emu_stop();return
    uc.mem_write(ptr,struct.pack('<II7Q',64,50,8<<30,4<<30,16<<30,8<<30,1<<47,1<<46,0));state.setdefault('fake_crt_calls',[]).append({'import':name,'synthetic':True});uc.reg_write(UC_X86_REG_RAX,1);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.stub_crt_basics and name.lower()=='api-ms-win-crt-runtime-l1-1-0.dll!_register_onexit_function':
    sp=uc.reg_read(UC_X86_REG_RSP);table=uc.reg_read(UC_X86_REG_RCX);callback=uc.reg_read(UC_X86_REG_RDX)
    if not stack<=sp<=stack+0x200000-8 or not 0x173534000<=table<0x1792a6be1 or not 0x140001000<=callback<0x172c84000:state['stop']={'kind':'unsafe_fake_onexit'};uc.emu_stop();return
    state.setdefault('fake_crt_calls',[]).append({'import':name,'table':hex(table),'callback':hex(callback),'executed':False});uc.reg_write(UC_X86_REG_RAX,0);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.stub_crt_basics and name.lower() in ('kernel32.dll!initializecriticalsectionex','kernel32.dll!initializecriticalsectionandspincount'):
    sp=uc.reg_read(UC_X86_REG_RSP);ptr=uc.reg_read(UC_X86_REG_RCX)
    if not stack<=sp<=stack+0x200000-8 or ptr%8 or not 0x173534000<=ptr<=0x1792a6be1-40 or (name.lower().endswith('initializecriticalsectionex') and uc.reg_read(UC_X86_REG_R8)!=0):state['stop']={'kind':'unsafe_fake_critical_section'};uc.emu_stop();return
    if ptr&~0xfff not in pages:invalid(uc,0,ptr,40,0,None)
    uc.mem_write(ptr,struct.pack('<QiIQQQ',0,-1,0,0,0,0));state.setdefault('fake_crt_calls',[]).append({'import':name,'object':hex(ptr),'synchronization':'synthetic single-threaded'});uc.reg_write(UC_X86_REG_RAX,1);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.stub_crt_basics and name.lower()=='api-ms-win-crt-heap-l1-1-0.dll!malloc':
    sp=uc.reg_read(UC_X86_REG_RSP);n=uc.reg_read(UC_X86_REG_RCX);heap=0x790000000000
    if not stack<=sp<=stack+0x200000-8 or n>0x100000:state['stop']={'kind':'unsafe_fake_malloc'};uc.emu_stop();return
    if 'fake_heap_used' not in state:uc.mem_map(heap,0x1000000);state['fake_heap_used']=0
    off=(state['fake_heap_used']+15)&~15;end=off+max(1,n)
    if end>0x1000000:state['stop']={'kind':'fake_heap_exhausted'};uc.emu_stop();return
    state['fake_heap_used']=end;result=heap+off;state.setdefault('fake_heap_allocations',{})[hex(result)]=n;state.setdefault('fake_crt_calls',[]).append({'import':name,'size':n,'result':hex(result)});uc.reg_write(UC_X86_REG_RAX,result);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.stub_crt_basics and name.lower() in ('kernel32.dll!initoncebegininitialize','kernel32.dll!initoncecomplete'):
    sp=uc.reg_read(UC_X86_REG_RSP);ptr=uc.reg_read(UC_X86_REG_RCX);flags=uc.reg_read(UC_X86_REG_RDX);short=name.lower().split('!')[-1]
    if not stack<=sp<=stack+0x200000-8 or flags!=0 or not 0x790000000000<=ptr<0x790000000000+state.get('fake_heap_used',0):state['stop']={'kind':'unsafe_fake_once'};uc.emu_stop();return
    states=state.setdefault('fake_once_states',{});key=hex(ptr)
    if short=='initoncebegininitialize':
     out=uc.reg_read(UC_X86_REG_R8)
     if not stack<=out<=stack+0x200000-4:state['stop']={'kind':'unsafe_fake_once_output'};uc.emu_stop();return
     pending=0 if states.get(key)=='complete' else 1;uc.mem_write(out,struct.pack('<I',pending));states[key]='complete' if pending==0 else 'pending'
    else:
     if states.get(key)!='pending':state['stop']={'kind':'unexpected_fake_once_complete'};uc.emu_stop();return
     states[key]='complete'
    state.setdefault('fake_crt_calls',[]).append({'import':name,'object':key,'state':states[key]});uc.reg_write(UC_X86_REG_RAX,1);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.stub_crt_basics and name.lower()=='msvcp140.dll!_mtx_init_in_situ':
    sp=uc.reg_read(UC_X86_REG_RSP);ptr=uc.reg_read(UC_X86_REG_RCX);kind=uc.reg_read(UC_X86_REG_RDX)
    if not stack<=sp<=stack+0x200000-8 or kind!=2 or not 0x790000000000<=ptr<0x790000000000+state.get('fake_heap_used',0):state['stop']={'kind':'unsafe_fake_mutex'};uc.emu_stop();return
    state.setdefault('fake_crt_calls',[]).append({'import':name,'object':hex(ptr),'kind':kind,'synchronization':'synthetic single-threaded'});uc.reg_write(UC_X86_REG_RAX,0);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.stub_crt_basics and name.lower() in ('msvcp140.dll!_mtx_lock','msvcp140.dll!_mtx_unlock'):
    sp=uc.reg_read(UC_X86_REG_RSP);ptr=uc.reg_read(UC_X86_REG_RCX);short=name.lower().split('!')[-1];key=hex(ptr);locks=state.setdefault('fake_mutex_locks',{})
    if not stack<=sp<=stack+0x200000-8 or not 0x790000000000<=ptr<0x790000000000+state.get('fake_heap_used',0) or (short=='_mtx_unlock' and not locks.get(key)):state['stop']={'kind':'unsafe_fake_mutex_lock'};uc.emu_stop();return
    locks[key]=locks.get(key,0)+(1 if short=='_mtx_lock' else -1);state.setdefault('fake_crt_calls',[]).append({'import':name,'object':key,'depth':locks[key]});uc.reg_write(UC_X86_REG_RAX,0);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.stub_crt_basics and name.lower()=='api-ms-win-crt-heap-l1-1-0.dll!free':
    sp=uc.reg_read(UC_X86_REG_RSP);ptr=uc.reg_read(UC_X86_REG_RCX);allocs=state.setdefault('fake_heap_allocations',{})
    if not stack<=sp<=stack+0x200000-8 or ptr and hex(ptr) not in allocs:state['stop']={'kind':'unsafe_fake_free'};uc.emu_stop();return
    if ptr:del allocs[hex(ptr)]
    state.setdefault('fake_crt_calls',[]).append({'import':name,'pointer':hex(ptr),'reuse':False});uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.stub_crt_basics and name.lower()=='vcruntime140.dll!memcmp':
    sp=uc.reg_read(UC_X86_REG_RSP);left=uc.reg_read(UC_X86_REG_RCX);right=uc.reg_read(UC_X86_REG_RDX);n=uc.reg_read(UC_X86_REG_R8)
    if not stack<=sp<=stack+0x200000-8 or n>65536 or any(not (0x172c84000<=v<=0x1792a6be1-n or stack<=v<=stack+0x200000-n or 0x790000000000<=v<=0x790000000000+state.get('fake_heap_used',0)-n) for v in (left,right)):state['stop']={'kind':'unsafe_fake_memcmp'};uc.emu_stop();return
    vals=[]
    for v in (left,right):
     for page in range(v&~0xfff,(v+n+4095)&~0xfff,4096):
      if not (stack<=page<stack+0x200000 or 0x790000000000<=page<0x790000000000+0x1000000) and page not in pages:invalid(uc,0,page,1,0,None)
     vals.append(bytes(uc.mem_read(v,n)))
    result=next((x-y for x,y in zip(*vals) if x!=y),0);state.setdefault('fake_crt_calls',[]).append({'import':name,'size':n,'result':result});uc.reg_write(UC_X86_REG_RAX,result&0xffffffff);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_veh and name.lower()=='kernel32.dll!virtualalloc':
    sp=uc.reg_read(UC_X86_REG_RSP);requested=uc.reg_read(UC_X86_REG_RCX);size=uc.reg_read(UC_X86_REG_RDX);kind=uc.reg_read(UC_X86_REG_R8);prot=uc.reg_read(UC_X86_REG_R9)
    if not stack<=sp<=stack+0x200000-8 or not 1<=size<=0x100000000:state['stop']={'kind':'unsafe_fake_virtualalloc'};uc.emu_stop();return
    if requested==0 and kind==0x2000 and prot==1:
     reserves=state.setdefault('fake_virtual_reservations',[])
     if len(reserves)>=16:state['stop']={'kind':'fake_virtual_reservation_limit'};uc.emu_stop();return
     result=0x7a0000000000+len(reserves)*0x100000000;reserves.append({'address':hex(result),'size':size})
    elif kind==0x1000 and prot==4 and state.get('fake_virtual_reservations'):
     start=requested&~0xfff;end=(requested+size+4095)&~4095
     if not any(int(res['address'],16)<=start<end<=int(res['address'],16)+res['size'] for res in state['fake_virtual_reservations']):state['stop']={'kind':'unsafe_fake_virtual_commit'};uc.emu_stop();return
     state.setdefault('fake_virtual_commits',[]).append((start,end));result=requested
    else:state['stop']={'kind':'unsupported_fake_virtualalloc','address':hex(requested),'size':size,'allocation_type':hex(kind),'protection':hex(prot)};uc.emu_stop();return
    uc.reg_write(UC_X86_REG_RAX,result);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_veh and name.lower() in ('kernel32.dll!queryperformancecounter','kernel32.dll!queryperformancefrequency'):
    sp=uc.reg_read(UC_X86_REG_RSP);ptr=uc.reg_read(UC_X86_REG_RCX)
    if not stack<=sp<=stack+0x200000-8 or not stack<=ptr<=stack+0x200000-8:state['stop']={'kind':'unsafe_fake_perf_counter'};uc.emu_stop();return
    value=10000000 if name.lower().endswith('frequency') else 12345678;uc.mem_write(ptr,struct.pack('<Q',value));state.setdefault('fake_perf_calls',[]).append({'name':name,'value':value});uc.reg_write(UC_X86_REG_RAX,1);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_veh and name.lower() in ('kernel32.dll!setlasterror','kernel32.dll!getlasterror'):
    sp=uc.reg_read(UC_X86_REG_RSP)
    if not stack<=sp<=stack+0x200000-8:state['stop']={'kind':'unsafe_fake_last_error'};uc.emu_stop();return
    if name.lower().endswith('setlasterror'):uc.mem_write(teb+0x68,struct.pack('<I',uc.reg_read(UC_X86_REG_RCX)&0xffffffff))
    else:uc.reg_write(UC_X86_REG_RAX,struct.unpack('<I',bytes(uc.mem_read(teb+0x68,4)))[0])
    state.setdefault('fake_last_error_calls',[]).append(name);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_veh and name.lower() in ('api-ms-win-crt-runtime-l1-1-0.dll!__p___argv','api-ms-win-crt-runtime-l1-1-0.dll!__p___argc'):
    sp=uc.reg_read(UC_X86_REG_RSP)
    if not stack<=sp<=stack+0x200000-8:state['stop']={'kind':'unsafe_fake_argv_stack'};uc.emu_stop();return
    if not state.get('fake_argv_initialized'):
     uc.mem_write(exception_mem+0x6000,struct.pack('<Q',exception_mem+0x6100));uc.mem_write(exception_mem+0x6008,struct.pack('<I',1));uc.mem_write(exception_mem+0x6100,struct.pack('<QQ',exception_mem+0x6200,0));uc.mem_write(exception_mem+0x6200,b'Marathon.exe\0');state['fake_argv_initialized']=True
    result=exception_mem+0x6000 if name.lower().endswith('__p___argv') else exception_mem+0x6008;state.setdefault('fake_argv_calls',[]).append(name);uc.reg_write(UC_X86_REG_RAX,result);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_veh and name.lower()=='kernel32.dll!loadlibraryexa':
    sp=uc.reg_read(UC_X86_REG_RSP);ptr=uc.reg_read(UC_X86_REG_RCX)
    if not stack<=sp<=stack+0x200000-8 or not 0x172c84000<=ptr<0x173534000-128:state['stop']={'kind':'unsafe_fake_loadlibrary'};uc.emu_stop();return
    if ptr&~0xfff not in pages:invalid(uc,0,ptr,128,0,None)
    raw=bytes(uc.mem_read(ptr,128));end=raw.find(b'\0');value=raw[:end] if end>=0 else b''
    if value.lower() not in (b'user32.dll',b'shlwapi.dll',b'gdi32.dll',b'shell32.dll',b'ole32.dll',b'winmm.dll'):state['stop']={'kind':'unsupported_fake_library','name':value.decode('ascii','backslashreplace')};uc.emu_stop();return
    libs=state.setdefault('fake_library_handles',{});key=value.decode().lower();handle=libs.setdefault(key,0x7b0000000000+len(libs)*0x1000);uc.reg_write(UC_X86_REG_RAX,handle);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_system_heap_info and name.lower()=='kernel32.dll!getprocaddress' and any(uc.reg_read(UC_X86_REG_RCX)==int(m['base'],16) for m in fake_system_modules):
    sp=uc.reg_read(UC_X86_REG_RSP);handle=uc.reg_read(UC_X86_REG_RCX);ptr=uc.reg_read(UC_X86_REG_RDX);mod=next(m for m in fake_system_modules if int(m['base'],16)==handle)
    if not stack<=sp<=stack+0x200000-8 or not handle<=ptr<=handle+mod['size']-128:state['stop']={'kind':'unsafe_fake_system_getproc'};uc.emu_stop();return
    raw=bytes(uc.mem_read(ptr,128));end=raw.find(b'\0');symbol=raw[:end].decode('ascii','backslashreplace') if end>=0 else '<unterminated>'
    if mod['name']!='kernel32.dll' or symbol!='HeapAlloc':state['stop']={'kind':'dynamic_import_required','library':mod['name'],'symbol':symbol};uc.emu_stop();return
    result=int(mod['fake_heap_alloc_marker'],16);state.setdefault('fake_system_proc_lookups',[]).append({'library':mod['name'],'symbol':symbol,'result':hex(result)});uc.reg_write(UC_X86_REG_RAX,result);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_veh and name.lower()=='kernel32.dll!getprocaddress':
    sp=uc.reg_read(UC_X86_REG_RSP);handle=uc.reg_read(UC_X86_REG_RCX);ptr=uc.reg_read(UC_X86_REG_RDX);libs=state.get('fake_library_handles',{})
    if not stack<=sp<=stack+0x200000-8 or handle not in libs.values() or not 0x172c84000<=ptr<0x173534000-128:state['stop']={'kind':'unsupported_fake_getproc','handle':hex(handle),'name_pointer':hex(ptr)};uc.emu_stop();return
    if ptr&~0xfff not in pages:invalid(uc,0,ptr,128,0,None)
    raw=bytes(uc.mem_read(ptr,128));end=raw.find(b'\0')
    if end<0:state['stop']={'kind':'unterminated_fake_getproc'};uc.emu_stop();return
    library=next(k for k,v in libs.items() if v==handle);symbol=raw[:end].decode('ascii','backslashreplace')
    if (library,symbol) not in (('user32.dll','RegisterWindowMessageW'),('shlwapi.dll','PathRemoveFileSpecW'),('shell32.dll','SHFileOperationW'),('shell32.dll','SHGetKnownFolderPath'),('ole32.dll','CoTaskMemFree'),('winmm.dll','timeGetTime')):state['stop']={'kind':'dynamic_import_required','library':library,'symbol':symbol};uc.emu_stop();return
    dyn=0x7c0000000000+({('user32.dll','RegisterWindowMessageW'):0,('shlwapi.dll','PathRemoveFileSpecW'):0x10,('shell32.dll','SHFileOperationW'):0x20,('shell32.dll','SHGetKnownFolderPath'):0x30,('ole32.dll','CoTaskMemFree'):0x40,('winmm.dll','timeGetTime'):0x50}[(library,symbol)])
    if not state.get('fake_dynamic_mapped'):uc.mem_map(0x7c0000000000,0x1000);state['fake_dynamic_mapped']=True
    state.setdefault('fake_dynamic_imports',[]).append({'library':library,'symbol':symbol});uc.reg_write(UC_X86_REG_RAX,dyn);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_veh and name.lower() in ('kernel32.dll!createmutexw','kernel32.dll!createmutexa'):
    sp=uc.reg_read(UC_X86_REG_RSP);security=uc.reg_read(UC_X86_REG_RCX);initial=uc.reg_read(UC_X86_REG_RDX);ptr=uc.reg_read(UC_X86_REG_R8)
    if not stack<=sp<=stack+0x200000-8 or security!=0 or initial not in (0,1) or not 0x172c84000<=ptr<0x173534000-128:state['stop']={'kind':'unsafe_fake_mutex_create'};uc.emu_stop();return
    handles=state.setdefault('fake_mutex_handles',[]);handle=0x7d0000000001+len(handles);handles.append({'name_pointer':hex(ptr),'initial_owner':initial,'handle':hex(handle)});uc.mem_write(teb+0x68,struct.pack('<I',0));uc.reg_write(UC_X86_REG_RAX,handle);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_veh and name.lower() in ('vcruntime140.dll!_set_purecall_handler','api-ms-win-crt-runtime-l1-1-0.dll!_set_invalid_parameter_handler'):
    sp=uc.reg_read(UC_X86_REG_RSP);ptr=uc.reg_read(UC_X86_REG_RCX)
    if not stack<=sp<=stack+0x200000-8 or not 0x140001000<=ptr<0x172c84000:state['stop']={'kind':'unsafe_fake_purecall_handler'};uc.emu_stop();return
    key='fake_purecall_handler' if name.lower().endswith('_set_purecall_handler') else 'fake_invalid_parameter_handler';previous=state.get(key,0);state[key]=ptr;uc.reg_write(UC_X86_REG_RAX,previous);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_veh and name.lower()=='kernel32.dll!getmodulefilenamew':
    sp=uc.reg_read(UC_X86_REG_RSP);module=uc.reg_read(UC_X86_REG_RCX);dst=uc.reg_read(UC_X86_REG_RDX);n=uc.reg_read(UC_X86_REG_R8);value='C:\\Preservation\\Marathon.exe';raw=(value+'\0').encode('utf-16le')
    if not stack<=sp<=stack+0x200000-8 or module!=0 or n<len(value)+1 or not stack<=dst<=stack+0x200000-len(raw):state['stop']={'kind':'unsafe_fake_module_path'};uc.emu_stop();return
    uc.mem_write(dst,raw);state['fake_module_path']='synthetic';uc.reg_write(UC_X86_REG_RAX,len(value));uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_veh and name.lower()=='api-ms-win-crt-string-l1-1-0.dll!_wcsnicmp':
    sp=uc.reg_read(UC_X86_REG_RSP);left=uc.reg_read(UC_X86_REG_RCX);right=uc.reg_read(UC_X86_REG_RDX);n=uc.reg_read(UC_X86_REG_R8)
    if not stack<=sp<=stack+0x200000-8 or n>1024 or any(not (0x172c84000<=v<=0x1792a6be1-2*n or stack<=v<=stack+0x200000-2*n) for v in (left,right)):state['stop']={'kind':'unsafe_fake_wcsnicmp'};uc.emu_stop();return
    vals=[]
    for v in (left,right):
     for page in range(v&~0xfff,(v+2*n+4095)&~0xfff,4096):
      if not stack<=page<stack+0x200000 and page not in pages:invalid(uc,0,page,1,0,None)
     vals.append(struct.unpack('<'+'H'*n,bytes(uc.mem_read(v,2*n))))
    result=0
    for x,y in zip(*vals):
     if x>127 or y>127:state['stop']={'kind':'unsupported_fake_wcsnicmp_unicode'};uc.emu_stop();return
     x=ord(chr(x).lower());y=ord(chr(y).lower())
     if x!=y:result=x-y;break
     if not x:break
    state.setdefault('fake_wcsnicmp',[]).append({'length':n,'result':result});uc.reg_write(UC_X86_REG_RAX,result&0xffffffff);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_veh and name.lower()=='kernel32.dll!gettemppathw':
    sp=uc.reg_read(UC_X86_REG_RSP);n=uc.reg_read(UC_X86_REG_RCX);dst=uc.reg_read(UC_X86_REG_RDX);value='C:\\Temp\\';raw=(value+'\0').encode('utf-16le')
    if not stack<=sp<=stack+0x200000-8 or n<len(value)+1 or not stack<=dst<=stack+0x200000-len(raw):state['stop']={'kind':'unsafe_fake_temp_path'};uc.emu_stop();return
    uc.mem_write(dst,raw);state['fake_temp_path']='synthetic';uc.reg_write(UC_X86_REG_RAX,len(value));uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_veh and name.lower()=='kernel32.dll!createdirectoryw':
    sp=uc.reg_read(UC_X86_REG_RSP);ptr=uc.reg_read(UC_X86_REG_RCX);security=uc.reg_read(UC_X86_REG_RDX)
    if not stack<=sp<=stack+0x200000-8 or security or not stack<=ptr<=stack+0x200000-1024:state['stop']={'kind':'unsafe_fake_directory'};uc.emu_stop();return
    raw=bytes(uc.mem_read(ptr,1024));end=next((i for i in range(0,len(raw)-1,2) if raw[i:i+2]==b'\0\0'),-1)
    if end<0:state['stop']={'kind':'unterminated_fake_directory'};uc.emu_stop();return
    key=hashlib.sha256(raw[:end]).hexdigest();dirs=state.setdefault('fake_directory_hashes',[]);exists=key in dirs
    if not exists:dirs.append(key)
    uc.mem_write(teb+0x68,struct.pack('<I',183 if exists else 0));uc.reg_write(UC_X86_REG_RAX,0 if exists else 1);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if (a.stub_crt_basics or a.model_veh) and name.lower()=='kernel32.dll!getsysteminfo':
    sp=uc.reg_read(UC_X86_REG_RSP);ptr=uc.reg_read(UC_X86_REG_RCX)
    if not stack<=sp<=stack+0x200000-8 or not stack<=ptr<=stack+0x200000-48:state['stop']={'kind':'unsafe_fake_system_info'};uc.emu_stop();return
    uc.mem_write(ptr,struct.pack('<HHIQQQIIIHH',9,0,4096,0x10000,0x7fffffffffff,0xff,8,8664,65536,6,0x3a09));state.setdefault('fake_crt_calls',[]).append({'import':name,'synthetic':True});uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_veh and name.lower()=='kernel32.dll!getfileattributesw':
    sp=uc.reg_read(UC_X86_REG_RSP);ptr=uc.reg_read(UC_X86_REG_RCX)
    if not stack<=sp<=stack+0x200000-8 or not stack<=ptr<=stack+0x200000-1024:state['stop']={'kind':'unsafe_fake_file_attributes'};uc.emu_stop();return
    raw=bytes(uc.mem_read(ptr,1024));end=next((i for i in range(0,len(raw)-1,2) if raw[i:i+2]==b'\0\0'),-1)
    if end<0:state['stop']={'kind':'unterminated_fake_file_attributes'};uc.emu_stop();return
    key=hashlib.sha256(raw[:end]).hexdigest();exists=key in state.get('fake_directory_hashes',[]);result=0x10 if exists else 0xffffffff;uc.mem_write(teb+0x68,struct.pack('<I',0 if exists else 2));state.setdefault('fake_file_attribute_queries',[]).append({'path_hash':key,'exists':exists});uc.reg_write(UC_X86_REG_RAX,result);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_veh and name.lower()=='api-ms-win-crt-convert-l1-1-0.dll!wcstombs':
    sp=uc.reg_read(UC_X86_REG_RSP);dst=uc.reg_read(UC_X86_REG_RCX);src=uc.reg_read(UC_X86_REG_RDX);n=uc.reg_read(UC_X86_REG_R8)
    if not stack<=sp<=stack+0x200000-8 or not 1<=n<=1024 or not stack<=dst<=stack+0x200000-n or not stack<=src<=stack+0x200000-2*n:state['stop']={'kind':'unsafe_fake_wcstombs'};uc.emu_stop();return
    raw=bytes(uc.mem_read(src,2*n));units=struct.unpack('<'+'H'*n,raw);out=bytearray();terminated=False
    for value in units:
     if not value:terminated=True;break
     if value>127:state['stop']={'kind':'unsupported_fake_wcstombs_unicode'};uc.emu_stop();return
     out.append(value)
    uc.mem_write(dst,bytes(out)+(b'\0' if terminated else b''));state.setdefault('fake_wcstombs',[]).append({'length':len(out),'terminated':terminated});uc.reg_write(UC_X86_REG_RAX,len(out));uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_veh and name.lower()=='api-ms-win-crt-stdio-l1-1-0.dll!_wfsopen':
    sp=uc.reg_read(UC_X86_REG_RSP);path=uc.reg_read(UC_X86_REG_RCX);mode=uc.reg_read(UC_X86_REG_RDX)
    if not stack<=sp<=stack+0x200000-8 or not stack<=path<stack+0x200000 or not stack<=mode<stack+0x200000:state['stop']={'kind':'unsafe_fake_wfsopen'};uc.emu_stop();return
    state.setdefault('fake_file_open_failures',[]).append({'api':name,'host_filesystem_access':False});uc.reg_write(UC_X86_REG_RAX,0);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_veh and name.lower()=='kernel32.dll!createfilew':
    sp=uc.reg_read(UC_X86_REG_RSP);ptr=uc.reg_read(UC_X86_REG_RCX)
    if not stack<=sp<=stack+0x200000-0x40 or not stack<=ptr<stack+0x200000:state['stop']={'kind':'unsafe_fake_createfile'};uc.emu_stop();return
    state.setdefault('fake_file_open_failures',[]).append({'api':name,'host_filesystem_access':False});uc.mem_write(teb+0x68,struct.pack('<I',2));uc.reg_write(UC_X86_REG_RAX,0xffffffffffffffff);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_veh and name.lower()=='kernel32.dll!setdlldirectoryw':
    sp=uc.reg_read(UC_X86_REG_RSP);ptr=uc.reg_read(UC_X86_REG_RCX)
    if not stack<=sp<=stack+0x200000-8 or not stack<=ptr<=stack+0x200000-1024:state['stop']={'kind':'unsafe_fake_dll_directory'};uc.emu_stop();return
    raw=bytes(uc.mem_read(ptr,1024));end=next((i for i in range(0,len(raw)-1,2) if raw[i:i+2]==b'\0\0'),-1)
    if end<0:state['stop']={'kind':'unterminated_fake_dll_directory'};uc.emu_stop();return
    state['fake_dll_directory_hash']=hashlib.sha256(raw[:end]).hexdigest();uc.reg_write(UC_X86_REG_RAX,1);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_veh and name.lower()=='kernel32.dll!sleep':
    sp=uc.reg_read(UC_X86_REG_RSP);duration=uc.reg_read(UC_X86_REG_RCX);calls=state.setdefault('fake_sleeps',[])
    if not stack<=sp<=stack+0x200000-8 or duration>10000 or len(calls)>=100:state['stop']={'kind':'unsafe_fake_sleep'};uc.emu_stop();return
    calls.append(duration);state['fake_timegettime']=state.get('fake_timegettime',100000)+duration;uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_veh and name.lower()=='kernel32.dll!getdynamictimezoneinformation':
    sp=uc.reg_read(UC_X86_REG_RSP);ptr=uc.reg_read(UC_X86_REG_RCX)
    if not stack<=sp<=stack+0x200000-8 or not stack<=ptr<=stack+0x200000-432:state['stop']={'kind':'unsafe_fake_timezone'};uc.emu_stop();return
    uc.mem_write(ptr,bytes(432));state['fake_timezone']='UTC, no daylight saving';uc.reg_write(UC_X86_REG_RAX,0);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.model_veh and name.lower()=='kernel32.dll!getmodulehandlea':
    sp=uc.reg_read(UC_X86_REG_RSP);ptr=uc.reg_read(UC_X86_REG_RCX)
    if not stack<=sp<=stack+0x200000-8 or not stack<=ptr<=stack+0x200000-128:state['stop']={'kind':'unsafe_fake_getmodulehandle'};uc.emu_stop();return
    raw=bytes(uc.mem_read(ptr,128));end=raw.find(b'\0')
    if end<0:state['stop']={'kind':'unterminated_fake_getmodulehandle'};uc.emu_stop();return
    module=raw[:end].decode('ascii','backslashreplace').lower();canonical=module if '.' in module else module+'.dll';matching=[m for m in fake_system_modules if m['name'].lower()==canonical];result=int(matching[0]['base'],16) if matching else state.get('fake_library_handles',{}).get(canonical,0)
    uc.mem_write(teb+0x68,struct.pack('<I',0 if result else 126));state.setdefault('fake_module_lookups',[]).append({'name':module,'result':hex(result)});uc.reg_write(UC_X86_REG_RAX,result);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);return
   if a.stub_srw_lock and name.lower() in ('kernel32.dll!acquiresrwlockexclusive','kernel32.dll!releasesrwlockexclusive','kernel32.dll!acquiresrwlockshared','kernel32.dll!releasesrwlockshared','kernel32.dll!wakeallconditionvariable','kernel32.dll!wakeconditionvariable'):
    sp=uc.reg_read(UC_X86_REG_RSP);calls=state.setdefault('fake_srw_calls',[])
    if len(calls)>=100 or not stack<=sp<=stack+0x200000-8:state['stop']={'kind':'unsafe_srw_stub'};uc.emu_stop();return
    ret=struct.unpack('<Q',uc.mem_read(sp,8))[0];calls.append({'import':name,'lock':hex(uc.reg_read(UC_X86_REG_RCX))});uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,ret);return
   if a.stub_flush and name.lower()=='kernel32.dll!flushinstructioncache':
    sp=uc.reg_read(UC_X86_REG_RSP)
    if not stack<=sp<=stack+0x200000-8:state['stop']={'kind':'unsafe_import_stack','address':hex(sp)};uc.emu_stop();return
    address=uc.reg_read(UC_X86_REG_RDX);length=uc.reg_read(UC_X86_REG_R8);state.setdefault('stubbed_flushes',[]).append({'address':hex(address),'length':length});ret=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RAX,1);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,ret);return
   if a.stub_getcurrentprocess and name.lower()=='kernel32.dll!getcurrentprocess':
    sp=uc.reg_read(UC_X86_REG_RSP)
    if not stack<=sp<=stack+0x200000-8:state['stop']={'kind':'unsafe_import_stack','address':hex(sp)};uc.emu_stop();return
    ret=struct.unpack('<Q',uc.mem_read(sp,8))[0];uc.reg_write(UC_X86_REG_RAX,0xffffffffffffffff);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,ret);state['stubbed_getcurrentprocess']=state.get('stubbed_getcurrentprocess',0)+1;return
   if name.lower()=='kernel32.dll!tlsgetvalue':
    sp=uc.reg_read(UC_X86_REG_RSP);idx=uc.reg_read(UC_X86_REG_RCX)
    ret=struct.unpack('<Q',uc.mem_read(sp,8))[0];val=state.setdefault('fake_tls_slots',{}).get(idx,0)
    uc.reg_write(UC_X86_REG_RAX,val);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,ret)
    state.setdefault('fake_tls_calls',[]).append({'import':name,'index':idx,'result':hex(val)});return
   if name.lower()=='kernel32.dll!tlssetvalue':
    sp=uc.reg_read(UC_X86_REG_RSP);idx=uc.reg_read(UC_X86_REG_RCX);val=uc.reg_read(UC_X86_REG_RDX)
    ret=struct.unpack('<Q',uc.mem_read(sp,8))[0];state.setdefault('fake_tls_slots',{})[idx]=val
    uc.reg_write(UC_X86_REG_RAX,1);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,ret)
    state.setdefault('fake_tls_calls',[]).append({'import':name,'index':idx,'value':hex(val)});return
   state['import_stack_hex']=bytes(uc.mem_read(uc.reg_read(UC_X86_REG_RSP),512)).hex();state['stop']={'kind':'synthetic_import_marker','address':hex(addr),'import':name};uc.emu_stop();return
  try:op=bytes(uc.mem_read(addr,min(size,4)))
  except UcError:return
  if op.startswith((b'\x0f\x05',b'\x0f\x34',b'\xcd',b'\xcc')):state['stop']={'kind':'host_or_breakpoint','address':hex(addr),'bytes':op.hex()};uc.emu_stop()
 def intr(uc,num,user):state['stop']={'kind':'interrupt','number':num,'address':hex(uc.reg_read(UC_X86_REG_RIP))};uc.emu_stop()
 def write(uc,access,addr,size,value,user):
  if a.model_object and 0x760000000000<=addr<0x760000010000:
   samples=state.setdefault('modeled_object_writes',[])
   if len(samples)<256:samples.append({'address':hex(addr),'size':size,'rip':hex(uc.reg_read(UC_X86_REG_RIP))})
  if a.vault_listener_native_table_control and addr==uc.reg_read(UC_X86_REG_RBX)+8 and uc.reg_read(UC_X86_REG_RIP)==0x16fdc8969:
   state.setdefault('listener_handler_bindings',[]).append({'destination':hex(addr),'handler':hex(value)})
  if a.bitset_layout_value is not None and addr<fixture_counter+4 and fixture_counter<addr+size:
   events=state['synthetic_layout_counter']['writes']
   if len(events)<32:events.append({'address':hex(addr),'size':size,'value':value,'rip':hex(uc.reg_read(UC_X86_REG_RIP))})

  if a.watch_stack_address is not None and addr<=a.watch_stack_address+7 and a.watch_stack_address<addr+size:
   state.setdefault('watched_stack_writes',[]).append({'address':hex(addr),'size':size,'value':hex(value&((1<<(size*8))-1)),'rip':hex(uc.reg_read(UC_X86_REG_RIP)),'recent':list(recent)[-30:]})
  state['writes']+=1
  if base<=addr<base+pe.OPTIONAL_HEADER.SizeOfImage:
   state['image_writes']=state.get('image_writes',0)+1
   if a.trace_image_writes:
    samples=state.setdefault('image_write_samples',[])
    if len(samples)<a.max_image_write_samples:samples.append({'address':hex(addr),'size':size,'value':hex(value),'rip':hex(uc.reg_read(UC_X86_REG_RIP)),'regs':{name:hex(uc.reg_read(reg)) for name,reg in (('rax',UC_X86_REG_RAX),('rcx',UC_X86_REG_RCX),('rdx',UC_X86_REG_RDX),('r8',UC_X86_REG_R8))}})
  if not stack<=addr<stack+0x200000:state.setdefault('nonstack_write',{'address':hex(addr),'rip':hex(uc.reg_read(UC_X86_REG_RIP))})
 def read(uc,access,addr,size,value,user):
  if a.model_object and 0x760000000000<=addr<0x760000010000:
   samples=state.setdefault('modeled_object_reads',[])
   if len(samples)<256:samples.append({'address':hex(addr),'size':size,'rip':hex(uc.reg_read(UC_X86_REG_RIP))})
  if a.trace_peb_reads and teb+0x1000<=addr<teb+0x2000:
   samples=state.setdefault('peb_read_samples',[])
   if len(state.get('modeled_faults',[]))>=2500 and len(samples)<10000:samples.append({'address':hex(addr),'size':size,'value':bytes(uc.mem_read(addr,size)).hex(),'rip':hex(uc.reg_read(UC_X86_REG_RIP))})
  if a.trace_image_reads and base<=addr<base+pe.OPTIONAL_HEADER.SizeOfImage:
   samples=state.setdefault('image_read_samples',[])
   if len(samples)<1000:samples.append({'address':hex(addr),'size':size,'rip':hex(uc.reg_read(UC_X86_REG_RIP))})
 def deliver_fault(fault):
  entries=state.setdefault('modeled_faults',[])
  if len(entries)>=8192:state['stop']={'kind':'exception_limit'};return False
  signature=uc.reg_read(UC_X86_REG_RBX)^uc.reg_read(UC_X86_REG_RBP)^0xd5e1740f6aceb1bb
  if signature&0xffffffff!=0x4b8155a3:state['stop']={'kind':'unhandled_synthetic_fault','address':hex(fault['address']),'rip':hex(fault['rip'])};return False
  regs=[(0x78,UC_X86_REG_RAX),(0x80,UC_X86_REG_RCX),(0x88,UC_X86_REG_RDX),(0x90,UC_X86_REG_RBX),(0x98,UC_X86_REG_RSP),(0xa0,UC_X86_REG_RBP),(0xa8,UC_X86_REG_RSI),(0xb0,UC_X86_REG_RDI),(0xb8,UC_X86_REG_R8),(0xc0,UC_X86_REG_R9),(0xc8,UC_X86_REG_R10),(0xd0,UC_X86_REG_R11),(0xd8,UC_X86_REG_R12),(0xe0,UC_X86_REG_R13),(0xe8,UC_X86_REG_R14),(0xf0,UC_X86_REG_R15),(0xf8,UC_X86_REG_RIP)]
  original=uc.context_save();ctx=bytearray(0x500);struct.pack_into('<I',ctx,0x30,0x10001f);struct.pack_into('<I',ctx,0x44,uc.reg_read(UC_X86_REG_EFLAGS))
  for off,reg in regs:struct.pack_into('<Q',ctx,off,uc.reg_read(reg))
  rec=bytearray(0x100);struct.pack_into('<I',rec,0,0xc0000005);struct.pack_into('<Q',rec,0x10,fault['rip']);struct.pack_into('<I',rec,0x18,2);struct.pack_into('<Q',rec,0x20,{19:0,20:1,21:8}.get(fault['access'],0));struct.pack_into('<Q',rec,0x28,fault['address'])
  uc.mem_write(exception_mem,struct.pack('<QQ',exception_mem+0x100,exception_mem+0x1000));uc.mem_write(exception_mem+0x100,bytes(rec));uc.mem_write(exception_mem+0x1000,bytes(ctx));sp=stack+0xfffd8;uc.mem_write(sp,struct.pack('<Q',handler_ret));uc.reg_write(UC_X86_REG_RSP,sp);uc.reg_write(UC_X86_REG_RCX,exception_mem);state['handling_exception']=True;state['stop']=None
  try:uc.emu_start(0x16fa491a0,0,count=1000000,timeout=a.timeout_ms*1000)
  except UcError as ex:
   if state['stop'] is None:state['stop']={'kind':'handler_error','error':str(ex)}
  state['handling_exception']=False;result=uc.reg_read(UC_X86_REG_RAX)&0xffffffff;stop=state['stop'];modified=bytes(uc.mem_read(exception_mem+0x1000,len(ctx)));resume=struct.unpack_from('<Q',modified,0xf8)[0];entries.append({'fault':hex(fault['address']),'rip':hex(fault['rip']),'signature':hex(signature),'handler_stop':stop,'handler_result':hex(result),'resume':hex(resume)})
  if not stop or stop.get('kind')!='synthetic_handler_return' or result!=0xffffffff:return False
  uc.context_restore(original)
  for off,reg in regs:uc.reg_write(reg,struct.unpack_from('<Q',modified,off)[0])
  uc.reg_write(UC_X86_REG_EFLAGS,struct.unpack_from('<I',modified,0x44)[0]);state['stop']=None;return True
 def invalid_instruction(uc,user):
  if not ((a.stub_crt_basics or a.model_veh)):return False
  def memory(ptr,n,writing):
   valid=(base<=ptr and ptr+n<=base+pe.OPTIONAL_HEADER.SizeOfImage or stack<=ptr and ptr+n<=stack+0x200000 or a.model_tls and tls_block<=ptr and ptr+n<=tls_block+tls_size or a.model_veh and exception_mem<=ptr and ptr+n<=exception_mem+0x10000 or 0x790000000000<=ptr and ptr+n<=0x790000000000+state.get('fake_heap_used',0) or any(start<=ptr and ptr+n<=end for start,end in state.get('fake_virtual_commits',[])) or (a.row7_mode1_fixture and row7_scratch<=ptr and ptr+n<=row7_scratch+4096) or (a.vault_ecs_fixture and 0x7FF00000<=ptr and ptr+n<=0x7FF00000+0xE0000))
   if not valid:return False
   for page in range(ptr&~0xfff,(ptr+n+4095)&~0xfff,4096):
    if base<=page<base+pe.OPTIONAL_HEADER.SizeOfImage or any(start<=page<end for start,end in state.get('fake_virtual_commits',[])):
     if page not in pages and not invalid(uc,0,page,1,0,None):return False
   return True
  try:event=try_avx(uc,uc.reg_read(UC_X86_REG_RIP),15,memory)
  except (UcError,ValueError):return False
  if not event:return False
  state.setdefault('general_avx_events',[]).append(event);return True
 uc.hook_add(UC_HOOK_MEM_INVALID,invalid);uc.hook_add(UC_HOOK_INSN_INVALID,invalid_instruction);uc.hook_add(UC_HOOK_CODE,code);uc.hook_add(UC_HOOK_INTR,intr);uc.hook_add(UC_HOOK_MEM_WRITE,write)
 if a.trace_image_reads:uc.hook_add(UC_HOOK_MEM_READ,read)
 elif a.trace_peb_reads:uc.hook_add(UC_HOOK_MEM_READ,read,begin=teb+0x1000,end=teb+0x1fff)
 start=time.monotonic()
 def fake_dll_notification():
  modules=[m for m in fake_system_modules if m['name']=='ntdll.dll']
  if not a.model_system_heap_info or not modules or uc.reg_read(UC_X86_REG_RIP)!=int(modules[0]['dll_notification_export'],16):return False
  sp=uc.reg_read(UC_X86_REG_RSP);flags=uc.reg_read(UC_X86_REG_RCX);callback=uc.reg_read(UC_X86_REG_RDX);context=uc.reg_read(UC_X86_REG_R8);cookie=uc.reg_read(UC_X86_REG_R9)
  if flags!=0 or not 0x140001000<=callback<0x172c84000 or not stack<=sp<=stack+0x200000-8 or not stack<=cookie<=stack+0x200000-8:state['stop']={'kind':'unsupported_fake_dll_notification'};return False
  uc.mem_write(cookie,struct.pack('<Q',0x7d3000000000));state.setdefault('fake_dll_notifications',[]).append({'callback':hex(callback),'context':hex(context),'cookie':hex(cookie),'host_api_called':False,'notifications_delivered':False});uc.reg_write(UC_X86_REG_RAX,0);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,struct.unpack('<Q',uc.mem_read(sp,8))[0]);state.pop('pending_fault',None);state['stop']=None;return True
 try:
  if a.resume_stop_checkpoint:
   state,recent_values=restore_checkpoint(uc,a.resume_stop_checkpoint,checkpoint_identity);recent=collections.deque(recent_values,maxlen=100);pages=set(state.pop('checkpoint_pages'));state['stop']=None;pc=uc.reg_read(UC_X86_REG_RIP)
  else:pc=a.start
  while True:
   if fake_dll_notification():pc=uc.reg_read(UC_X86_REG_RIP)
   try:uc.emu_start(pc,0,count=a.count,timeout=a.timeout_ms*1000)
   except UcError:
    fault=state.pop('pending_fault',None)
    if fake_dll_notification():pc=uc.reg_read(UC_X86_REG_RIP);continue
    if fault is None or not deliver_fault(fault):raise
    pc=uc.reg_read(UC_X86_REG_RIP);continue
   if state['stop'] is None and uc.reg_read(UC_X86_REG_RIP)!=a.target and state['instructions']<a.count:
    pc=uc.reg_read(UC_X86_REG_RIP)
    continue
   break
 except UcError as ex:
  if state['stop'] is None:state['stop']={'kind':'unicorn_error','error':str(ex),'rip':hex(uc.reg_read(UC_X86_REG_RIP))}
 if state['stop'] is None:state['stop']={'kind':'budget_or_return','rip':hex(uc.reg_read(UC_X86_REG_RIP))}
 if a.save_stop_checkpoint:
  state['checkpoint_pages']=sorted(pages);state['saved_checkpoint']=save_checkpoint(uc,a.save_stop_checkpoint,state,recent,checkpoint_identity)
 sp=uc.reg_read(UC_X86_REG_RSP);state['stack_at_stop']=[hex(struct.unpack('<Q',bytes(uc.mem_read(sp+i*8,8)))[0]) for i in range(24)];state['registers_at_stop']={name:hex(uc.reg_read(reg)) for name,reg in (('rax',UC_X86_REG_RAX),('rbx',UC_X86_REG_RBX),('rcx',UC_X86_REG_RCX),('rdx',UC_X86_REG_RDX),('rsp',UC_X86_REG_RSP),('rsi',UC_X86_REG_RSI),('rdi',UC_X86_REG_RDI),('rbp',UC_X86_REG_RBP),('r8',UC_X86_REG_R8),('r9',UC_X86_REG_R9),('r10',UC_X86_REG_R10),('r11',UC_X86_REG_R11),('r12',UC_X86_REG_R12),('r13',UC_X86_REG_R13),('r14',UC_X86_REG_R14),('r15',UC_X86_REG_R15),('eflags',UC_X86_REG_EFLAGS))};state['modeled_tls']=a.model_tls;state['modeled_object']=a.model_object;state['seeded_general']=a.seed_general;state['inline_dispatch']=a.inline_dispatch;state['stub_getcurrentprocess']=a.stub_getcurrentprocess;state['stub_flush']=a.stub_flush
 if a.vault_ecs_fixture:state['vault_ecs_fixture']=True
 state['stack_sha256']=hashlib.sha256(bytes(uc.mem_read(stack,0x200000))).hexdigest()
 if a.model_tls:state['tls_sha256']=hashlib.sha256(bytes(uc.mem_read(tls_block,tls_size))).hexdigest()
 state['modeled_tls_template']=a.model_tls_template;state['fake_system_modules']=fake_system_modules
 if a.a23f_field_fixture:
  state['synthetic_a23f_field_fixture']={'fields':['0x11223344','0x55667788'],
                                        'output':bytes(uc.mem_read(0x760000000100,16)).hex()}
 if a.model_object:state['object_sha256']=hashlib.sha256(bytes(uc.mem_read(0x760000000000,0x10000))).hexdigest()
 state.update(start=hex(a.start),target=hex(a.target),rcx=hex(a.rcx),recent=list(recent),mapped_pages=len(pages),elapsed_seconds=round(time.monotonic()-start,3),warning='Synthetic registers/stack and modeled image; no Windows process or host APIs; not proof of runtime reachability.')
 print(json.dumps(state))

