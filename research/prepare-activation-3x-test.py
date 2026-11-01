import pathlib,sys,struct,hashlib,json
sys.path.insert(0,str(pathlib.Path('work/analysis-deps').resolve()));import pefile
from capstone import Cs,CS_ARCH_X86,CS_MODE_32
from unicorn import Uc,UC_ARCH_X86,UC_MODE_32
from unicorn.x86_const import *
src=pathlib.Path('F:/SteamLibrary/steamapps/common/Starshot/SpaceCircus.exe.before-activation-test-20261010-165246.bak');b=bytearray(src.read_bytes());assert hashlib.sha256(b).hexdigest()=='81db60a4ca047345777b81bad6d6c5de087ba79193825f0e3800f2b0e1f80c1c'
p=pefile.PE(data=bytes(b));base=p.OPTIONAL_HEADER.ImageBase;align=lambda n,a:(n+a-1)//a*a
rva=align(max(s.VirtualAddress+max(s.Misc_VirtualSize,s.SizeOfRawData) for s in p.sections),p.OPTIONAL_HEADER.SectionAlignment);raw=align(len(b),p.OPTIONAL_HEADER.FileAlignment)
header=p.sections[-1].get_file_offset()+40;assert header+40<=min(s.PointerToRawData for s in p.sections if s.SizeOfRawData);assert b[header:header+40]==bytes(40)
# Three helpers exactly preserve the input arithmetic except for doubling the activation half-size.
load=bytes.fromhex('d98180090000 d98180090000 d8c0 dec1')
helpers={'sub':load+bytes.fromhex('dee9 c3'),'add':load+bytes.fromhex('dec1 c3'),'load':load+b'\xc3'}
code=bytearray();addresses={}
for name,body in helpers.items():
 addresses[name]=base+rva+len(code);code+=body
sites={0x439d34:'sub',0x439d3a:'load',0x439d53:'sub',0x439d62:'add',0x439d71:'sub',0x439d80:'add'}
originals={'sub':bytes.fromhex('d8a180090000'),'add':bytes.fromhex('d88180090000'),'load':bytes.fromhex('d98180090000')}
for va,name in sites.items():
 off=p.get_offset_from_rva(va-base);assert b[off:off+6]==originals[name],(hex(va),b[off:off+6].hex())
 b[off:off+6]=b'\xe8'+struct.pack('<i',addresses[name]-(va+5))+b'\x90'
for name,body in helpers.items():
 u=Uc(UC_ARCH_X86,UC_MODE_32);u.mem_map(base,align(rva+4096,4096));u.mem_map(0x20000000,0x2000)
 va=addresses[name];u.mem_write(va,body);u.mem_write(0x20000980,struct.pack('<f',19.));u.mem_write(0x20000100,struct.pack('<f',100.))
 # Preload an input for binary arithmetic; the load variant adds a fresh value.
 setup=bytes.fromhex('d90500010020') if name!='load' else b''
 testva=base+rva+0x100;test=setup+b'\xe8'+struct.pack('<i',va-(testva+len(setup)+5))+bytes.fromhex('d91d04010020');u.mem_write(testva,test)
 u.reg_write(UC_X86_REG_ECX,0x20000000);u.reg_write(UC_X86_REG_EAX,0x12345678);u.reg_write(UC_X86_REG_ESP,0x20001800);u.reg_write(UC_X86_REG_EFLAGS,0x246);u.reg_write(UC_X86_REG_FPCW,0x7f)
 u.emu_start(testva,testva+len(test),count=30);actual=struct.unpack('<f',u.mem_read(0x20000104,4))[0];expected={'sub':43.,'add':157.,'load':57.}[name];assert actual==expected,(name,actual)
 assert u.reg_read(UC_X86_REG_ECX)==0x20000000 and u.reg_read(UC_X86_REG_EAX)==0x12345678 and u.reg_read(UC_X86_REG_ESP)==0x20001800 and u.reg_read(UC_X86_REG_EFLAGS)==0x246 and u.reg_read(UC_X86_REG_FPCW)==0x7f
 assert struct.unpack('<f',u.mem_read(0x20000980,4))[0]==19.;print('Validated',name,actual)
rawsize=align(len(code),p.OPTIONAL_HEADER.FileAlignment);b+=bytes(raw-len(b))+code+bytes(rawsize-len(code))
section=struct.pack('<8sIIIIIIHHI',b'.fix\0\0\0\0',len(code),rva,rawsize,raw,0,0,0,0,0x60000020);b[header:header+40]=section
struct.pack_into('<H',b,p.FILE_HEADER.get_field_absolute_offset('NumberOfSections'),p.FILE_HEADER.NumberOfSections+1)
struct.pack_into('<I',b,p.OPTIONAL_HEADER.get_field_absolute_offset('SizeOfImage'),align(rva+len(code),p.OPTIONAL_HEADER.SectionAlignment));struct.pack_into('<I',b,p.OPTIONAL_HEADER.get_field_absolute_offset('SizeOfCode'),p.OPTIONAL_HEADER.SizeOfCode+rawsize)
q=pefile.PE(data=bytes(b));assert q.sections[-1].Name.startswith(b'.fix') and q.get_data(rva,len(code))==code
for name,addr in addresses.items():
 print('Helper',name,hex(addr))
 for i in Cs(CS_ARCH_X86,CS_MODE_32).disasm(helpers[name],addr):print(hex(i.address),i.mnemonic,i.op_str)
pathlib.Path('work/SpaceCircus-activation-3x-test.exe').write_bytes(b);meta={'sha256':hashlib.sha256(b).hexdigest(),'sites':{hex(k):v for k,v in sites.items()},'section_rva':hex(rva),'helpers_bytes':len(code),'scope':'Triple box half-size only during activation bounds calculations; preserve script field and FPS fix'};pathlib.Path('work/activation-3x-patch.json').write_text(json.dumps(meta,indent=2));print(meta)

