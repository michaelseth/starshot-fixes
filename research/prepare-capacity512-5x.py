from pathlib import Path
import sys,struct,hashlib,json
sys.path.insert(0,str(Path('work/analysis-deps').resolve()))
import pefile
from unicorn import Uc,UC_ARCH_X86,UC_MODE_32
from unicorn.x86_const import *

source=Path('F:/SteamLibrary/steamapps/common/Starshot/SpaceCircus.exe')
original=source.read_bytes();b=bytearray(original)
assert hashlib.sha256(b).hexdigest()=='c7dc270920f84427da7ff3c07934f6031ec6173887f8e441a3558655aea5692f'
p=pefile.PE(data=bytes(b));base=p.OPTIONAL_HEADER.ImageBase
section=next(s for s in p.sections if s.Name.startswith(b'.fix'))
old=pefile.PE('work/SpaceCircus-capacity512-3_5x-test.exe')
assert section.get_data()==next(s for s in old.sections if s.Name.startswith(b'.fix')).get_data()
# 4r + r, with no absolute constant addresses or new relocations.
load=bytes.fromhex('d98180090000 d98180090000 d8c0 d8c0 dec1')
bodies={'sub':load+bytes.fromhex('dee9 c3'),'add':load+bytes.fromhex('dec1 c3'),'load':load+b'\xc3'}
code=bytearray();addresses={}
for name,body in bodies.items():addresses[name]=base+section.VirtualAddress+len(code);code+=body
assert len(code)<=section.SizeOfRawData
allowed=set(range(section.PointerToRawData,section.PointerToRawData+section.SizeOfRawData))
b[section.PointerToRawData:section.PointerToRawData+section.SizeOfRawData]=code+bytes(section.SizeOfRawData-len(code))
virtual_size_field=section.get_field_absolute_offset('Misc_VirtualSize')
struct.pack_into('<I',b,virtual_size_field,len(code));allowed.update(range(virtual_size_field,virtual_size_field+4))
for va,name in {0x439d34:'sub',0x439d3a:'load',0x439d53:'sub',0x439d62:'add',0x439d71:'sub',0x439d80:'add'}.items():
 off=p.get_offset_from_rva(va-base);assert b[off:off+6]==old.get_data(va-base,6)
 b[off:off+6]=b'\xe8'+struct.pack('<i',addresses[name]-(va+5))+b'\x90';allowed.update(range(off,off+6))
assert all(n in allowed for n,(a,z) in enumerate(zip(original,b)) if a!=z)
for name,body in bodies.items():
 u=Uc(UC_ARCH_X86,UC_MODE_32);u.mem_map(base,0x100000);u.mem_map(0x20000000,0x2000)
 va=addresses[name];u.mem_write(va,body);u.mem_write(0x20000980,struct.pack('<f',19.));u.mem_write(0x20000100,struct.pack('<f',100.))
 setup=bytes.fromhex('d90500010020') if name!='load' else b''
 testva=base+section.VirtualAddress+0x100
 test=setup+b'\xe8'+struct.pack('<i',va-(testva+len(setup)+5))+bytes.fromhex('d91d04010020');u.mem_write(testva,test)
 u.reg_write(UC_X86_REG_ECX,0x20000000);u.reg_write(UC_X86_REG_EAX,0x12345678);u.reg_write(UC_X86_REG_ESP,0x20001800);u.reg_write(UC_X86_REG_EFLAGS,0x246);u.reg_write(UC_X86_REG_FPCW,0x7f)
 u.emu_start(testva,testva+len(test),count=60)
 actual=struct.unpack('<f',u.mem_read(0x20000104,4))[0];assert actual=={'sub':5.,'add':195.,'load':95.}[name]
 assert u.reg_read(UC_X86_REG_ECX)==0x20000000 and u.reg_read(UC_X86_REG_EAX)==0x12345678
 assert u.reg_read(UC_X86_REG_ESP)==0x20001800 and u.reg_read(UC_X86_REG_EFLAGS)==0x246 and u.reg_read(UC_X86_REG_FPCW)==0x7f
 assert struct.unpack('<f',u.mem_read(0x20000980,4))[0]==19.
 print('PASS helper',name,actual)
out=Path('work/SpaceCircus-capacity512-5x-test.exe');out.write_bytes(b)
meta={'sha256':hashlib.sha256(b).hexdigest(),'multiplier':5.0,'capacity':512,'helpers_bytes':len(code),'changed_scope':'Six activation calls, .fix section and its virtual-size header only'}
Path('work/capacity512-5x-patch.json').write_text(json.dumps(meta,indent=2),encoding='utf-8');print(meta)
v=Path('work/validate-activation-bounds.py').read_text().replace('SpaceCircus-activation-test.exe',out.name).replace('0x400000,0x90000','0x400000,0x100000').replace('2*radius','5*radius').replace('[0.,19.,50.]','[0.,19.,25.,50.]')
exec(compile(v,'integrated-5x-bounds','exec'))
t=Path('work/test-capacity512.py').read_text().replace('SpaceCircus-capacity512-test.exe',out.name)
exec(compile(t,'5x-capacity-tests','exec'))
