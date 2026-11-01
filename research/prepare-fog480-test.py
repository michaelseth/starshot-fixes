from pathlib import Path
import sys,struct,hashlib,json
sys.path.insert(0,str(Path('work/analysis-deps').resolve()))
import pefile
from unicorn import Uc,UC_ARCH_X86,UC_MODE_32
from unicorn.x86_const import *

source=Path('F:/SteamLibrary/steamapps/common/Starshot/glide.i3D')
original=source.read_bytes();b=bytearray(original)
assert hashlib.sha256(b).hexdigest()=='5ebecc77fd32d822f4c704b259847421478bedae7010328eb267c86b63de733a'
p=pefile.PE(data=bytes(b));base=p.OPTIONAL_HEADER.ImageBase
entry=base+0xf2d9;resume=entry+12;cave=base+0x1d640
off=p.get_offset_from_rva(cave-base)
old_code=pefile.PE('work/glide-distant-fog-test.i3D').get_data(cave-base,53)
assert b[off:off+53]==old_code and b[off+53:off+55]==bytes(2)
stolen=bytes.fromhex('898104030000899908030000')
# Triple the original fog start; quadruple the end / far plane.
code=stolen+bytes.fromhex('d98104030000 d98104030000 d8c0 dec1 d99904030000 d98108030000 d8c0 d8c0 d99908030000')
code+=b'\xe9'+struct.pack('<i',resume-(cave+len(code)+5));assert len(code)==55
b[off:off+len(code)]=code
s=p.sections[0];size=cave-base-s.VirtualAddress+len(code);assert size<=s.SizeOfRawData
field=s.get_field_absolute_offset('Misc_VirtualSize');struct.pack_into('<I',b,field,size)
allowed=set(range(off,off+len(code)))|set(range(field,field+4))
assert all(n in allowed for n,(x,y) in enumerate(zip(original,b)) if x!=y)
for start,end in [(50.,120.),(20.,100.),(0.,0.),(120.,120.)]:
 u=Uc(UC_ARCH_X86,UC_MODE_32);u.mem_map(base,0x40000);u.mem_map(0x20000000,0x2000)
 u.mem_write(base,p.get_memory_mapped_image());u.mem_write(cave,code)
 a=struct.unpack('<I',struct.pack('<f',start))[0];z=struct.unpack('<I',struct.pack('<f',end))[0]
 u.reg_write(UC_X86_REG_ECX,0x20000000);u.reg_write(UC_X86_REG_EAX,a);u.reg_write(UC_X86_REG_EBX,z)
 u.reg_write(UC_X86_REG_EFLAGS,0x246);u.reg_write(UC_X86_REG_FPCW,0x7f);u.reg_write(UC_X86_REG_ESP,0x20001800)
 u.emu_start(entry,resume,count=40)
 actual=struct.unpack('<2f',u.mem_read(0x20000304,8));assert actual==(3*start,4*end)
 assert u.reg_read(UC_X86_REG_EAX)==a and u.reg_read(UC_X86_REG_EBX)==z and u.reg_read(UC_X86_REG_ECX)==0x20000000
 assert u.reg_read(UC_X86_REG_EFLAGS)==0x246 and u.reg_read(UC_X86_REG_ESP)==0x20001800 and u.reg_read(UC_X86_REG_FPCW)==0x7f
 print('PASS fog/far plane',start,end,'->',actual)
q=pefile.PE(data=bytes(b));assert q.get_data(cave-base,len(code))==code
assert [e.dll for e in q.DIRECTORY_ENTRY_IMPORT]==[e.dll for e in p.DIRECTORY_ENTRY_IMPORT]
out=Path('work/glide-capacity512-fog480-test.i3D');out.write_bytes(b)
meta={'sha256':hashlib.sha256(b).hexdigest(),'typical_fog':[150,480],'previous_fog':[100,360],'capacity':512,'scope':'Fog helper and text virtual-size header only; 5x activation untouched'}
Path('work/fog480-patch.json').write_text(json.dumps(meta,indent=2),encoding='utf-8');print(meta)
t=Path('work/test-capacity512.py').read_text().replace('SpaceCircus-capacity512-test.exe','SpaceCircus-capacity512-5x-test.exe').replace('glide-capacity512-test.i3D',out.name)
exec(compile(t,'fog480-capacity-regression','exec'))
