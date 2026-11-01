import pathlib,sys,struct,hashlib,math,json
sys.path.insert(0,str(pathlib.Path('work/analysis-deps').resolve()))
import pefile
from capstone import Cs,CS_ARCH_X86,CS_MODE_32
from unicorn import Uc,UC_ARCH_X86,UC_MODE_32
from unicorn.x86_const import *
src=pathlib.Path('work/glide-no-fog-test.i3D');b=bytearray(src.read_bytes());assert hashlib.sha256(b).hexdigest()=='fae97f7c54721780ff2a0b3424f10869f691f30380e413f3cdcec849994045f2'
p=pefile.PE(data=bytes(b));base=0x10000000;entry=0x10011984;resume=entry+6;cave=0x1001d620
entryoff=p.get_offset_from_rva(entry-base);caveoff=p.get_offset_from_rva(cave-base);stolen=bytes.fromhex('d91d404b0210');assert b[entryoff:entryoff+6]==stolen;assert b[caveoff:caveoff+64]==bytes(64)
aspect=16/9;aspectbits=struct.pack('<f',aspect);code=stolen+bytes.fromhex('c705404b0210')+aspectbits
code+=b'\xe9'+struct.pack('<i',resume-(cave+len(code)+5));b[entryoff:entryoff+6]=b'\xe9'+struct.pack('<i',cave-(entry+5))+b'\x90';b[caveoff:caveoff+len(code)]=code
halfva=0x1001e3b8;halfoff=p.get_offset_from_rva(halfva-base);originalhalf=struct.unpack_from('<d',b,halfoff)[0];newhalf=math.atan(math.tan(originalhalf)*((16/9)/(4/3)));struct.pack_into('<d',b,halfoff,newhalf)
section=p.sections[0];size=cave-base-section.VirtualAddress+len(code);struct.pack_into('<I',b,section.get_file_offset()+8,size)
u=Uc(UC_ARCH_X86,UC_MODE_32);u.mem_map(base,0x40000);u.mem_write(entry,bytes(b[entryoff:entryoff+6]));u.mem_write(cave,code)
u.mem_write(0x1001d700,bytes.fromhex('d90510d70110')+b'\xe9'+struct.pack('<i',entry-(0x1001d706+5)));u.mem_write(0x1001d710,struct.pack('<f',4/3))
u.reg_write(UC_X86_REG_EAX,0x12345678);u.reg_write(UC_X86_REG_EFLAGS,0x246);u.reg_write(UC_X86_REG_FPCW,0x7f);u.emu_start(0x1001d700,resume,count=25)
actual=struct.unpack('<f',u.mem_read(0x10024b40,4))[0];assert abs(actual-aspect)<1e-7;assert u.reg_read(UC_X86_REG_EAX)==0x12345678 and u.reg_read(UC_X86_REG_EFLAGS)==0x246 and u.reg_read(UC_X86_REG_FPCW)==0x7f
old_v=math.tan(originalhalf)/(4/3);new_v=math.tan(newhalf)/aspect;assert abs(old_v-new_v)<1e-12
print('Aspect hook:',actual,'FOV degrees old/new:',math.degrees(2*originalhalf),math.degrees(2*newhalf),'vertical tangent unchanged:',old_v,new_v)
for i in Cs(CS_ARCH_X86,CS_MODE_32).disasm(code,cave):print(hex(i.address),i.mnemonic,i.op_str)
pathlib.Path('work/glide-widescreen-test.i3D').write_bytes(b);meta={'sha256':hashlib.sha256(b).hexdigest(),'aspect':aspect,'half_fov_radians':newhalf,'horizontal_fov_degrees':math.degrees(2*newhalf),'distance':'original 120; unsuccessful doubled-distance patch omitted','fog':'disabled comparison retained'};pathlib.Path('work/widescreen-patch.json').write_text(json.dumps(meta,indent=2));print(meta)
conf=pathlib.Path('F:/SteamLibrary/steamapps/common/Starshot/dgVoodoo.conf').read_bytes();assert conf.count(b'ScalingMode                             = stretched_4_3')==1 if b'ScalingMode                             = stretched_4_3' in conf else True
import re
newconf,n=re.subn(rb'(?m)^(ScalingMode\s*=\s*)stretched_4_3\s*$',rb'\1stretched',conf);assert n==1
pathlib.Path('work/dgVoodoo-widescreen-test.conf').write_bytes(newconf);print('Prepared scaling change',n)
