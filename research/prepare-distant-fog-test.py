import pathlib,sys,struct,hashlib,json
sys.path.insert(0,str(pathlib.Path('work/analysis-deps').resolve()));import pefile
from capstone import Cs,CS_ARCH_X86,CS_MODE_32
from unicorn import Uc,UC_ARCH_X86,UC_MODE_32
from unicorn.x86_const import *
src=pathlib.Path('F:/SteamLibrary/steamapps/common/Starshot/glide.i3D');b=bytearray(src.read_bytes());assert hashlib.sha256(b).hexdigest()=='fa76739890deae2943f3dc9db3978e485d71bd71548cd4dcbab02c2f8f3450cb'
p=pefile.PE(data=bytes(b));base=0x10000000;entry=0x1000f2d9;resume=entry+12;cave=0x1001d640;entryoff=p.get_offset_from_rva(entry-base);caveoff=p.get_offset_from_rva(cave-base)
stolen=bytes.fromhex('898104030000899908030000');assert b[entryoff:entryoff+12]==stolen;assert b[caveoff:caveoff+100]==bytes(100)
# Double fog start and triple fog end; the end also extends the renderer far plane.
code=stolen+bytes.fromhex('d98104030000 d8c0 d99904030000 d98108030000 d98108030000 d8c0 dec1 d99908030000')
code+=b'\xe9'+struct.pack('<i',resume-(cave+len(code)+5));b[entryoff:entryoff+12]=b'\xe9'+struct.pack('<i',cave-(entry+5))+bytes.fromhex('90909090909090');b[caveoff:caveoff+len(code)]=code
modeoff=p.get_offset_from_rva(0x13116);assert b[modeoff:modeoff+2]==b'\x6a\x00';b[modeoff+1]=2
section=p.sections[0];size=cave-base-section.VirtualAddress+len(code);assert size<=section.SizeOfRawData;struct.pack_into('<I',b,section.get_file_offset()+8,size)
for start,end in [(50.,120.),(20.,100.),(0.,0.)]:
 u=Uc(UC_ARCH_X86,UC_MODE_32);u.mem_map(base,0x40000);u.mem_map(0x20000000,0x2000);u.mem_write(entry,bytes(b[entryoff:entryoff+12]));u.mem_write(cave,code)
 a=struct.unpack('<I',struct.pack('<f',start))[0];z=struct.unpack('<I',struct.pack('<f',end))[0];u.reg_write(UC_X86_REG_ECX,0x20000000);u.reg_write(UC_X86_REG_EAX,a);u.reg_write(UC_X86_REG_EBX,z);u.reg_write(UC_X86_REG_EFLAGS,0x246);u.reg_write(UC_X86_REG_FPCW,0x7f);u.reg_write(UC_X86_REG_ESP,0x20001800);u.emu_start(entry,resume,count=30)
 actual=struct.unpack('<2f',u.mem_read(0x20000304,8));assert actual==(2*start,3*end);assert u.reg_read(UC_X86_REG_EAX)==a and u.reg_read(UC_X86_REG_EBX)==z and u.reg_read(UC_X86_REG_ECX)==0x20000000 and u.reg_read(UC_X86_REG_EFLAGS)==0x246 and u.reg_read(UC_X86_REG_ESP)==0x20001800 and u.reg_read(UC_X86_REG_FPCW)==0x7f;print('Validated fog',start,end,'->',actual)
q=pefile.PE(data=bytes(b));assert q.get_data(cave-base,len(code))==code
for i in Cs(CS_ARCH_X86,CS_MODE_32).disasm(code,cave):print(hex(i.address),i.mnemonic,i.op_str)
pathlib.Path('work/glide-distant-fog-test.i3D').write_bytes(b);meta={'sha256':hashlib.sha256(b).hexdigest(),'cave':hex(cave),'code_bytes':len(code),'scope':'Restore table fog; 2x start, 3x end/far plane; retain widescreen'};pathlib.Path('work/distant-fog-patch.json').write_text(json.dumps(meta,indent=2));print(meta)
