import pathlib,sys,struct,hashlib,json
sys.path.insert(0,str(pathlib.Path('work/analysis-deps').resolve()))
import pefile
from capstone import Cs,CS_ARCH_X86,CS_MODE_32
from unicorn import Uc,UC_ARCH_X86,UC_MODE_32
from unicorn.x86_const import *
src=pathlib.Path('F:/SteamLibrary/steamapps/common/Starshot/glide.i3D');b=bytearray(src.read_bytes());assert hashlib.sha256(b).hexdigest()=='fae97f7c54721780ff2a0b3424f10869f691f30380e413f3cdcec849994045f2'
p=pefile.PE(data=bytes(b));base=p.OPTIONAL_HEADER.ImageBase;entry=0x1000f2df;resume=entry+6;cave=0x1001d620
entryoff=p.get_offset_from_rva(entry-base);caveoff=p.get_offset_from_rva(cave-base)
stolen=bytes.fromhex('899908030000');assert b[entryoff:entryoff+6]==stolen;assert b[caveoff:caveoff+64]==bytes(64)
code=stolen+bytes.fromhex('d98108030000 d8c0 d99908030000')
code+=b'\xe9'+struct.pack('<i',resume-(cave+len(code)+5))
b[entryoff:entryoff+6]=b'\xe9'+struct.pack('<i',cave-(entry+5))+b'\x90';b[caveoff:caveoff+len(code)]=code
section=p.sections[0];size=cave-base-section.VirtualAddress+len(code);assert size<=section.SizeOfRawData
struct.pack_into('<I',b,section.get_file_offset()+8,size)
for value in [0.,50.,120.,1000.]:
 u=Uc(UC_ARCH_X86,UC_MODE_32);u.mem_map(base,0x40000);u.mem_map(0x20000000,0x2000);u.mem_write(entry,bytes(b[entryoff:entryoff+6]));u.mem_write(cave,code)
 bits=struct.unpack('<I',struct.pack('<f',value))[0];u.reg_write(UC_X86_REG_ECX,0x20000000);u.reg_write(UC_X86_REG_EBX,bits);u.reg_write(UC_X86_REG_EAX,0x12345678);u.reg_write(UC_X86_REG_EFLAGS,0x246);u.reg_write(UC_X86_REG_FPCW,0x7f);u.reg_write(UC_X86_REG_ESP,0x20001800)
 u.emu_start(entry,resume,count=30)
 result=struct.unpack('<f',u.mem_read(0x20000308,4))[0];assert result==value*2,(value,result)
 assert u.reg_read(UC_X86_REG_EAX)==0x12345678 and u.reg_read(UC_X86_REG_EBX)==bits and u.reg_read(UC_X86_REG_ECX)==0x20000000
 assert u.reg_read(UC_X86_REG_EFLAGS)==0x246 and u.reg_read(UC_X86_REG_ESP)==0x20001800 and u.reg_read(UC_X86_REG_FPCW)==0x7f
 print('Validated distance',value,'->',result)
for i in Cs(CS_ARCH_X86,CS_MODE_32).disasm(code,cave):print(hex(i.address),i.mnemonic,i.op_str)
out=pathlib.Path('work/glide-double-distance-test.i3D');out.write_bytes(b)
meta={'sha256':hashlib.sha256(b).hexdigest(),'entry':hex(entry),'cave':hex(cave),'code_bytes':len(code),'text_virtual_size':size,'scope':'Double fog setter end distance, shared renderer far plane; keep no-fog comparison'}
pathlib.Path('work/distance-patch.json').write_text(json.dumps(meta,indent=2));print(meta)
