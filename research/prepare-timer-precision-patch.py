import pathlib,hashlib,struct,json,sys
sys.path.insert(0,str(pathlib.Path('work/analysis-deps').resolve()))
import pefile
from capstone import Cs,CS_ARCH_X86,CS_MODE_32
src=pathlib.Path('F:/SteamLibrary/steamapps/common/Starshot/SpaceCircus.exe')
b=bytearray(src.read_bytes())
assert hashlib.sha1(b).hexdigest()=='a88a9ba3429faf80d51be7fa801e7435b2dbb039'
p=pefile.PE(data=bytes(b));base=p.OPTIONAL_HEADER.ImageBase
entry=0x41d080;resume=entry+7;cave=0x45e1c0
entryoff=p.get_offset_from_rva(entry-base);caveoff=p.get_offset_from_rva(cave-base)
stolen=bytes.fromhex('83ec1c8d442400')
assert b[entryoff:entryoff+7]==stolen
assert b[caveoff:caveoff+64]==bytes(64)
prefix=bytes.fromhex('83ec04 d93c24 668b0424 660d0003 6689442402 d96c2402')
suffix=bytes.fromhex('d92c24 83c404 c3')
tramp=cave+len(prefix)+5+len(suffix)
code=prefix+b'\xe8'+struct.pack('<i',tramp-(cave+len(prefix)+5))+suffix
code+=stolen+b'\xe9'+struct.pack('<i',resume-(tramp+len(stolen)+5))
assert len(code)<=64
b[caveoff:caveoff+len(code)]=code
b[entryoff:entryoff+7]=b'\xe9'+struct.pack('<i',cave-(entry+5))+b'\x90\x90'
section=p.sections[0];size=cave-base-section.VirtualAddress+len(code)
struct.pack_into('<I',b,section.get_file_offset()+8,size)
out=pathlib.Path('work/SpaceCircus-wintimer-precision-test.exe');out.write_bytes(b)
patched=pefile.PE(data=bytes(b));assert patched.sections[0].Misc_VirtualSize==size
md=Cs(CS_ARCH_X86,CS_MODE_32)
print('Timer hook:')
for i in md.disasm(bytes(b[entryoff:entryoff+7]),entry):print(hex(i.address),i.mnemonic,i.op_str)
print('Wrapper and trampoline:')
for i in md.disasm(code,cave):print(hex(i.address),i.mnemonic,i.op_str)
assert sum(i.size for i in md.disasm(code,cave))==len(code)
meta={'original_sha1':hashlib.sha1(src.read_bytes()).hexdigest(),'candidate_sha256':hashlib.sha256(b).hexdigest(),'timer_entry':hex(entry),'cave':hex(cave),'cave_file_offset':hex(caveoff),'code_bytes':len(code),'original_text_virtual_size':section.Misc_VirtualSize,'new_text_virtual_size':size,'scope':'Windows-timer integer getter only; restore original x87 CW on return'}
pathlib.Path('work/starshot-timer-patch.json').write_text(json.dumps(meta,indent=2))
print(json.dumps(meta,indent=2))
