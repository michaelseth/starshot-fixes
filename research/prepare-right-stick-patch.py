import pathlib, sys, struct, hashlib, json
sys.path.insert(0, str(pathlib.Path('work/analysis-deps').resolve()))
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

src=pathlib.Path('F:/SteamLibrary/steamapps/common/Starshot/SpaceCircus.exe')
b=bytearray(src.read_bytes())
assert hashlib.sha256(b).hexdigest()=='f1cc6d35ff97a96024faeb6437fc7ff1a8f96e6405b96b448415d27d8c18a2b2'
p=pefile.PE(data=bytes(b)); base=p.OPTIONAL_HEADER.ImageBase
align=lambda n,a:(n+a-1)//a*a
rva=align(max(s.VirtualAddress+max(s.Misc_VirtualSize,s.SizeOfRawData) for s in p.sections),p.OPTIONAL_HEADER.SectionAlignment)
raw=align(len(b),p.OPTIONAL_HEADER.FileAlignment)
header=p.sections[-1].get_file_offset()+40
assert header+40<=min(s.PointerToRawData for s in p.sections if s.SizeOfRawData)
assert b[header:header+40]==bytes(40)
section=bytearray(128)
def put(data,alignment=4):
    offset=align(len(section),alignment);section.extend(bytes(offset-len(section)));section.extend(data);return rva+offset
name_rva=put(b'StarshotCamera.dll\0')
symbol_rva=put(b'\0\0CameraApply\0',2)
int_rva=put(struct.pack('<II',symbol_rva,0))
iat_rva=put(struct.pack('<II',symbol_rva,0))
old_imports=[]
for d in p.DIRECTORY_ENTRY_IMPORT:
    old_imports.append(d.struct.get_file_offset())
descriptors=b''.join(bytes(b[o:o+20]) for o in old_imports)
descriptors+=struct.pack('<IIIII',int_rva,0,0,name_rva,iat_rva)+bytes(20)
imports_rva=put(descriptors)
site=0x40a427; target=base+rva
original=bytes(b[p.get_offset_from_rva(site-base):p.get_offset_from_rva(site-base)+5])
assert original==b'\xe8'+struct.pack('<i',0x409ef0-(site+5))
code=bytearray(b'\xe8'+struct.pack('<i',0x409ef0-(target+5)))
code+=bytes.fromhex('9c 60 83ec6c dd3424 57 ff15')
iat_operand=target+len(code)
code+=struct.pack('<I',base+iat_rva)
code+=bytes.fromhex('83c404 dd2424 83c46c 61 9d c3')
assert len(code)<=128;section[:len(code)]=code
off=p.get_offset_from_rva(site-base);b[off:off+5]=b'\xe8'+struct.pack('<i',target-(site+5))
# Preserve every original base relocation, and add the shim's IAT operand.
relocs={}
for block in getattr(p,'DIRECTORY_ENTRY_BASERELOC',[]):
    for e in block.entries:
        if e.type:relocs.setdefault(e.rva&~0xfff,[]).append((e.type<<12)|(e.rva&0xfff))
new_rva=iat_operand-base
relocs.setdefault(new_rva&~0xfff,[]).append((3<<12)|(new_rva&0xfff))
reloc_data=bytearray()
for page,entries in sorted(relocs.items()):
    entries=sorted(set(entries))
    if len(entries)%2:entries.append(0)
    reloc_data+=struct.pack('<II',page,8+len(entries)*2)+struct.pack('<'+'H'*len(entries),*entries)
relocs_rva=put(reloc_data)
size=align(len(section),p.OPTIONAL_HEADER.FileAlignment)
b+=bytes(raw-len(b))+section+bytes(size-len(section))
b[header:header+40]=struct.pack('<8sIIIIIIHHI',b'.camera\0',len(section),rva,size,raw,0,0,0,0,0xe0000060)
struct.pack_into('<H',b,p.FILE_HEADER.get_field_absolute_offset('NumberOfSections'),p.FILE_HEADER.NumberOfSections+1)
struct.pack_into('<I',b,p.OPTIONAL_HEADER.get_field_absolute_offset('SizeOfImage'),align(rva+len(section),p.OPTIONAL_HEADER.SectionAlignment))
struct.pack_into('<I',b,p.OPTIONAL_HEADER.get_field_absolute_offset('SizeOfCode'),p.OPTIONAL_HEADER.SizeOfCode+size)
for index,addr,length in [(1,imports_rva,len(descriptors)),(5,relocs_rva,len(reloc_data)),(11,0,0)]:
    d=p.OPTIONAL_HEADER.DATA_DIRECTORY[index];struct.pack_into('<II',b,d.get_file_offset(),addr,length)
q=pefile.PE(data=bytes(b))
assert [e.dll for e in q.DIRECTORY_ENTRY_IMPORT]==[e.dll for e in p.DIRECTORY_ENTRY_IMPORT]+[b'StarshotCamera.dll']
assert q.DIRECTORY_ENTRY_IMPORT[-1].imports[0].name==b'CameraApply'
assert q.DIRECTORY_ENTRY_IMPORT[-1].imports[0].address==base+iat_rva
q.relocate_image(base+0x100000)
assert struct.unpack('<I',q.get_data(iat_operand-base,4))[0]==base+0x100000+iat_rva
out=pathlib.Path('work/SpaceCircus-right-stick-test.exe');out.write_bytes(b)
meta={'sha256':hashlib.sha256(b).hexdigest(),'hook':hex(site),'shim':hex(target),'iat':hex(base+iat_rva),'iat_operand':hex(iat_operand),'shim_size':len(code)}
pathlib.Path('work/right-stick-patch.json').write_text(json.dumps(meta,indent=2));print(meta)
for i in Cs(CS_ARCH_X86,CS_MODE_32).disasm(code,target):print(hex(i.address),i.mnemonic,i.op_str)
dll=pefile.PE('work/StarshotCamera.dll')
print('DLL imports:',[e.dll.decode() for e in dll.DIRECTORY_ENTRY_IMPORT])
print('DLL exports:',[e.name.decode() for e in dll.DIRECTORY_ENTRY_EXPORT.symbols])
