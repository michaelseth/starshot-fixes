import pathlib,sys,struct,hashlib,json
sys.path.insert(0,str(pathlib.Path('work/analysis-deps').resolve()))
import pefile
from capstone import Cs,CS_ARCH_X86,CS_MODE_32
from capstone.x86_const import X86_OP_IMM

ROOT=pathlib.Path('F:/SteamLibrary/steamapps/common/Starshot')
md=Cs(CS_ARCH_X86,CS_MODE_32);md.detail=True
align=lambda n,a:(n+a-1)//a*a

class Patch:
 def __init__(self,path,expected,catalog):
  self.source=path;self.b=bytearray(path.read_bytes());assert hashlib.sha256(self.b).hexdigest()==expected
  self.p=pefile.PE(data=bytes(self.b));self.base=self.p.OPTIONAL_HEADER.ImageBase
  self.rva=align(max(s.VirtualAddress+max(s.Misc_VirtualSize,s.SizeOfRawData) for s in self.p.sections),self.p.OPTIONAL_HEADER.SectionAlignment)
  self.code=bytearray();self.hooks=[];self.catalog=json.loads(pathlib.Path(catalog).read_text())
 def off(self,va):return self.p.get_offset_from_rva(va-self.base)
 def change32(self,va,old,new):
  off=self.off(va);assert struct.unpack_from('<I',self.b,off)[0]==old,(hex(va),self.b[off:off+4].hex())
  struct.pack_into('<I',self.b,off,new)
 def hook(self,start,changes,minimum=5):
  off=self.off(start);old=[];length=0
  for i in md.disasm(bytes(self.b[off:off+40]),start):
   old.append(i);length+=i.size
   if length>=minimum and set(changes)<=set(x.address for x in old):break
  assert length>=5 and set(changes)<=set(x.address for x in old)
  end=start+length
  # Never cover an entry reached from outside the replaced instruction block.
  for v in self.catalog:
   if v['mnemonic'].startswith('j') or v['mnemonic']=='call':
    try:dest=int(v['op_str'],16)
    except ValueError:continue
    assert not start<dest<end or start<=v['address']<end,(hex(start),'external target',hex(dest),hex(v['address']))
  addr=self.base+self.rva+len(self.code);out=bytearray()
  sizes={}
  for i in old:
   if i.address in changes:sizes[i.address]=len(changes[i.address])
   elif i.bytes[0] in range(0x70,0x80):sizes[i.address]=6
   elif i.bytes[0]==0xeb:sizes[i.address]=5
   else:sizes[i.address]=i.size
  mapping={};at=addr
  for i in old:mapping[i.address]=at;at+=sizes[i.address]
  for i in old:
   pos=addr+len(out)
   if i.address in changes:data=changes[i.address]
   elif i.mnemonic.startswith('j') or i.mnemonic=='call':
    assert i.operands[0].type==X86_OP_IMM
    target=i.operands[0].imm;target=mapping.get(target,target)
    if i.bytes[0] in range(0x70,0x80):prefix=bytes([0x0f,0x80+(i.bytes[0]&15)])
    elif i.bytes[0]==0xeb:prefix=b'\xe9'
    else:prefix=bytes(i.bytes[:-4])
    data=prefix+struct.pack('<i',target-(pos+len(prefix)+4))
   else:
    data=bytes(i.bytes)
    # Current hooks deliberately avoid absolute relocatable operands.
    relocs=[e.rva+self.base for block in getattr(self.p,'DIRECTORY_ENTRY_BASERELOC',[]) for e in block.entries if e.type]
    assert not any(i.address<=v<i.address+i.size for v in relocs)
   out+=data
  out+=b'\xe9'+struct.pack('<i',end-(addr+len(out)+5));self.code+=out
  self.b[off:off+length]=b'\xe9'+struct.pack('<i',addr-(start+5))+b'\x90'*(length-5)
  self.hooks.append({'site':hex(start),'end':hex(end),'helper':hex(addr),'size':len(out),'old':''.join(bytes(i.bytes).hex() for i in old)})
 def widen(self,va,newdisp):
  i=next(md.disasm(bytes(self.b[self.off(va):self.off(va)+16]),va));data=bytearray(i.bytes)
  if i.mnemonic=='add' and data[0]==0x83 and i.imm_size==1:
   data[0]=0x81;data[i.imm_offset:i.imm_offset+1]=struct.pack('<i',newdisp);return bytes(data)
  assert i.disp_size==1 and (data[i.modrm_offset]&0xc0)==0x40,(hex(va),i.mnemonic,i.op_str)
  data[i.modrm_offset]=(data[i.modrm_offset]&0x3f)|0x80
  data[i.disp_offset:i.disp_offset+1]=struct.pack('<i',newdisp)
  return bytes(data)
 def save(self,name):
  p=self.p;header=p.sections[-1].get_file_offset()+40
  assert header+40<=min(s.PointerToRawData for s in p.sections if s.SizeOfRawData)
  assert self.b[header:header+40]==bytes(40)
  raw=align(len(self.b),p.OPTIONAL_HEADER.FileAlignment);size=align(len(self.code),p.OPTIONAL_HEADER.FileAlignment)
  self.b+=bytes(raw-len(self.b))+self.code+bytes(size-len(self.code))
  self.b[header:header+40]=struct.pack('<8sIIIIIIHHI',b'.limits\0',len(self.code),self.rva,size,raw,0,0,0,0,0x60000020)
  struct.pack_into('<H',self.b,p.FILE_HEADER.get_field_absolute_offset('NumberOfSections'),p.FILE_HEADER.NumberOfSections+1)
  struct.pack_into('<I',self.b,p.OPTIONAL_HEADER.get_field_absolute_offset('SizeOfImage'),align(self.rva+len(self.code),p.OPTIONAL_HEADER.SectionAlignment))
  struct.pack_into('<I',self.b,p.OPTIONAL_HEADER.get_field_absolute_offset('SizeOfCode'),p.OPTIONAL_HEADER.SizeOfCode+size)
  q=pefile.PE(data=bytes(self.b));assert q.sections[-1].get_data()[:len(self.code)]==self.code
  assert [x.dll for x in q.DIRECTORY_ENTRY_IMPORT]==[x.dll for x in p.DIRECTORY_ENTRY_IMPORT]
  out=pathlib.Path('work')/name;out.write_bytes(self.b)
  result={'file':str(out),'sha256':hashlib.sha256(self.b).hexdigest(),'hooks':self.hooks}
  print(json.dumps(result,indent=2));return result

game=Patch(ROOT/'SpaceCircus.exe','0fa3d280c70772a4ace8bfec371670892ebdf411b1972815bb2edebccc29e01c','work/unique-instructions.json')
# Keep all existing fields in place. Append a 512-entry list at +17800.
game.change32(0x42dfa2,0x177c4,0x18000)
game.change32(0x42dfba,0x5df1,0x6000)
game.change32(0x42e4c7,150,512)
for start,site in [(0x4285db,0x4285dd),(0x42e4de,0x42e4de),(0x42e50c,0x42e50c),(0x42ea1b,0x42ea1b),(0x42f92d,0x42f92d),(0x430382,0x430382),(0x4304d3,0x4304d3)]:
 game.hook(start,{site:game.widen(site,0x17800)})
# The update loop used list[-1] to read the count; keep the original count field.
game.hook(0x42f938,{0x42f938:game.widen(0x42f938,0x1c-0x17800)})
gmeta=game.save('SpaceCircus-capacity512-test.exe')

renderer=Patch(ROOT/'glide.i3D','09e25925e47e2f71a78c5093d557a8c630833a9648877e6c8dc9443aa007e2de','work/unique-glide-instructions.json')
# Append renderer's own 512-entry queue at +400; leave fog/camera fields untouched.
renderer.change32(0x1000f137,0x328,0xc00)
renderer.change32(0x1000fba4,150,511) # Original jbe: accept indices 0..511 only.
renderer.hook(0x1000fbb5,{0x1000fbb5:renderer.widen(0x1000fbb5,0x400)})
renderer.hook(0x1000ed00,{0x1000ed06:renderer.widen(0x1000ed06,0x400)},minimum=9)
# Expand both dynamically allocated sorting buffers as related queue headroom.
renderer.change32(0x10011ac3,0x400,0x800)
renderer.change32(0x10011ad5,0x200,0x800)
rmeta=renderer.save('glide-capacity512-test.i3D')
pathlib.Path('work/capacity512-patch.json').write_text(json.dumps({'game':gmeta,'renderer':rmeta,'capacity':512,'entity_list_offset':0x17800,'game_allocation_size':0x18000,'renderer_queue_offset':0x400,'renderer_allocation_size':0xc00},indent=2))
