import pathlib,sys,struct,hashlib,collections,json
sys.path.insert(0,str(pathlib.Path('work/analysis-deps').resolve()));import pefile
path=pathlib.Path('work/glide-widescreen-test.i3D');b=bytearray(path.read_bytes());p=pefile.PE(data=bytes(b));entries=[]
for block in p.DIRECTORY_ENTRY_BASERELOC:
 for e in block.entries:
  if e.type and e.rva!=0x11986:entries.append((e.rva,e.type))
entries += [(0x1d622,3),(0x1d628,3)];assert len(entries)==len(set(entries));groups=collections.defaultdict(list)
for r,t in entries:groups[r&~0xfff].append((t<<12)|(r&0xfff))
encoded=bytearray()
for page,values in sorted(groups.items()):
 values.sort()
 if len(values)%2:values.append(0)
 encoded+=struct.pack('<II',page,8+2*len(values))+struct.pack('<'+'H'*len(values),*values)
dir=p.OPTIONAL_HEADER.DATA_DIRECTORY[5];off=p.get_offset_from_rva(dir.VirtualAddress);assert len(encoded)<=dir.Size
b[off:off+len(encoded)]=encoded;struct.pack_into('<I',b,dir.get_file_offset()+4,len(encoded))
q=pefile.PE(data=bytes(b));newentries={(e.rva,e.type) for bl in q.DIRECTORY_ENTRY_BASERELOC for e in bl.entries if e.type};assert newentries==set(entries)
entryoff=q.get_offset_from_rva(0x11984);caveoff=q.get_offset_from_rva(0x1d620);entrybytes=bytes(b[entryoff:entryoff+6]);q.relocate_image(0x11000000)
assert q.__data__[entryoff:entryoff+6]==entrybytes
assert struct.unpack_from('<I',q.__data__,caveoff+2)[0]==0x11024b40
assert struct.unpack_from('<I',q.__data__,caveoff+8)[0]==0x11024b40
path.write_bytes(b);meta=json.loads(pathlib.Path('work/widescreen-patch.json').read_text());meta['sha256']=hashlib.sha256(b).hexdigest();meta['relocations']='Removed original entry operand relocation, added both cave operands; validated alternate image base';pathlib.Path('work/widescreen-patch.json').write_text(json.dumps(meta,indent=2));print(meta)
