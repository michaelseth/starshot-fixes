import pathlib,hashlib,sys
sys.path.insert(0,str(pathlib.Path('work/analysis-deps').resolve()))
import pefile
from capstone import Cs,CS_ARCH_X86,CS_MODE_32
src=pathlib.Path('F:/SteamLibrary/steamapps/common/Starshot/glide.i3D');b=bytearray(src.read_bytes());assert hashlib.sha1(b).hexdigest()=='dd3f9ae550be7f67623716b8c56ef0cbee9b25ca'
p=pefile.PE(data=bytes(b));va=0x10013116;off=p.get_offset_from_rva(va-p.OPTIONAL_HEADER.ImageBase)
assert b[off:off+7]==bytes.fromhex('6a02e85ba40000')
b[off+1]=0
out=pathlib.Path('work/glide-no-fog-test.i3D');out.write_bytes(b)
assert len(b)==len(src.read_bytes());assert [(x,a,z) for x,(a,z) in enumerate(zip(src.read_bytes(),b)) if a!=z]==[(off+1,2,0)]
for i in Cs(CS_ARCH_X86,CS_MODE_32).disasm(bytes(b[off:off+7]),va):print(hex(i.address),i.mnemonic,i.op_str)
print('Candidate SHA256',hashlib.sha256(b).hexdigest(),'changed file offset',hex(off+1))
