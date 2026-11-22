import pathlib,tempfile,struct,sys
sys.path.insert(0,str(pathlib.Path(__file__).parent));from pcapmeta import inspect
pack=lambda *n:struct.pack('<'+'I'*len(n),*n)
def block(t,p):return pack(t,len(p)+12)+p+pack(len(p)+12)
shb=block(0x0a0d0d0a,pack(0x1a2b3c4d)+struct.pack('<HHq',1,0,-1))
idb=block(1,struct.pack('<HHI',1,0,262144))
epb=block(6,pack(0,0,123,4,8)+b'abcd')
isb=block(5,pack(0,0,123)+struct.pack('<HHQ',5,8,3)+struct.pack('<HH',0,0))
with tempfile.TemporaryDirectory() as d:
 p=pathlib.Path(d)/'a';p.write_bytes(shb+idb+epb+isb);r=inspect(p);assert r['packets']==1 and r['truncated_packets']==1 and r['interface_dropped']==3 and not r['partial']
 p.write_bytes(shb+idb+epb+isb[:-3]);assert inspect(p)['partial']
 p.write_bytes(shb+idb+epb);assert inspect(p)['interface_dropped'] is None
 p.write_bytes(b'x'*24)
 try:inspect(p);raise AssertionError('invalid accepted')
 except ValueError:pass
print('pcapng checks passed: packets, truncation, drops, partial file, unknown counters, malformed data')
