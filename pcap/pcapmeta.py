"""Bounded pcapng structure inspection; no application payload decoding."""
import struct

def inspect(path):
    result={'packets':0,'truncated_packets':0,'partial':False,'interface_received':None,'interface_dropped':None,'os_dropped':None}
    endian=None
    with open(path,'rb') as f:
        while True:
            head=f.read(12)
            if not head:break
            if len(head)!=12:result['partial']=True;break
            if head[:4]==b'\x0a\x0d\x0d\x0a':
                endian='<' if head[8:12]==b'\x4d\x3c\x2b\x1a' else '>' if head[8:12]==b'\x1a\x2b\x3c\x4d' else None
            if endian is None:raise ValueError('Invalid pcapng section')
            kind,size=struct.unpack(endian+'II',head[:8])
            if size<12 or size%4 or size>1048576:raise ValueError('Invalid block size')
            tail=f.read(size-12)
            if len(tail)!=size-12:result['partial']=True;break
            block=head+tail
            if struct.unpack(endian+'I',block[-4:])[0]!=size:raise ValueError('Invalid block trailer')
            if kind==6:
                if size<32:raise ValueError('Invalid packet block')
                cap,original=struct.unpack(endian+'II',block[20:28]);result['packets']+=1
                if cap>size-32:raise ValueError('Invalid packet length')
                result['truncated_packets']+=int(cap<original)
            elif kind==5:
                pos=20
                while pos+4<=size-4:
                    code,length=struct.unpack(endian+'HH',block[pos:pos+4]);pos+=4
                    if code==0:break
                    if pos+length>size-4:raise ValueError('Invalid option')
                    if code in (4,5,7) and length==8:
                        result[{4:'interface_received',5:'interface_dropped',7:'os_dropped'}[code]]=struct.unpack(endian+'Q',block[pos:pos+8])[0]
                    pos+=(length+3)//4*4
    return result
