#!/usr/bin/python3
"""Passive TCP evidence capture. Never replies, parses a protocol, or executes bytes."""
import asyncio,base64,datetime,hashlib,json,os,pathlib,socket,sqlite3,time,uuid
STATE=pathlib.Path(os.environ.get('MONERO_SCAN_STATE','./captures'))
PORTS=[int(x) for x in os.environ.get('MONERO_SCAN_PORTS','18080,18081,18089').split(',')]
CAP=4096

def connect_db():
 db=sqlite3.connect(STATE/'queue.sqlite',timeout=10)
 os.chmod(STATE/'queue.sqlite',0o660)
 db.execute('PRAGMA journal_mode=WAL');db.execute('PRAGMA synchronous=FULL')
 db.execute('PRAGMA journal_size_limit=1048576');db.execute('PRAGMA max_page_count=65536')
 db.execute('CREATE TABLE IF NOT EXISTS pending(id TEXT PRIMARY KEY,event TEXT NOT NULL)')
 db.execute('CREATE TABLE IF NOT EXISTS counters(name TEXT PRIMARY KEY,value INTEGER NOT NULL)')
 db.commit();return db

def classify(data):
 if data.startswith(bytes.fromhex('0121010101010101')):return 'levin_signature'
 if data.startswith(b'\x16\x03'):return 'tls_client_hello_candidate'
 if data.startswith((b'GET ',b'POST ',b'HEAD ',b'OPTIONS ',b'CONNECT ',b'PUT ')):return 'http_request'
 return 'no_payload' if not data else 'other'

def bump(db,name):
 db.execute('INSERT INTO counters VALUES(?,1) ON CONFLICT(name) DO UPDATE SET value=value+1',(name,))

def save(db,event):
 with db:
  if db.execute('SELECT count(*) FROM pending').fetchone()[0]>=20000:
   bump(db,'queue_overflow');return
  db.execute('INSERT INTO pending VALUES(?,?)',(event['session'],json.dumps(event,sort_keys=True)))
  bump(db,'captured')

async def main():
 STATE.mkdir(exist_ok=True);db=connect_db();active=0
 async def handle(reader,writer):
  nonlocal active
  peer=writer.get_extra_info('peername');local=writer.get_extra_info('sockname')
  start=time.time();stamp=datetime.datetime.now(datetime.timezone.utc).isoformat()
  data=b'';outcome='closed';busy=active>=128
  active+=1
  try:
   if busy:outcome='concurrency_limit'
   else:
    deadline=asyncio.get_running_loop().time()+5
    while len(data)<CAP:
     try:chunk=await asyncio.wait_for(reader.read(CAP-len(data)),max(.001,deadline-asyncio.get_running_loop().time()))
     except asyncio.TimeoutError:outcome='timeout';break
     if not chunk:break
     data+=chunk
    if len(data)==CAP:outcome='capture_limit'
  except (ConnectionError,OSError):outcome='reset'
  finally:
   active-=1;writer.close()
   event={'eventid':'monero.scan.connection','timestamp':stamp,'session':'monero:'+uuid.uuid4().hex,'src_ip':peer[0],'src_port':peer[1],'dst_ip':local[0],'dst_port':local[1],'transport':'tcp','captured_bytes':len(data),'payload_b64':base64.b64encode(data).decode(),'payload_sha256':hashlib.sha256(data).hexdigest(),'classification':classify(data),'outcome':outcome,'duration_ms':round((time.time()-start)*1000),'capture_limit':CAP,'is_validation':data.startswith(b'MONERO-SCAN-VALIDATION:')}
   try:save(db,event)
   except sqlite3.Error as e:print(json.dumps({'error':'spool_write_failed','kind':type(e).__name__}),flush=True)
 async def heartbeat():
  while True:
   with db:db.execute("INSERT INTO counters VALUES('listener_heartbeat',?) ON CONFLICT(name) DO UPDATE SET value=excluded.value",(int(time.time()),))
   await asyncio.sleep(30)
 heartbeat_task=asyncio.create_task(heartbeat())
 servers=[]
 for port in PORTS:
  # Bind to loopback for local evaluation.
  s=await asyncio.start_server(handle,'127.0.0.1',port,limit=8192,backlog=256)
  servers.append(s)
 print(json.dumps({'ready':True,'ports':PORTS,'capture_bytes':CAP}),flush=True)
 await asyncio.gather(*(s.serve_forever() for s in servers))
if __name__=='__main__':asyncio.run(main())
