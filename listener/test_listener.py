import base64,json,os,pathlib,socket,sqlite3,subprocess,tempfile,time,unittest
from contextlib import closing
ROOT=pathlib.Path(__file__).parent
class ListenerTests(unittest.TestCase):
 def test_capture_replay_and_bounds(self):
  with tempfile.TemporaryDirectory() as t:
   s=socket.socket();s.bind(('127.0.0.1',0));port=s.getsockname()[1];s.close()
   p=subprocess.Popen(['python3',str(ROOT/'listener.py')],env=dict(os.environ,MONERO_SCAN_STATE=t,MONERO_SCAN_PORTS=str(port)),stdout=subprocess.PIPE)
   try:
    self.assertTrue(json.loads(p.stdout.readline())['ready'])
    for data in (b'GET /json_rpc HTTP/1.0\r\n\r\n',b'A'*9000,b'',b'MONERO-SCAN-VALIDATION:test'):
     c=socket.create_connection(('127.0.0.1',port));c.sendall(data);c.shutdown(socket.SHUT_WR)
     try:self.assertEqual(c.recv(1),b'')
     except ConnectionResetError:pass
     c.close()
    time.sleep(.2)
    with closing(sqlite3.connect(pathlib.Path(t)/'queue.sqlite')) as db:
     rows=[json.loads(x[0]) for x in db.execute('SELECT event FROM pending ORDER BY rowid')]
    self.assertEqual(len(rows),4);self.assertEqual(rows[0]['classification'],'http_request');self.assertEqual(rows[1]['captured_bytes'],4096);self.assertEqual(rows[1]['outcome'],'capture_limit');self.assertEqual(rows[2]['classification'],'no_payload');self.assertTrue(rows[3]['is_validation'])
    self.assertEqual(base64.b64decode(rows[0]['payload_b64']),b'GET /json_rpc HTTP/1.0\r\n\r\n')
    self.assertEqual(len({r['session'] for r in rows}),4)
   finally:
    p.terminate()
    p.wait()
    p.stdout.close()
if __name__=='__main__':unittest.main()
