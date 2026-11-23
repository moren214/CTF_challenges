import json,socket,sys
HOST='172.16.221.2'; PORT=1337
class C:
    def __init__(self,host=HOST,port=PORT):
        self.s=socket.create_connection((host,port),timeout=10); self.f=self.s.makefile('rb')
    def ev(self,code):
        self.s.sendall((json.dumps({'code':code})+'\n').encode())
        line=self.f.readline()
        if not line: raise RuntimeError('closed')
        return json.loads(line)
    def close(self):
        try:self.s.close()
        except:pass
if __name__=='__main__':
    c=C(); code=sys.stdin.read(); print(json.dumps(c.ev(code),indent=1)[:4000]); c.close()
