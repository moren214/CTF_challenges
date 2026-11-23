import os,struct,subprocess,sys,json
RUNNER="/mnt/d/work/p3/build/qjs_runner"
LOADER="/opt/lc23986/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"
LIBPATH="/opt/lc23986/usr/lib/x86_64-linux-gnu"
def run(src, flag="{{FLAG}}", timeout=10):
    env={"LC_ALL":"C","LANG":"C","QJS_CTF_FLAG":flag}
    p=subprocess.Popen([LOADER,"--library-path",LIBPATH,RUNNER],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env)
    p.stdin.write(struct.pack(">I",len(src))+src.encode()); p.stdin.flush()
    hdr=p.stdout.read(5)
    if len(hdr)<5:
        err=p.stderr.read().decode(errors="replace"); p.wait(); return ("NOFRAME",err[-2000:])
    st=hdr[0:1]; n=struct.unpack(">I",hdr[1:5])[0]; payload=p.stdout.read(n)
    if os.environ.get("MAPS"):
        try:
            for line in open("/proc/%d/maps" % p.pid):
                if "libc.so.6" in line:
                    print("MAP", line.strip()); break
        except Exception as e: print("MAPERR",e)
    p.stdin.close()
    try: p.wait(timeout=2)
    except Exception: p.kill()
    return (st.decode(),payload.decode(errors="replace"))
if __name__=="__main__":
    src=open(sys.argv[1]).read()
    st,out=run(src)
    print("STATUS",st)
    print(out[:4000])
