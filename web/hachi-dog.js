/* Olfa mascot web component: <hachi-dog state="idle|scanning|safe|phishing|blocked|offline|error">. Art & animation from the original character sheet, unchanged. API: el.setDog(state); fires 'ended' after one-shot states. */
const SOFT='cubic-bezier(.45,0,.55,1)',SPRING='cubic-bezier(.34,1.56,.64,1)',FALL='cubic-bezier(.5,0,.9,.5)';
const EASE={s:SOFT,p:SPRING,f:FALL}, BRIDGE=350;
const tf=(x=0,y=0,r=0,sx=1,sy=1)=>`translate(${x}px,${y}px) rotate(${r}deg) scale(${sx},${sy})`;
// frame = [ms, {x,y,r,sx,sy,o}, easing-to-next: s|p|f]
const kf=(D,fr)=>fr.map(([t,v,e='s'])=>{const k={offset:t/D,easing:EASE[e],transform:tf(v.x,v.y,v.r,v.sx,v.sy)};if(v.o!==undefined)k.opacity=v.o;return k});
const O={}; // helper: {}
const BK=[600,1050,1500];
const zf=off=>Array.from({length:13},(_,i)=>{const t=i*200,ph=(((t-off)/2400)%1+1)%1,o=ph<.15?ph/.15:ph>.7?(1-ph)/.3:1,k=+(.5+ph*.7).toFixed(2);return [t,{o:+o.toFixed(2),x:Math.round(16*Math.sin(ph*7)),y:Math.round(-ph*120),sx:k,sy:k,r:Math.round(ph*14)}]});
const STATES={
idle:{D:4400,loop:true,parts:{
 rig:[[0,{}],[1900,{sx:.994,sy:1.012}],[4400,{}]],
 chest:[[0,{}],[1950,{sx:1.006,sy:1.01}],[4400,{}]],
 head:[[0,{}],[1300,{y:-1.5}],[2000,{y:-1.5,r:-3.5}],[3200,{y:-1,r:-3.5}],[4000,{}],[4400,{}]],
 'ear-l':[[0,{}],[1400,{r:1}],[2100,{r:-4}],[3300,{r:-3}],[4100,{}],[4400,{}]],
 'ear-r':[[0,{}],[1400,{r:-1}],[2100,{r:3}],[2650,{r:3}],[2760,{r:-9},'p'],[3000,{r:4}],[3300,{r:2}],[4100,{}],[4400,{}]],
 tail:[[0,{}],[500,{r:8}],[1000,{r:-3}],[1500,{r:6}],[2100,{}],[4400,{}]],
 'eye-l':[[0,{}],[3350,{}],[3470,{sx:1.03,sy:.08}],[3560,{sx:1.03,sy:.08}],[3760,{}],[4400,{}]],
 'eye-r':[[0,{}],[3350,{}],[3470,{sx:1.03,sy:.08}],[3560,{sx:1.03,sy:.08}],[3760,{}],[4400,{}]],
 'paw-fl':[[0,{}],[1950,{r:3}],[2760,{r:3}],[2900,{r:-3},'p'],[3300,{r:1}],[4400,{}]],
 'paw-fr':[[0,{}],[1950,{r:-3}],[2760,{r:-3}],[2900,{r:3},'p'],[3300,{r:-1}],[4400,{}]],
 collar:[[0,{}],[2050,{y:1}],[4400,{}]],
 badge:[[0,{}],[2250,{y:1.6,r:1}],[4400,{}]],
 tongue:[[0,{}],[2300,{y:1.5,sy:1.04}],[4400,{}]]}},
scanning:{D:4600,loop:true,parts:{
 rig:[[0,{}],[120,{sx:1.03,sy:.97}],[380,{sx:.985,sy:1.02,y:-2},'p'],[700,{}],[4600,{}]],
 head:[[0,{}],[250,{y:2}],[560,{y:-4}],[900,{y:-3}],[1250,{x:-9,y:-3,r:-8}],[1750,{x:-9,y:-3,r:-8}],[2450,{x:9,y:-3,r:8}],[2950,{x:9,y:-3,r:8}],[3600,{y:-2}],[4200,{}],[4600,{}]],
 'eye-l':[[0,{}],[800,{}],[1050,{x:-8},'p'],[1750,{x:-8}],[2250,{x:8},'p'],[2950,{x:8}],[3500,{}],[3880,{}],[3980,{sx:1.03,sy:.08}],[4070,{sx:1.03,sy:.08}],[4280,{}],[4600,{}]],
 'eye-r':[[0,{}],[800,{}],[1050,{x:-8},'p'],[1750,{x:-8}],[2250,{x:8},'p'],[2950,{x:8}],[3500,{}],[3880,{}],[3980,{sx:1.03,sy:.08}],[4070,{sx:1.03,sy:.08}],[4280,{}],[4600,{}]],
 'highlight-l':[[0,{}],[1140,{x:-2}],[1840,{x:-2}],[2340,{x:2}],[3040,{x:2}],[3590,{}],[4600,{}]],
 'highlight-r':[[0,{}],[1140,{x:-2}],[1840,{x:-2}],[2340,{x:2}],[3040,{x:2}],[3590,{}],[4600,{}]],
 'brow-l':[[0,{o:1,y:-6}],[160,{o:1,y:-6},'p'],[480,{o:1,y:-9}],[800,{o:1,y:-6}],[4600,{o:1,y:-6}]],
 'brow-r':[[0,{o:1,y:-6}],[220,{o:1,y:-6},'p'],[540,{o:1,y:-9}],[860,{o:1,y:-6}],[4600,{o:1,y:-6}]],
 'ear-l':[[0,{}],[330,{},'p'],[650,{r:5,sy:1.06}],[1350,{r:1,sy:1.06}],[2000,{r:5,sy:1.06}],[3700,{r:5,sy:1.06}],[4300,{}],[4600,{}]],
 'ear-r':[[0,{}],[390,{},'p'],[710,{r:-5,sy:1.06}],[1400,{r:-5,sy:1.06}],[2550,{r:-1,sy:1.06}],[3100,{r:-5,sy:1.06}],[3750,{r:-5,sy:1.06}],[4300,{}],[4600,{}]],
 'paw-fl':[[0,{}],[120,{r:-5}],[380,{r:8},'p'],[700,{r:3}],[3600,{r:3}],[4300,{}],[4600,{}]],
 'paw-fr':[[0,{}],[120,{r:5}],[380,{r:-8},'p'],[700,{r:-3}],[3600,{r:-3}],[4300,{}],[4600,{}]],
 mouth:[[0,{o:0}],[4600,{o:0}]],
 tongue:[[0,{o:0}],[4600,{o:0}]],
 'mouth-closed':[[0,{o:1}],[4600,{o:1}]],
 tail:[[0,{}],[700,{r:-3}],[1400,{r:4}],[2100,{r:-3}],[2800,{r:3}],[3500,{r:-1}],[4600,{}]],
 collar:[[0,{}],[250,{y:1.5}],[560,{y:-1.5}],[900,{}],[4600,{}]],
 badge:[[0,{}],[330,{y:2.5}],[660,{y:-2},'p'],[1000,{}],[4600,{}]]}},
safe:{D:2800,loop:false,parts:{
 ground:[[0,{}],[130,{sx:1.04}],[400,{sx:.86}],[560,{sx:.78}],[800,{sx:1.08},'p'],[1000,{sx:.97}],[1180,{sx:1.03}],[1450,{}],[2800,{}]],
 rig:[[0,{}],[130,{sx:1.05,sy:.93},'p'],[400,{sx:.965,sy:1.07,y:-40}],[560,{sx:.975,sy:1.05,y:-46},'f'],[800,{sx:1.07,sy:.92},'p'],[980,{sx:.985,sy:1.03,y:-9}],[1160,{sx:1.025,sy:.975},'p'],[1450,{}],[2800,{}]],
 chest:[[0,{}],[130,{sx:1.02,sy:.98}],[400,{sx:.99,sy:1.02}],[820,{sx:1.03,sy:.97}],[1200,{}],[2800,{}]],
 head:[[0,{}],[230,{y:3}],[520,{y:-6}],[640,{y:-3}],[900,{y:5}],[1080,{y:-4}],[1260,{y:2}],[1500,{r:-5},'p'],[2300,{r:-5}],[2800,{}]],
 'ear-l':[[0,{}],[330,{}],[560,{r:-10}],[700,{r:-13}],[940,{r:7},'p'],[1160,{r:-3}],[1420,{r:1}],[1700,{r:-2}],[2400,{r:-2}],[2800,{}]],
 'ear-r':[[0,{}],[380,{}],[610,{r:10}],[750,{r:13}],[990,{r:-7},'p'],[1210,{r:3}],[1470,{r:-1}],[1750,{r:3}],[2450,{r:3}],[2800,{}]],
 'eye-l':[[0,{o:1}],[150,{o:1}],[480,{o:0}],[2350,{o:0}],[2750,{o:1}],[2800,{o:1}]],
 'eye-r':[[0,{o:1}],[150,{o:1}],[480,{o:0}],[2350,{o:0}],[2750,{o:1}],[2800,{o:1}]],
 'eyes-happy-arc':[[0,{o:0}],[250,{o:0}],[520,{o:1}],[2350,{o:1}],[2750,{o:0}],[2800,{o:0}]],
 'cheek-l':[[0,{o:0}],[450,{o:0}],[900,{o:.9}],[2400,{o:.9}],[2800,{o:0}]],
 'cheek-r':[[0,{o:0}],[500,{o:0}],[950,{o:.9}],[2400,{o:.9}],[2800,{o:0}]],
 tongue:[[0,{}],[650,{y:-2}],[920,{y:5,sy:1.08}],[1120,{y:-3}],[1400,{y:1}],[1800,{y:2,sy:1.03}],[2300,{y:2,sy:1.03}],[2800,{}]],
 tail:[[0,{}],[250,{r:-6}],[460,{r:16}],[650,{r:-10}],[840,{r:18}],[1030,{r:-8}],[1230,{r:13}],[1430,{r:-4}],[1640,{r:9}],[1880,{r:-2}],[2150,{r:5}],[2800,{}]],
 'paw-fl':[[0,{}],[110,{r:-8}],[430,{r:48},'p'],[620,{r:62}],[860,{r:-12}],[1040,{r:14}],[1300,{r:-2}],[1700,{r:6}],[2400,{r:6}],[2800,{}]],
 'paw-fr':[[0,{}],[170,{r:8}],[490,{r:-48},'p'],[680,{r:-62}],[920,{r:12}],[1100,{r:-14}],[1360,{r:2}],[1760,{r:-6}],[2400,{r:-6}],[2800,{}]],
 collar:[[0,{}],[130,{y:2}],[480,{y:-4}],[700,{y:-2}],[900,{y:5}],[1100,{y:-1.5}],[1350,{}],[2800,{}]],
 badge:[[0,{}],[200,{y:3,r:2}],[560,{y:-6,r:-4}],[740,{y:-3,r:-2}],[960,{y:7,r:5}],[1180,{y:-2,r:-2}],[1420,{y:.5,r:1}],[1700,{}],[2800,{}]],
 'spark-1':[[0,{o:0,sx:.2,sy:.2}],[700,{o:0,sx:.2,sy:.2},'p'],[1000,{o:1,r:15}],[1300,{o:1,sx:.85,sy:.85,r:20}],[1600,{o:1,sx:1.05,sy:1.05,r:28}],[2000,{o:1,sx:.9,sy:.9,r:34}],[2500,{o:0,sx:.4,sy:.4,r:45}],[2800,{o:0,sx:.4,sy:.4,r:45}]],
 'spark-2':[[0,{o:0,sx:.2,sy:.2}],[860,{o:0,sx:.2,sy:.2},'p'],[1160,{o:1,r:-15}],[1450,{o:1,sx:.85,sy:.85,r:-20}],[1750,{o:1,sx:1.05,sy:1.05,r:-28}],[2150,{o:1,sx:.9,sy:.9,r:-34}],[2550,{o:0,sx:.4,sy:.4,r:-45}],[2800,{o:0,sx:.4,sy:.4,r:-45}]],
 'spark-3':[[0,{o:0,sx:.2,sy:.2}],[1020,{o:0,sx:.2,sy:.2},'p'],[1320,{o:1,r:10}],[1600,{o:1,sx:.85,sy:.85,r:15}],[1900,{o:1,sx:1.05,sy:1.05,r:22}],[2250,{o:1,sx:.9,sy:.9,r:28}],[2600,{o:0,sx:.4,sy:.4,r:40}],[2800,{o:0,sx:.4,sy:.4,r:40}]],
 heart:[[0,{o:0,sx:.3,sy:.3}],[1050,{o:0,sx:.3,sy:.3},'p'],[1400,{o:1}],[1800,{o:1,y:-8,sx:1.05,sy:1.05}],[2300,{o:1,y:-14}],[2650,{o:0,y:-24,sx:.9,sy:.9}],[2800,{o:0,y:-24,sx:.9,sy:.9}]]}},
phishing:{D:2500,loop:false,
shake:BK.flatMap((b,i)=>{const a=[4,3,3][i];return [[b-10,0,0],[b+20,a,-a/2],[b+50,-a,a/2],[b+90,a*.7,0],[b+130,-a*.4,0],[b+170,0,0]]}),
parts:{
 rig:[[0,{}],[240,{y:-8,sy:1.035,sx:.985}],[400,{sx:1.07,sy:.9},'p'],...BK.flatMap(b=>[[b,{sx:1.085,sy:.875}],[b+120,{sx:1.07,sy:.9}]]),[1900,{sx:1.07,sy:.9}],[2100,{y:-2,sx:.99,sy:1.02}],[2300,{}],[2500,{}]],
 head:[[0,{}],[240,{y:-5}],[400,{y:3,sx:1.01,sy:1.01}],...BK.flatMap(b=>[[b-80,{y:3,sx:1.01,sy:1.01}],[b,{y:9,sx:1.09,sy:1.09},'p'],[b+160,{y:3,sx:1.01,sy:1.01}]]),[1900,{y:3,sx:1.01,sy:1.01}],[2100,{y:-1}],[2300,{}],[2500,{}]],
 'ear-l':[[0,{}],[240,{r:3}],[400,{r:-20,sy:.92},'p'],...BK.flatMap(b=>[[b,{r:-25,sy:.9}],[b+160,{r:-20,sy:.92}]]),[1900,{r:-20,sy:.92}],[2150,{r:2}],[2500,{}]],
 'ear-r':[[0,{}],[240,{r:-3}],[400,{r:20,sy:.92},'p'],...BK.flatMap(b=>[[b,{r:25,sy:.9}],[b+160,{r:20,sy:.92}]]),[1900,{r:20,sy:.92}],[2150,{r:-2}],[2500,{}]],
 'brow-l':[[0,{o:0}],[300,{o:0}],[420,{o:1,y:14,r:12},'p'],[1900,{o:1,y:14,r:12}],[2200,{o:0}],[2500,{o:0}]],
 'brow-r':[[0,{o:0}],[300,{o:0}],[420,{o:1,y:14,r:-12},'p'],[1900,{o:1,y:14,r:-12}],[2200,{o:0}],[2500,{o:0}]],
 'eye-l':[[0,{}],[240,{sx:1.02,sy:1.05}],[400,{sx:1.05,sy:.64,y:6},'p'],[1900,{sx:1.05,sy:.64,y:6}],[2150,{sy:.95}],[2500,{}]],
 'eye-r':[[0,{}],[240,{sx:1.02,sy:1.05}],[400,{sx:1.05,sy:.64,y:6},'p'],[1900,{sx:1.05,sy:.64,y:6}],[2150,{sy:.95}],[2500,{}]],
 mouth:[[0,{o:0}],...BK.flatMap(b=>[[b-40,{o:0}],[b-10,{o:1,sy:1.2}],[b+170,{o:1,sy:1.2}],[b+200,{o:0}]]),[1950,{o:0}],[2050,{o:1}],[2500,{o:1}]],
 'mouth-closed':[[0,{o:1}],...BK.flatMap(b=>[[b-40,{o:1}],[b-10,{o:0}],[b+170,{o:0}],[b+200,{o:1}]]),[1950,{o:1}],[2050,{o:0}],[2500,{o:0}]],
 tongue:[[0,{o:0}],...BK.flatMap(b=>[[b-40,{o:0}],[b-10,{o:1,y:4}],[b+170,{o:1,y:4}],[b+200,{o:0}]]),[1950,{o:0}],[2050,{o:1}],[2500,{o:1}]],
 tail:[[0,{}],[240,{r:-6}],[400,{r:-38},'p'],...BK.flatMap(b=>[[b,{r:-42}],[b+100,{r:-36}]]),[1900,{r:-38}],[2100,{r:-8}],[2300,{r:3}],[2500,{}]],
 'paw-fl':[[0,{}],[240,{r:-9,sy:1.04}],[400,{r:18},'p'],...BK.flatMap(b=>[[b,{r:28,sx:1.06,sy:1.08,y:4}],[b+160,{r:18}]]),[1900,{r:18}],[2000,{r:-5}],[2150,{r:7}],[2300,{r:-1}],[2500,{}]],
 'paw-fr':[[0,{}],[240,{r:9,sy:1.04}],[400,{r:-18},'p'],...BK.flatMap(b=>[[b,{r:-28,sx:1.06,sy:1.08,y:4}],[b+160,{r:-18}]]),[1900,{r:-18}],[2000,{r:5}],[2150,{r:-7}],[2300,{r:1}],[2500,{}]],
 ground:[[0,{}],[400,{sx:1.1}],[1900,{sx:1.1}],[2300,{}],[2500,{}]],
 ring:[[0,{o:0,sx:.8,sy:.8}],...BK.flatMap(b=>[[b-20,{o:0,sx:.8,sy:.8}],[b+60,{o:.9,sx:.95,sy:.95}],[b+420,{o:0,sx:1.45,sy:1.45}]]),[2500,{o:0,sx:1.45,sy:1.45}]],
 'arcs-r':[[0,{o:0,sx:.5,sy:.5}],...BK.flatMap(b=>[[b-10,{o:0,sx:.5,sy:.5}],[b+60,{o:1,sx:.95,sy:.95}],[b+320,{o:0,sx:1.35,sy:1.35,x:14}]]),[2500,{o:0,sx:1.35,sy:1.35,x:14}]],
 'arcs-l':[[0,{o:0,sx:.5,sy:.5}],...BK.flatMap(b=>[[b-10,{o:0,sx:.5,sy:.5}],[b+60,{o:1,sx:.95,sy:.95}],[b+320,{o:0,sx:1.35,sy:1.35,x:-14}]]),[2500,{o:0,sx:1.35,sy:1.35,x:-14}]],
 woof:[[0,{o:0,sx:.4,sy:.4}],...BK.flatMap(b=>[[b-10,{o:0,sx:.4,sy:.4}],[b+80,{o:1,sx:1.15,sy:1.15,r:-4},'p'],[b+170,{o:1}],[b+340,{o:0,y:-14}]]),[2500,{o:0,y:-14}]]}},
blocked:{D:2600,loop:false,parts:{
 rig:[[0,{}],[150,{sx:1.03,sy:.96}],[450,{sx:.99,sy:1.03,y:-6}],[520,{y:-8,sy:1.04},'f'],[600,{sx:1.07,sy:.9},'p'],[760,{sx:.98,sy:1.03,y:-5}],[930,{sx:1.02,sy:.98}],[1100,{}],[2600,{}]],
 head:[[0,{}],[150,{y:2}],[450,{y:-5,r:3}],[520,{y:-6,r:3},'f'],[600,{y:5,sx:1.02,sy:1.02},'p'],[760,{y:-3}],[1000,{y:-4}],[1250,{y:4,r:2}],[1450,{y:-4}],[1650,{y:3,r:1}],[1850,{y:-3}],[2100,{}],[2600,{}]],
 'paw-fr':[[0,{}],[150,{r:8,y:2}],[450,{r:-105,sy:1.05}],[520,{r:-110,sy:1.05},'f'],[600,{r:-4,sy:1.12,y:6}],[680,{r:-4,sy:1.12,y:6}],[900,{r:2}],[1100,{r:-5}],[2000,{r:-5}],[2300,{}],[2600,{}]],
 'paw-fl':[[0,{}],[150,{r:-4}],[450,{r:8}],[600,{r:-6},'p'],[900,{r:3}],[1100,{r:5}],[2000,{r:5}],[2300,{}],[2600,{}]],
 'ear-l':[[0,{}],[150,{r:3}],[450,{r:-6}],[600,{r:8},'p'],[800,{r:-3}],[1100,{r:-4}],[2000,{r:-4}],[2300,{}],[2600,{}]],
 'ear-r':[[0,{}],[150,{r:-3}],[450,{r:6}],[600,{r:-8},'p'],[800,{r:3}],[1100,{r:4}],[2000,{r:4}],[2300,{}],[2600,{}]],
 'brow-l':[[0,{o:0}],[300,{o:0}],[450,{o:1,y:10,r:10}],[700,{o:1,y:10,r:10}],[850,{o:0}],[2600,{o:0}]],
 'brow-r':[[0,{o:0}],[300,{o:0}],[450,{o:1,y:10,r:-10}],[700,{o:1,y:10,r:-10}],[850,{o:0}],[2600,{o:0}]],
 'eye-l':[[0,{o:1}],[450,{o:1}],[520,{o:1,sy:.8,y:3}],[690,{o:1,sy:.8,y:3}],[800,{o:1}],[1000,{o:1}],[1100,{o:0}],[2050,{o:0}],[2250,{o:1}],[2600,{o:1}]],
 'eye-r':[[0,{o:1}],[450,{o:1}],[520,{o:1,sy:.8,y:3}],[690,{o:1,sy:.8,y:3}],[800,{o:1}],[1000,{o:1}],[1100,{o:0}],[2050,{o:0}],[2250,{o:1}],[2600,{o:1}]],
 'eyes-happy-arc':[[0,{o:0}],[1000,{o:0}],[1100,{o:1}],[2050,{o:1}],[2250,{o:0}],[2600,{o:0}]],
 'cheek-l':[[0,{o:0}],[1000,{o:0}],[1200,{o:.9}],[2050,{o:.9}],[2400,{o:0}],[2600,{o:0}]],
 'cheek-r':[[0,{o:0}],[1000,{o:0}],[1200,{o:.9}],[2050,{o:.9}],[2400,{o:0}],[2600,{o:0}]],
 mouth:[[0,{o:1}],[400,{o:1}],[450,{o:0}],[760,{o:0}],[820,{o:1}],[2600,{o:1}]],
 'mouth-closed':[[0,{o:0}],[400,{o:0}],[450,{o:1}],[760,{o:1}],[820,{o:0}],[2600,{o:0}]],
 tongue:[[0,{o:1}],[400,{o:1}],[450,{o:0}],[760,{o:0}],[820,{o:1}],[2600,{o:1}]],
 tail:[[0,{}],[450,{r:-8}],[600,{r:-14}],[900,{r:0}],[1050,{r:-16}],[1200,{r:16}],[1350,{r:-16}],[1500,{r:16}],[1650,{r:-14}],[1800,{r:14}],[1950,{r:-10}],[2100,{r:8}],[2300,{r:-2}],[2600,{}]],
 collar:[[0,{}],[600,{y:3}],[760,{y:-2}],[1000,{}],[2600,{}]],
 badge:[[0,{}],[600,{y:5,r:2}],[760,{y:-3,r:-2}],[1000,{}],[2600,{}]],
 ground:[[0,{}],[600,{sx:1.08},'p'],[900,{sx:.98}],[1100,{}],[2600,{}]],
 impact:[[0,{o:0,sx:.3,sy:.3}],[595,{o:0,sx:.3,sy:.3}],[620,{o:1,sx:.5,sy:.5}],[900,{o:0,sx:1.5,sy:1.5}],[2600,{o:0,sx:1.5,sy:1.5}]],
 stamp:[[0,{o:0,sx:.3,sy:.3}],[590,{o:0,sx:.3,sy:.3},'p'],[740,{o:1,sx:1,sy:1}],[1700,{o:1}],[2100,{o:0,y:-12,sx:.9,sy:.9}],[2600,{o:0,y:-12,sx:.9,sy:.9}]]}},
offline:{D:2400,loop:false,
hold:{D:2400,parts:{
 rig:[[0,{y:-40,sx:1.02,sy:.93}],[1200,{y:-40,sx:1.03,sy:.95}],[2400,{y:-40,sx:1.02,sy:.93}]],
 head:[[0,{r:-9,y:10}],[1200,{r:-7,y:8}],[2400,{r:-9,y:10}]],
 z1:zf(0),z2:zf(800),z3:zf(1600)}},
parts:{
 chair:[[0,{o:0,y:50,sx:.8,sy:.8}],[100,{o:0,y:50,sx:.8,sy:.8},'p'],[700,{o:1}],[2400,{o:1}]],
 rig:[[0,{}],[700,{sy:.95,sx:1.02}],[900,{y:-70,sy:1.03,sx:.98},'f'],[1150,{y:-40,sx:1.05,sy:.9},'p'],[1300,{y:-40,sx:1.02,sy:.93}],[2400,{y:-40,sx:1.02,sy:.93}]],
 head:[[0,{}],[700,{y:2}],[900,{y:-3}],[1150,{y:5,sx:1.02,sy:.98},'p'],[1300,{}],[1600,{r:-4,y:4}],[2200,{r:-9,y:10}],[2400,{r:-9,y:10}]],
 'ear-l':[[0,{}],[1300,{}],[2100,{r:-26,sy:.92}],[2400,{r:-26,sy:.92}]],
 'ear-r':[[0,{}],[1300,{}],[2100,{r:26,sy:.92}],[2400,{r:26,sy:.92}]],
 'eye-l':[[0,{o:1}],[1400,{o:1}],[1600,{o:1,sy:.4}],[2000,{o:1,sy:.15}],[2200,{o:0,sy:.15}],[2400,{o:0,sy:.15}]],
 'eye-r':[[0,{o:1}],[1400,{o:1}],[1600,{o:1,sy:.4}],[2000,{o:1,sy:.15}],[2200,{o:0,sy:.15}],[2400,{o:0,sy:.15}]],
 'eyes-sleep':[[0,{o:0}],[2000,{o:0}],[2200,{o:1}],[2400,{o:1}]],
 mouth:[[0,{o:1}],[1300,{o:1}],[1500,{o:0}],[2400,{o:0}]],
 tongue:[[0,{o:1}],[1300,{o:1}],[1500,{o:0}],[2400,{o:0}]],
 'mouth-closed':[[0,{o:0}],[1300,{o:0}],[1500,{o:1}],[2400,{o:1}]],
 tail:[[0,{}],[1300,{r:4}],[2100,{r:8}],[2400,{r:8}]],
 'paw-bl':[[0,{}],[1150,{x:-12,r:-6}],[2400,{x:-12,r:-6}]],
 'paw-br':[[0,{}],[1150,{x:12,r:6}],[2400,{x:12,r:6}]],
 'paw-fl':[[0,{}],[900,{}],[1300,{r:-62,sy:.92}],[2400,{r:-62,sy:.92}]],
 'paw-fr':[[0,{}],[900,{}],[1300,{r:62,sy:.92}],[2400,{r:62,sy:.92}]],
 z1:[[0,{o:0}],[2400,{o:0}]],z2:[[0,{o:0}],[2400,{o:0}]],z3:[[0,{o:0}],[2400,{o:0}]]}},
error:{D:3600,loop:true,parts:{
 rig:[[0,{}],[300,{sx:1.01,sy:.98}],[1000,{sx:1.02,sy:.97}],[1500,{sx:1.01,sy:.98}],[2800,{sx:1.01,sy:.98}],[3300,{}],[3600,{}]],
 head:[[0,{}],[300,{r:-11,y:2},'p'],[1000,{r:-11,y:2}],[1700,{r:-14,y:3}],[2800,{r:-11,y:2}],[3300,{}],[3600,{}]],
 'eye-l':[[0,{}],[700,{}],[850,{x:-9},'p'],[1350,{x:-9}],[1450,{x:9},'p'],[2000,{x:9}],[2200,{}],[3600,{}]],
 'eye-r':[[0,{}],[700,{}],[850,{x:9},'p'],[1350,{x:9}],[1450,{x:-9},'p'],[2000,{x:-9}],[2200,{}],[3600,{}]],
 'highlight-l':[[0,{}],[700,{}],[850,{x:-3}],[1350,{x:-3}],[1450,{x:3}],[2000,{x:3}],[2200,{}],[3600,{}]],
 'highlight-r':[[0,{}],[700,{}],[850,{x:3}],[1350,{x:3}],[1450,{x:-3}],[2000,{x:-3}],[2200,{}],[3600,{}]],
 'brow-l':[[0,{o:0}],[250,{o:0}],[400,{o:1,y:-4,r:-12},'p'],[3000,{o:1,y:-4,r:-12}],[3400,{o:0}],[3600,{o:0}]],
 'brow-r':[[0,{o:0}],[250,{o:0}],[400,{o:1,y:-4,r:12},'p'],[3000,{o:1,y:-4,r:12}],[3400,{o:0}],[3600,{o:0}]],
 mouth:[[0,{o:1}],[300,{o:1}],[400,{o:0}],[3200,{o:0}],[3400,{o:1}],[3600,{o:1}]],
 tongue:[[0,{o:1}],[300,{o:1}],[400,{o:0}],[3200,{o:0}],[3400,{o:1}],[3600,{o:1}]],
 'mouth-closed':[[0,{o:0}],[300,{o:0}],[400,{o:1}],[3200,{o:1}],[3400,{o:0}],[3600,{o:0}]],
 'ear-l':[[0,{}],[300,{r:-14,sy:.95}],[2800,{r:-14,sy:.95}],[3300,{}],[3600,{}]],
 'ear-r':[[0,{}],[300,{r:-5,sy:1.07}],[2800,{r:-5,sy:1.07}],[3300,{}],[3600,{}]],
 tail:[[0,{}],[300,{r:10}],[1500,{r:12}],[2800,{r:10}],[3300,{}],[3600,{}]],
 'paw-fl':[[0,{}],[300,{r:4}],[900,{r:4}],[1000,{r:20,y:-6},'p'],[1500,{r:20,y:-6}],[1700,{r:4}],[2800,{r:4}],[3300,{}],[3600,{}]],
 'paw-fr':[[0,{}],[300,{r:-4}],[900,{r:-4}],[1000,{r:-20,y:-6},'p'],[1500,{r:-20,y:-6}],[1700,{r:-4}],[2800,{r:-4}],[3300,{}],[3600,{}]],
 sweat:[[0,{o:0,y:-10,sx:.3,sy:.3}],[500,{o:0,y:-10,sx:.3,sy:.3},'p'],[800,{o:1}],[2200,{o:1,y:14}],[2900,{o:1,y:60,sx:.9,sy:1.1}],[3200,{o:0,y:90,sx:.8,sy:1.15}],[3600,{o:0,y:-10,sx:.3,sy:.3}]]}}
};
const IDS=[...new Set(Object.values(STATES).flatMap(s=>Object.keys(s.parts)))];
const OPS=new Set(Object.values(STATES).flatMap(s=>Object.entries(s.parts).filter(([,f])=>f.some(a=>a[1].o!==undefined)).map(a=>a[0])));
for(const s of Object.values(STATES)){for(const id in s.parts)s.parts[id]=kf(s.D,s.parts[id]);if(s.hold)for(const id in s.hold.parts)s.hold.parts[id]=kf(s.hold.D,s.hold.parts[id]);}

const CSS=`
:host{display:inline-block;width:var(--hachi-size,240px);aspect-ratio:1;line-height:0}
svg{width:100%;height:100%;display:block;overflow:visible}
#ground,#rig,#tail,#chest,#paw-fl,#paw-fr,#paw-bl,#paw-br,#collar,#badge,#head,#ear-l,#ear-r,#brow-l,#brow-r,#cheek-l,#cheek-r,
#eyelid-l,#eyelid-r,#eye-l,#eye-r,#highlight-l,#highlight-r,#tongue,#mouth,#mouth-closed,#eyes-happy-arc,
#spark-1,#spark-2,#spark-3,#heart,#ring,#woof,#arcs-l,#arcs-r,#impact,#stamp,#eyes-sleep,#z1,#z2,#z3,#sweat,#chair{transform-box:fill-box;transform-origin:50% 50%}
#rig{transform-origin:50% 100%}#head{transform-origin:50% 95%}
#ear-l{transform-origin:85% 90%}#ear-r{transform-origin:15% 90%}
#tail{transform-origin:0% 55%}#paw-fl{transform-origin:90% 0%}#paw-fr{transform-origin:10% 0%}#arcs-r{transform-origin:0% 50%}#arcs-l{transform-origin:100% 50%}#chair{transform-origin:50% 100%}
#eyelid-l,#eyelid-r,#tongue,#collar,#badge,#chest{transform-origin:50% 0%}
/* hidden by default; controlled here, animated by the state engine */
#brow-l,#brow-r,#cheek-l,#cheek-r,#eyelid-l,#eyelid-r,#mouth-closed,#eyes-happy-arc,#spark-1,#spark-2,#spark-3,#heart,#ring,#woof,#arcs-l,#arcs-r,#impact,#stamp,#eyes-sleep,#z1,#z2,#z3,#sweat,#chair{opacity:0}
@media (prefers-reduced-motion:reduce){
 :host([state=scanning]) #brow-l,:host([state=scanning]) #brow-r{opacity:1;transform:translateY(-6px)}
 :host([state=scanning]) #mouth,:host([state=scanning]) #tongue{opacity:0}
 :host([state=scanning]) #mouth-closed{opacity:1}
 :host([state=scanning]) #head{transform:rotate(-5deg)}
 :host([state=scanning]) #ear-l{transform:rotate(5deg) scaleY(1.06)}
 :host([state=scanning]) #ear-r{transform:rotate(-5deg) scaleY(1.06)}
 :host([state=safe]) #eye-l,:host([state=safe]) #eye-r{opacity:0}
 :host([state=safe]) #eyes-happy-arc,:host([state=safe]) #spark-1,:host([state=safe]) #spark-2,:host([state=safe]) #spark-3,:host([state=safe]) #heart{opacity:1}
 :host([state=safe]) #cheek-l,:host([state=safe]) #cheek-r{opacity:.9}
 :host([state=safe]) #head{transform:rotate(-5deg)}
}`;
const SVG=`<svg xmlns="http://www.w3.org/2000/svg" viewBox="85 107 940 940" role="img" aria-label="Hachi the Shiba Inu"><style>path,ellipse,circle,rect{stroke-linejoin:round;stroke-linecap:round}
.ol{stroke:#6B2C0A;stroke-width:11}
.o{fill:#FBAE4A}.c{fill:#FBEDCD}.ie{fill:#FDEBCB}.is{fill:#FDD6A3}.e{fill:#391E10}.wh{fill:#F4F2EF}.gl{fill:#A0622E}
.k{stroke:none}.so{fill:none;stroke:#6B2C0A;stroke-width:11}.m{fill:none;stroke:#C98F5E;stroke-width:7}.ln{fill:none;stroke:#6B2C0A;stroke-width:9}
.r{fill:#C24F44}.g{fill:#FBBB4B}.t{fill:#F67160}.td{fill:#C24F44}
.ha{fill:none;stroke:#391E10;stroke-width:11}</style>
<ellipse id="ground" cx="565" cy="978" rx="250" ry="18" fill="#6B2C0A" opacity=".14"/>
<ellipse id="ring" cx="565" cy="978" rx="250" ry="18" fill="none" stroke="#E0463A" stroke-width="9"/>
<g id="chair"><rect x="170" y="190" width="760" height="760" rx="90" fill="#5E9E97" stroke="#6B2C0A" stroke-width="11"/><rect x="215" y="235" width="670" height="560" rx="60" fill="#7FB8B0" stroke="#6B2C0A" stroke-width="8"/><path d="M255 285H335" fill="none" stroke="#A9D6CF" stroke-width="8"/><rect x="130" y="640" width="150" height="320" rx="50" fill="#4F8D86" stroke="#6B2C0A" stroke-width="10"/><rect x="820" y="640" width="150" height="320" rx="50" fill="#4F8D86" stroke="#6B2C0A" stroke-width="10"/><rect x="230" y="930" width="640" height="55" rx="26" fill="#7FB8B0" stroke="#6B2C0A" stroke-width="8"/><rect x="170" y="962" width="50" height="36" rx="10" fill="#8A4B22" stroke="#6B2C0A" stroke-width="8"/><rect x="880" y="962" width="50" height="36" rx="10" fill="#8A4B22" stroke="#6B2C0A" stroke-width="8"/></g>
<g id="rig">
<g id="tail"><path class="o ol" d="M 718 768C 756 713 846 716 861 783C 871 833 844 876 796 884C 766 884 741 876 728 866C 738 838 731 798 718 768Z"/><path class="c k" d="M 741 756C 796 746 838 778 824 828C 816 858 781 866 756 862C 784 846 790 810 762 784Z"/></g>
<g id="body"><path class="o k" d="M550 690L440 690C408 745 372 815 376 880C377 893 380 902 384 908L508 934C516 916 526 900 532 890L550 888Z"/><path class="o k" d="M 550 690L 660 690C 692 745 728 815 724 880C 723 893 720 902 716 908L 592 934C 584 916 574 900 568 890L 550 888Z"/><path class="so" d="M440 690C408 745 372 815 376 880C377 893 380 902 384 908"/><path class="so" d="M 660 690C 692 745 728 815 724 880C 723 893 720 902 716 908"/></g>
<g id="chest"><path class="c k" d="M448 700C420 765 422 835 468 866C510 892 590 892 632 866C678 835 680 765 652 700Z"/></g>
<g id="paw-fl"><path class="o k" d="M452 694C418 700 392 735 384 782C379 815 394 836 418 832C432 828 442 800 448 760C452 735 456 715 458 700Z"/><path class="c k" d="M384 796C396 808 412 810 427 802C430 818 424 829 415 832C397 836 381 820 384 796Z"/><path class="so" d="M452 694C418 700 392 735 384 782C379 815 394 836 418 832C432 828 442 800 448 760"/></g>
<g id="paw-fr"><path class="o k" d="M648 694C682 700 708 735 716 782C721 815 706 836 682 832C668 828 658 800 652 760C648 735 644 715 642 700Z"/><path class="c k" d="M716 796C704 808 688 810 673 802C670 818 676 829 685 832C703 836 719 820 716 796Z"/><path class="so" d="M648 694C682 700 708 735 716 782C721 815 706 836 682 832C668 828 658 800 652 760"/></g>
<g id="paw-bl"><path class="o k" d="M386 903C372 912 350 930 345 952C344 970 366 980 400 979C440 978 480 965 510 934C505 922 490 906 470 902C440 896 410 896 386 903Z"/><path class="c k" d="M351 958C355 942 380 932 408 934C428 938 440 952 446 967C420 977 380 978 357 969Z"/><path class="m" d="M368 962C371 952 378 946 386 943M389 970C392 959 399 951 408 948"/><path class="so" d="M386 903C372 912 350 930 345 952C344 970 366 980 400 979C440 978 480 965 510 934"/></g>
<g id="paw-br"><path class="o k" d="M 714 903C 728 912 750 930 755 952C 756 970 734 980 700 979C 660 978 620 965 590 934C 595 922 610 906 630 902C 660 896 690 896 714 903Z"/><path class="c k" d="M 749 958C 745 942 720 932 692 934C 672 938 660 952 654 967C 680 977 720 978 743 969Z"/><path class="m" d="M 732 962C 729 952 722 946 714 943M 711 970C 708 959 701 951 692 948"/><path class="so" d="M 714 903C 728 912 750 930 755 952C 756 970 734 980 700 979C 660 978 620 965 590 934"/></g>
<g id="crotch"><path class="so" d="M508 934C516 916 526 900 532 890L550 888"/><path class="so" d="M 592 934C 584 916 574 900 568 890L 550 888"/></g>
<g id="collar"><path class="r ol" style="stroke-width:8" d="M472 688Q555 722 638 688L633 710Q555 746 477 710Z"/></g>
<g id="badge"><path class="g ol" style="stroke-width:8" d="M555 732L581 741V762Q581 783 555 794Q529 783 529 762V741Z"/><rect class="e k" x="545" y="760" width="20" height="16" rx="4"/><path class="ln" style="stroke:#391E10;stroke-width:6;fill:none" d="M549 760V755Q555 747 561 755V760"/></g>
<g id="head">
<path class="o ol" d="M416 286C488 214 630 214 694 282L720 296C760 330 815 370 845 450C868 520 870 590 840 625C805 655 740 665 680 675C640 682 600 684 550 684C500 684 460 680 420 672C370 662 310 650 280 620C245 590 240 520 262 450C278 405 300 380 320 350Z"/>
<g id="ear-l"><path class="o k" d="M436 270C400 230 352 182 292 180C245 182 212 235 218 305C222 345 255 372 290 398L440 330Z"/><path class="ie k" d="M262 282C258 245 278 236 300 244C345 258 376 288 388 306C345 322 320 350 298 390C272 352 262 312 262 282Z"/><path class="is k" d="M388 306C345 322 320 350 298 390C300 345 325 316 388 306Z"/><path class="so" d="M436 270C400 230 352 182 292 180C245 182 212 235 218 305C222 345 255 372 290 398"/></g>
<g id="ear-r"><path class="o k" d="M 664 270C 700 230 748 182 808 180C 855 182 888 235 882 305C 878 345 845 372 810 398L 660 330Z"/><path class="ie k" d="M 838 282C 842 245 822 236 800 244C 755 258 724 288 712 306C 755 322 780 350 802 390C 828 352 838 312 838 282Z"/><path class="is k" d="M 712 306C 755 322 780 350 802 390C 800 345 775 316 712 306Z"/><path class="so" d="M 664 270C 700 230 748 182 808 180C 855 182 888 235 882 305C 878 345 845 372 810 398"/></g>
<path class="c k" d="M268 572C258 522 296 498 335 506C385 518 425 510 468 474C503 448 530 450 550 454C570 450 597 448 632 474C675 510 715 518 765 506C804 498 842 522 832 572C826 612 800 632 750 646C700 662 640 672 550 674C470 672 400 662 350 646C300 632 274 612 270 575Z"/>
<g id="forehead-spot-l"><ellipse class="ie k" cx="460" cy="313" rx="29" ry="20" transform="rotate(-22 460 313)"/></g>
<g id="forehead-spot-r"><ellipse class="ie k" cx="654" cy="309" rx="26" ry="18" transform="rotate(22 654 309)"/></g>
<g id="brow-l"><path class="ln" d="M375 380Q420 360 470 372"/></g><g id="brow-r"><path class="ln" d="M730 380Q685 360 635 372"/></g>
<g id="cheek-l"><ellipse cx="318" cy="590" rx="30" ry="18" fill="#FD9F92"/></g><g id="cheek-r"><ellipse cx="782" cy="590" rx="30" ry="18" fill="#FD9F92"/></g>
<g id="muzzle-base"></g>
<g id="mouth"><path class="e" d="M512 538C505 590 535 618 562 616C595 616 616 580 612 538C600 548 585 552 562 552C540 552 524 548 512 538Z"/><path class="ln" style="stroke:#391E10;stroke-width:7" d="M512 538C503 538 499 528 505 524M612 538C621 538 625 528 619 524"/></g>
<g id="mouth-closed"><path class="ln" style="stroke:#391E10;stroke-width:7" d="M562 532V546M562 546C550 561 530 558 521 545M562 546C574 561 594 558 603 545"/></g>
<g id="tongue"><path class="t" d="M531 586C540 570 584 570 593 586C590 606 574 616 562 616C548 616 534 606 531 586Z"/><path class="td k" d="M532 588C540 572 586 572 592 588C580 582 545 582 532 588Z"/></g>
<g id="muzzle-top"></g>
<g id="eye-l"><path class="e" d="M428 398C470 398 491 436 487 476C483 511 456 530 426 529C392 528 367 500 367 460C367 425 391 398 428 398Z"/><path class="wh" d="M394 404C362 424 355 480 384 516C372 482 374 440 402 412Z"/><path class="gl" d="M396 482C412 512 446 514 462 484C466 500 452 516 430 516C410 516 398 504 396 482Z"/>
<g id="pupil-l"></g><g id="highlight-l"><ellipse class="wh" cx="452" cy="432" rx="15" ry="18"/><circle class="wh" cx="463" cy="462" r="7"/></g>
<g id="eyelid-l"><path class="o k" d="M430 392C478 392 505 432 498 440L360 440C365 410 395 392 430 392Z"/></g></g><g id="eye-r"><path class="e" d="M 685 398C 643 398 622 436 626 476C 630 511 657 530 687 529C 721 528 746 500 746 460C 746 425 722 398 685 398Z"/><path class="wh" d="M 719 404C 751 424 758 480 729 516C 741 482 739 440 711 412Z"/><path class="gl" d="M 717 482C 701 512 667 514 651 484C 647 500 661 516 683 516C 703 516 715 504 717 482Z"/>
<g id="pupil-r"></g><g id="highlight-r"><ellipse class="wh" cx="661" cy="432" rx="15" ry="18"/><circle class="wh" cx="650" cy="462" r="7"/></g>
<g id="eyelid-r"><path class="o k" d="M 683 392C 635 392 608 432 615 440L 753 440C 748 410 718 392 683 392Z"/></g></g>
<g id="eyes-happy-arc"><path class="ha" d="M388 488Q427 432 466 488"/><path class="ha" d="M646 488Q685 432 724 488"/></g><g id="eyes-sleep"><path class="ha" d="M388 468Q427 506 466 468"/><path class="ha" d="M646 468Q685 506 724 468"/></g>
<g id="tear-rim"></g>
<g id="nose"><path class="e" d="M525 497C528 482 548 480 562 480C582 480 598 485 600 500C600 520 580 530 562 530C542 530 524 515 525 497Z"/><ellipse class="wh" cx="553" cy="493" rx="11" ry="6"/></g>
</g>
</g>

<g id="sparkle"><g id="spark-1"><path class="g ol" style="stroke-width:7" transform="translate(150 300)" d="M0 -34Q6.8 -6.8 34 0Q6.8 6.8 0 34Q-6.8 6.8 -34 0Q-6.8 -6.8 0 -34Z"/></g><g id="spark-2"><path class="g ol" style="stroke-width:7" transform="translate(930 215)" d="M0 -28Q5.6 -5.6 28 0Q5.6 5.6 0 28Q-5.6 5.6 -28 0Q-5.6 -5.6 0 -28Z"/></g><g id="spark-3"><path class="g ol" style="stroke-width:7" transform="translate(165 520)" d="M0 -22Q4.4 -4.4 22 0Q4.4 4.4 0 22Q-4.4 4.4 -22 0Q-4.4 -4.4 0 -22Z"/></g></g>
<g id="heart"><path class="t ol" style="stroke-width:8" transform="translate(935 430)" d="M0 24C-40 -2 -26 -34 -10 -34C-4 -34 0 -28 0 -22C0 -28 4 -34 10 -34C26 -34 40 -2 0 24Z"/></g>
<g id="arcs-r"><path class="ln" d="M880 410Q915 460 880 510"/><path class="ln" d="M915 380Q975 460 915 540"/></g>
<g id="arcs-l"><path class="ln" d="M220 410Q185 460 220 510"/><path class="ln" d="M185 380Q125 460 185 540"/></g>
<g id="woof"><g transform="translate(925 345) rotate(-8)"><text text-anchor="middle" style="font:900 54px/1 system-ui,sans-serif;fill:#F67160;stroke:#6B2C0A;stroke-width:11;paint-order:stroke;stroke-linejoin:round">WOOF</text></g></g>
<circle id="impact" cx="700" cy="850" r="60" fill="none" stroke="#6B2C0A" stroke-width="10"/>
<g id="stamp"><g transform="translate(925 800) rotate(-10)"><path class="ol" fill="#F67160" style="stroke-width:10" d="M0 -80L64 -56V8Q64 56 0 90Q-64 56 -64 8V-56Z"/><path d="M0 -62L48 -44V6Q48 42 0 68Q-48 42 -48 6V-44Z" fill="none" stroke="#FBEDCD" stroke-width="5"/><path d="M-24 -14L24 34M24 -14L-24 34" stroke="#FBEDCD" stroke-width="15" fill="none"/></g></g>
<g id="z1"><text x="885" y="430" text-anchor="middle" style="font:900 52px/1 system-ui,sans-serif;fill:#FBEDCD;stroke:#6B2C0A;stroke-width:10;paint-order:stroke;stroke-linejoin:round">Z</text></g><g id="z2"><text x="885" y="430" text-anchor="middle" style="font:900 52px/1 system-ui,sans-serif;fill:#FBEDCD;stroke:#6B2C0A;stroke-width:10;paint-order:stroke;stroke-linejoin:round">Z</text></g><g id="z3"><text x="885" y="430" text-anchor="middle" style="font:900 52px/1 system-ui,sans-serif;fill:#FBEDCD;stroke:#6B2C0A;stroke-width:10;paint-order:stroke;stroke-linejoin:round">Z</text></g>
<g id="sweat"><g transform="translate(905 430)"><path d="M0 -30C14 -6 22 4 22 14A22 22 0 1 1 -22 14C-22 4 -14 -6 0 -30Z" fill="#8FD0F4" stroke="#6B2C0A" stroke-width="8"/><ellipse cx="-8" cy="12" rx="5" ry="8" fill="#F4F2EF" transform="rotate(15 -8 12)"/></g></g>
</svg>`;
const reduced=()=>matchMedia('(prefers-reduced-motion: reduce)').matches;

class HachiDog extends HTMLElement{
 static get observedAttributes(){return['state']}
 constructor(){super();this._tok=0;this._cur=null;this._anims=[];this._els={};this._started=false;
  this.attachShadow({mode:'open'}).innerHTML=`<style>${CSS}</style>${SVG}`;}
 connectedCallback(){const r=this.shadowRoot;this._rest={};this._ready=true;
  for(const id of IDS){const el=r.getElementById(id);this._els[id]=el;if(OPS.has(id))this._rest[id]=getComputedStyle(el).opacity;}
  if(!this.hasAttribute('state'))this.setAttribute('state','idle');else this._run(this._valid(this.getAttribute('state')));}
 disconnectedCallback(){this._ready=false;this._cur=null;this._tok++;this._anims.forEach(a=>a.cancel());this._anims=[];this._started=false;}
 _valid(s){return STATES[s]?s:'idle'}
 attributeChangedCallback(n,o,v){if(this._ready&&this.isConnected&&this._cur!==v&&o!==v)this._run(this._valid(v));}
 setDog(s){if(!STATES[s]){console.warn(`hachi-dog: unknown state "${s}"`);return}
  if(this.getAttribute('state')===s)this._run(s);else this.setAttribute('state',s);}
 _end(state,tok){if(tok!==this._tok)return;
  this.dispatchEvent(new CustomEvent('ended',{detail:{state},bubbles:true,composed:true}));this.setDog('idle');}
 async _run(state){
  const tok=++this._tok,def=STATES[state];this._cur=state;
  if(reduced()){this._anims.forEach(a=>a.cancel());this._anims=[];
   if(!def.loop)setTimeout(()=>this._end(state,tok),1600);return;}
  const snap={};
  for(const id of IDS){const cs=getComputedStyle(this._els[id]);snap[id]={t:cs.transform,o:cs.opacity};}
  this._anims.forEach(a=>a.cancel());
  const bridges=[],starts=[];
  for(const id of IDS){const el=this._els[id],p=def.parts[id],op=OPS.has(id);
   const to=p?{transform:p[0].transform}:{transform:tf()};
   if(op)to.opacity=p&&p[0].opacity!==undefined?p[0].opacity:this._rest[id];
   if(this._started){const from={transform:snap[id].t==='none'?tf():snap[id].t};if(op)from.opacity=snap[id].o;
    bridges.push(el.animate([from,to],{duration:BRIDGE,easing:SOFT,fill:'forwards'}));}
   if(p)starts.push([el,p]);}
  this._anims=bridges;
  if(bridges.length){await Promise.all(bridges.map(b=>b.finished.catch(()=>0)));if(tok!==this._tok)return;}
  const mains=starts.map(([el,p])=>el.animate(p,{duration:def.D,iterations:def.loop?Infinity:1,fill:'both'}));
  if(def.shake)mains.push(this.animate([[0,0,0],...def.shake,[def.D,0,0]].map(([t,x,y])=>({offset:t/def.D,transform:`translate(${x}px,${y}px)`})),{duration:def.D}));
  bridges.forEach(b=>b.cancel());this._anims=mains;this._started=true;
  if(!def.loop){await Promise.all(mains.map(m=>m.finished.catch(()=>0)));if(tok!==this._tok)return;
   if(def.hold){const hs=Object.entries(def.hold.parts).map(([id,f])=>this._els[id].animate(f,{duration:def.hold.D,iterations:Infinity,fill:'both'}));this._anims.push(...hs);return;}
   this._end(state,tok);}
 }
}
customElements.define('hachi-dog',HachiDog);
