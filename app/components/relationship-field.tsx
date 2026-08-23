"use client";
import { useEffect, useRef } from "react";
import type { NormalizedObservation } from "../../lib/threat-types";

interface FieldNode { id:string; type:"source"|"family"|"record"; label:string; x:number; y:number; vx:number; vy:number; radius:number; mass:number; color:string; record?:NormalizedObservation }
interface FieldEdge { from:number; to:number; phase:number }
interface View { x:number; y:number; scale:number }

const KIND_COLORS: Record<string,string> = { ipv4:"#e8ff4f", ipv6:"#c8f071", domain:"#70e6c4", url:"#72aef8", hash:"#d783bc", malware:"#f39a62", vulnerability:"#c8d4d4", infrastructure:"#d2dfe0" };

export function RelationshipField({ records, onSelect }: { records:NormalizedObservation[]; onSelect(record:NormalizedObservation):void }) {
  const canvasRef=useRef<HTMLCanvasElement>(null);
  const selectRef=useRef(onSelect);
  useEffect(()=>{selectRef.current=onSelect},[onSelect]);

  useEffect(()=>{
    const canvas=canvasRef.current;if(!canvas)return;
    const context=canvas.getContext("2d");if(!context)return;
    const compactField=window.matchMedia("(max-width: 600px)").matches;
    const field=createField(records.slice(0,compactField?70:120));
    const view:View={x:0,y:0,scale:1};
    let width=1,height=1,dpr=1,frame=0,hover=-1,drag=-1,panning=false,moved=false,lastX=0,lastY=0,lastWidth=0,lastHeight=0;
    const reduced=window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const resize=()=>{const box=canvas.getBoundingClientRect();dpr=Math.min(2,window.devicePixelRatio||1);width=Math.max(1,box.width);height=Math.max(1,box.height);canvas.width=Math.round(width*dpr);canvas.height=Math.round(height*dpr);context.setTransform(dpr,0,0,dpr,0,0);if(!lastWidth||Math.abs(width-lastWidth)>24||Math.abs(height-lastHeight)>24)fitField(field,width,height);lastWidth=width;lastHeight=height};
    const observer=new ResizeObserver(resize);observer.observe(canvas);resize();

    const point=(event:PointerEvent|WheelEvent)=>({x:(event.clientX-canvas.getBoundingClientRect().left-view.x)/view.scale,y:(event.clientY-canvas.getBoundingClientRect().top-view.y)/view.scale});
    const nearest=(x:number,y:number)=>{let found=-1,best=18/view.scale;field.nodes.forEach((node,index)=>{const distance=Math.hypot(node.x-x,node.y-y);if(distance<Math.max(best,node.radius+7)){best=distance;found=index}});return found};
    const down=(event:PointerEvent)=>{canvas.setPointerCapture(event.pointerId);const p=point(event);drag=nearest(p.x,p.y);panning=drag<0;moved=false;lastX=event.clientX;lastY=event.clientY};
    const move=(event:PointerEvent)=>{const dx=event.clientX-lastX,dy=event.clientY-lastY;if(Math.abs(dx)+Math.abs(dy)>2)moved=true;lastX=event.clientX;lastY=event.clientY;if(drag>=0){const p=point(event);const node=field.nodes[drag];node.x=p.x;node.y=p.y;node.vx=0;node.vy=0}else if(panning){view.x+=dx;view.y+=dy}else{const p=point(event);hover=nearest(p.x,p.y)}canvas.style.cursor=drag>=0?"grabbing":hover>=0?"pointer":panning?"grabbing":"grab"};
    const up=()=>{if(drag>=0&&!moved&&field.nodes[drag].record)selectRef.current(field.nodes[drag].record as NormalizedObservation);drag=-1;panning=false};
    const wheel=(event:WheelEvent)=>{event.preventDefault();const before=point(event);const next=Math.min(2.2,Math.max(.62,view.scale*Math.exp(-event.deltaY*.001)));view.x=event.clientX-canvas.getBoundingClientRect().left-before.x*next;view.y=event.clientY-canvas.getBoundingClientRect().top-before.y*next;view.scale=next};
    const keydown=(event:KeyboardEvent)=>{const step=event.shiftKey?42:18;if(event.key==="ArrowLeft")view.x+=step;else if(event.key==="ArrowRight")view.x-=step;else if(event.key==="ArrowUp")view.y+=step;else if(event.key==="ArrowDown")view.y-=step;else if(event.key==="+"||event.key==="=")view.scale=Math.min(2.2,view.scale*1.12);else if(event.key==="-")view.scale=Math.max(.62,view.scale/1.12);else if(event.key==="Home"){view.x=0;view.y=0;view.scale=1;fitField(field,width,height)}else if(event.key==="Enter"&&hover>=0&&field.nodes[hover].record)selectRef.current(field.nodes[hover].record as NormalizedObservation);else return;event.preventDefault()};
    canvas.addEventListener("pointerdown",down);canvas.addEventListener("pointermove",move);canvas.addEventListener("pointerup",up);canvas.addEventListener("pointercancel",up);canvas.addEventListener("wheel",wheel,{passive:false});canvas.addEventListener("keydown",keydown);

    const tick=(time:number)=>{frame=requestAnimationFrame(tick);if(!reduced)simulate(field,width,height,time,drag);draw(context,field,width,height,time,view,hover,reduced,dpr)};
    frame=requestAnimationFrame(tick);
    return()=>{cancelAnimationFrame(frame);observer.disconnect();canvas.removeEventListener("pointerdown",down);canvas.removeEventListener("pointermove",move);canvas.removeEventListener("pointerup",up);canvas.removeEventListener("pointercancel",up);canvas.removeEventListener("wheel",wheel);canvas.removeEventListener("keydown",keydown)};
  },[records]);

  return <div className="relationshipField interactiveField"><canvas ref={canvasRef} tabIndex={0} role="application" aria-label={`Interactive force-directed field of ${records.length} visible observations. Drag or use arrow keys to pan, plus and minus to zoom, and Home to reset.`}/>{records.length ? <><div className="fieldHelp"><span className="mobileFieldLimit">{Math.min(records.length,70)} OF {records.length} PLOTTED · </span>DRAG · PAN · ZOOM · TAP TO INSPECT</div><div className="graphLegend"><span><i className="source"/>SOURCE</span><span><i className="kind"/>OBSERVATION / TYPE COLOR</span><span><i className="family"/>FAMILY</span></div></> : <div className="emptyMap"><strong>NO SIGNAL IN WINDOW</strong><span>The field will form from validated source records.</span></div>}</div>;
}

function fitField(field:{nodes:FieldNode[]},width:number,height:number){
  if(!field.nodes.length||width<2||height<2)return;
  const left=width<560?58:76,right=width<560?58:76,top=48,bottom=70;
  const minX=Math.min(...field.nodes.map(node=>node.x)),maxX=Math.max(...field.nodes.map(node=>node.x));
  const minY=Math.min(...field.nodes.map(node=>node.y)),maxY=Math.max(...field.nodes.map(node=>node.y));
  const spanX=Math.max(1,maxX-minX),spanY=Math.max(1,maxY-minY);
  const scale=Math.min((width-left-right)/spanX,(height-top-bottom)/spanY,1);
  field.nodes.forEach(node=>{node.x=left+(node.x-minX)*scale;node.y=top+(node.y-minY)*scale;node.vx=0;node.vy=0});
}

function createField(records:NormalizedObservation[]): {nodes:FieldNode[];edges:FieldEdge[]} {
  const nodes:FieldNode[]=[],edges:FieldEdge[]=[];const indices=new Map<string,number>();
  const add=(node:Omit<FieldNode,"x"|"y"|"vx"|"vy">)=>{const existing=indices.get(node.id);if(existing!==undefined)return existing;const seed=hash(node.id);const index=nodes.length;nodes.push({...node,x:120+(seed%640),y:70+((seed>>>8)%330),vx:0,vy:0});indices.set(node.id,index);return index};
  const familyCounts=new Map<string,number>();records.forEach(record=>{if(record.malwareFamily)familyCounts.set(record.malwareFamily,(familyCounts.get(record.malwareFamily)??0)+1)});const families=new Set([...familyCounts].sort((a,b)=>b[1]-a[1]).slice(0,10).map(([name])=>name));
  records.forEach((record,index)=>{const source=add({id:`source:${record.source}`,type:"source",label:sourceLabel(record.source),radius:15,mass:5,color:"#e8ff4f"});const recordNode=add({id:`record:${record.id}`,type:"record",label:record.indicator??record.title??record.sourceRecordId??record.kind,radius:5.5,mass:1,color:KIND_COLORS[record.kind]??"#d2dfe0",record});edges.push({from:source,to:recordNode,phase:(index%17)/17});if(record.malwareFamily&&families.has(record.malwareFamily)){const family=add({id:`family:${record.malwareFamily}`,type:"family",label:record.malwareFamily,radius:10,mass:3,color:"#ffb23f"});edges.push({from:family,to:recordNode,phase:(index%23)/23})}});
  return {nodes,edges};
}

function simulate(field:{nodes:FieldNode[];edges:FieldEdge[]},width:number,height:number,time:number,drag:number){const nodes=field.nodes;for(let i=0;i<nodes.length;i++){for(let j=i+1;j<nodes.length;j++){const a=nodes[i],b=nodes[j],dx=b.x-a.x,dy=b.y-a.y,d2=Math.max(90,dx*dx+dy*dy),force=34/d2,fx=dx*force,fy=dy*force;a.vx-=fx/a.mass;a.vy-=fy/a.mass;b.vx+=fx/b.mass;b.vy+=fy/b.mass}}for(const edge of field.edges){const a=nodes[edge.from],b=nodes[edge.to],dx=b.x-a.x,dy=b.y-a.y,d=Math.max(1,Math.hypot(dx,dy)),target=a.type==="source"||b.type==="source"?105:72,force=(d-target)*.0009,fx=dx*force,fy=dy*force;a.vx+=fx/a.mass;a.vy+=fy/a.mass;b.vx-=fx/b.mass;b.vy-=fy/b.mass}nodes.forEach((node,index)=>{if(index===drag)return;const ambient=.0018/node.mass;node.vx+=(width/2-node.x)*.00008+Math.sin(time*.00035+index*1.7)*ambient;node.vy+=(height/2-node.y)*.00008+Math.cos(time*.00029+index*1.3)*ambient;node.vx*=.91;node.vy*=.91;node.x+=node.vx;node.y+=node.vy;const margin=node.type==="record"?24:58;node.x=Math.max(margin,Math.min(width-margin,node.x));node.y=Math.max(30,Math.min(height-64,node.y))})}

function draw(ctx:CanvasRenderingContext2D,field:{nodes:FieldNode[];edges:FieldEdge[]},width:number,height:number,time:number,view:View,hover:number,reduced:boolean,dpr:number){
  ctx.setTransform(1,0,0,1,0,0);
  ctx.clearRect(0,0,width*dpr,height*dpr);
  ctx.setTransform(dpr*view.scale,0,0,dpr*view.scale,dpr*view.x,dpr*view.y);
  ctx.lineCap="round";

  for(const edge of field.edges){
    const a=field.nodes[edge.from],b=field.nodes[edge.to];
    ctx.strokeStyle="rgba(207,222,218,.28)";
    ctx.lineWidth=.9;
    ctx.beginPath();
    ctx.moveTo(a.x,a.y);
    ctx.lineTo(b.x,b.y);
    ctx.stroke();
    if(!reduced){
      const progress=(time*.00011+edge.phase)%1;
      const x=a.x+(b.x-a.x)*progress,y=a.y+(b.y-a.y)*progress;
      ctx.fillStyle="#e8ff4f";
      ctx.shadowColor="#e8ff4f";
      ctx.shadowBlur=8;
      ctx.beginPath();
      ctx.arc(x,y,1.8,0,Math.PI*2);
      ctx.fill();
      ctx.shadowBlur=0;
    }
  }

  field.nodes.forEach((node,index)=>{
    const active=index===hover;
    const radius=node.radius+(active?2.5:0);
    ctx.globalAlpha=active?1:node.type==="record"?.94:1;
    ctx.fillStyle=node.color;
    ctx.shadowColor=node.color;
    ctx.shadowBlur=active?18:node.type==="record"?7:13;
    ctx.beginPath();
    ctx.arc(node.x,node.y,radius,0,Math.PI*2);
    ctx.fill();
    ctx.shadowBlur=0;
    ctx.strokeStyle=node.type==="record"?"rgba(5,7,7,.9)":"rgba(255,255,255,.72)";
    ctx.lineWidth=node.type==="record"?1.25:1.5;
    ctx.stroke();
    if(node.type!=="record"){
      ctx.globalAlpha=.3;
      ctx.strokeStyle=node.color;
      ctx.lineWidth=1;
      ctx.beginPath();
      ctx.arc(node.x,node.y,radius+5,0,Math.PI*2);
      ctx.stroke();
    }
    ctx.globalAlpha=1;
  });
  drawFieldLabels(ctx,field.nodes,hover,width,height);
}

function drawFieldLabels(ctx:CanvasRenderingContext2D,nodes:FieldNode[],hover:number,width:number,height:number){
  const occupied:{left:number;top:number;right:number;bottom:number}[]=[];
  const candidates=nodes.map((node,index)=>({node,index})).filter(({node,index})=>index===hover||node.type!=="record").sort((a,b)=>labelPriority(b.node,b.index===hover)-labelPriority(a.node,a.index===hover));
  for(const {node,index} of candidates){
    const active=index===hover;
    const text=short(node.label,active?30:node.type==="source"?18:15);
    const fontSize=active?10:node.type==="source"?9:8;
    ctx.font=`700 ${fontSize}px ui-monospace, monospace`;
    const labelWidth=Math.ceil(ctx.measureText(text).width)+12,labelHeight=fontSize+8;
    const positions=[
      {x:node.x-labelWidth/2,y:node.y+node.radius+7},
      {x:node.x-labelWidth/2,y:node.y-node.radius-labelHeight-7},
      {x:node.x+node.radius+8,y:node.y-labelHeight/2},
      {x:node.x-node.radius-labelWidth-8,y:node.y-labelHeight/2},
    ];
    const chosen=positions.map(position=>({left:Math.max(4,Math.min(width-labelWidth-4,position.x)),top:Math.max(4,Math.min(height-labelHeight-46,position.y))})).map(position=>({...position,right:position.left+labelWidth,bottom:position.top+labelHeight})).find(box=>!occupied.some(other=>boxesOverlap(box,other)));
    if(!chosen&&!active)continue;
    const box=chosen??{left:Math.max(4,Math.min(width-labelWidth-4,node.x-labelWidth/2)),top:Math.max(4,Math.min(height-labelHeight-46,node.y+node.radius+7)),right:0,bottom:0};
    if(!chosen){box.right=box.left+labelWidth;box.bottom=box.top+labelHeight}
    occupied.push(box);
    ctx.globalAlpha=active?1:.92;
    ctx.fillStyle="rgba(5,6,5,.82)";
    ctx.fillRect(box.left,box.top,labelWidth,labelHeight);
    ctx.strokeStyle=active?node.color:"rgba(117,112,95,.45)";
    ctx.lineWidth=.7;
    ctx.strokeRect(box.left+.5,box.top+.5,labelWidth-1,labelHeight-1);
    ctx.fillStyle=active?"#fff8df":"#e8e3d3";
    ctx.textAlign="center";
    ctx.textBaseline="middle";
    ctx.fillText(text,box.left+labelWidth/2,box.top+labelHeight/2+.5);
    ctx.globalAlpha=1;
  }
}

function labelPriority(node:FieldNode,active:boolean){return active?4:node.type==="source"?3:node.type==="family"?2:1}
function boxesOverlap(a:{left:number;top:number;right:number;bottom:number},b:{left:number;top:number;right:number;bottom:number}){return a.left<b.right+4&&a.right+4>b.left&&a.top<b.bottom+3&&a.bottom+3>b.top}
function sourceLabel(value:string){return value.replace("cisa-kev","CISA KEV").replace("malwarebazaar","MALWARE BAZAAR").toUpperCase()}
function short(value:string,max:number){return value.length>max?`${value.slice(0,max-1)}…`:value}
function hash(value:string){let result=2166136261;for(let i=0;i<value.length;i++){result^=value.charCodeAt(i);result=Math.imul(result,16777619)}return result>>>0}
