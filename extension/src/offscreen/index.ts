import type { NormalizedClipboardItem } from '../shared/types';
import { base64, buffer, fromBase64 } from '../crypto/encoding';
import { contentHash, validateItem } from '../crypto/protocol';

let timer:number|undefined;
let reading=false;
let lastHash='';
let interval=1000;

const clipboardEvents=navigator.clipboard as Clipboard&{addEventListener?:(type:string,listener:()=>void)=>void};
clipboardEvents.addEventListener?.('clipboardchange',()=>{if(timer)clearTimeout(timer);timer=window.setTimeout(()=>void poll(),200);});

chrome.runtime.onMessage.addListener((message:unknown,_sender,sendResponse)=>{
  if(!message||typeof message!=='object'||!('target'in message)||(message as {target?:string}).target!=='offscreen'||!('command'in message)||typeof(message as {command?:unknown}).command!=='string')return;
  void handle(message as unknown as {command:string;item?:SerializedItem;connected?:boolean}).then(sendResponse,(error)=>sendResponse({error:error instanceof Error?error.message:String(error)}));
  return true;
});

interface SerializedItem{type:'text/plain'|'image/png';bytes:string;width?:number;height?:number}

async function handle(message:{command:string;item?:SerializedItem;connected?:boolean}):Promise<unknown>{
  if(message.command==='start'){start();return{ok:true};}
  if(message.command==='connection'){interval=message.connected?1000:5000;start();return{ok:true};}
  if(message.command==='read'){const item=await readClipboard();return item?serialize(item):null;}
  if(message.command==='write'){if(!message.item)throw new Error('Missing clipboard item');await writeClipboard(deserialize(message.item));return{ok:true};}
  throw new Error('Unknown offscreen command');
}

function start():void{if(timer)clearTimeout(timer);timer=window.setTimeout(()=>void poll(),interval);}
async function poll():Promise<void>{
  if(reading){start();return;}reading=true;
  try{const item=await readClipboard();if(item){const hash=await contentHash(item);if(hash!==lastHash){lastHash=hash;await chrome.runtime.sendMessage({type:'clipboard-observed',item:serialize(item),hash});}}}catch(error){await chrome.runtime.sendMessage({type:'clipboard-error',message:error instanceof Error?error.message:String(error)});}finally{reading=false;start();}
}

async function readClipboard():Promise<NormalizedClipboardItem|null>{
  const entries=await navigator.clipboard.read();
  for(const entry of entries){
    const imageType=entry.types.find((type)=>type.startsWith('image/'));
    if(imageType){const source=await entry.getType(imageType);const bitmap=await createImageBitmap(source);try{const canvas=new OffscreenCanvas(bitmap.width,bitmap.height);canvas.getContext('2d')?.drawImage(bitmap,0,0);const png=await canvas.convertToBlob({type:'image/png'});const item:NormalizedClipboardItem={type:'image/png',bytes:new Uint8Array(await png.arrayBuffer()),width:bitmap.width,height:bitmap.height};validateItem(item);return item;}finally{bitmap.close();}}
    if(entry.types.includes('text/plain')){const text=await(await entry.getType('text/plain')).text();const item:NormalizedClipboardItem={type:'text/plain',bytes:new TextEncoder().encode(text)};validateItem(item);return item;}
  }
  if(entries.length>0)throw new Error('Unsupported clipboard content');
  return null;
}

async function writeClipboard(item:NormalizedClipboardItem):Promise<void>{
  validateItem(item);
  if(item.type==='text/plain')await navigator.clipboard.writeText(new TextDecoder().decode(item.bytes));
  else {const blob=new Blob([buffer(item.bytes)],{type:'image/png'});let bitmap:ImageBitmap;try{bitmap=await createImageBitmap(blob);}catch{throw new Error('Malformed PNG');}try{if(bitmap.width!==item.width||bitmap.height!==item.height)throw new Error('PNG dimensions do not match');}finally{bitmap.close();}await navigator.clipboard.write([new ClipboardItem({'image/png':blob})]);}
  lastHash=await contentHash(item);
}

function serialize(item:NormalizedClipboardItem):SerializedItem{return{type:item.type,bytes:base64(item.bytes),...(item.type==='image/png'?{width:item.width,height:item.height}:{})};}
function deserialize(item:SerializedItem):NormalizedClipboardItem{return item.type==='text/plain'?{type:'text/plain',bytes:fromBase64(item.bytes)}:{type:'image/png',bytes:fromBase64(item.bytes),width:item.width??0,height:item.height??0};}
