import type { NormalizedClipboardItem } from '../shared/types';
import { base64, fromBase64 } from '../crypto/encoding';
import { contentHash, validateItem } from '../crypto/protocol';

let timer:number|undefined;
let reading=false;
let lastHash='';
let lastError='';
let interval=1000;
const clipboardText=document.querySelector<HTMLTextAreaElement>('#clipboard-text')!;

const clipboardEvents=navigator.clipboard as (Clipboard&{addEventListener?:(type:string,listener:()=>void)=>void})|undefined;
clipboardEvents?.addEventListener?.('clipboardchange',()=>{if(timer)clearTimeout(timer);timer=window.setTimeout(()=>void poll(),200);});

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
  try{const item=await readClipboard();const recovered=lastError!=='';lastError='';if(item){const hash=await contentHash(item);if(hash!==lastHash){lastHash=hash;await chrome.runtime.sendMessage({type:'clipboard-observed',item:serialize(item),hash});}else if(recovered)await chrome.runtime.sendMessage({type:'clipboard-ready'});}else if(recovered)await chrome.runtime.sendMessage({type:'clipboard-ready'});}catch(error){const message=error instanceof Error?error.message:String(error);if(message!==lastError){lastError=message;await chrome.runtime.sendMessage({type:'clipboard-error',message});}}finally{reading=false;start();}
}

async function readClipboard():Promise<NormalizedClipboardItem|null>{
  let pasted:Promise<NormalizedClipboardItem|null>|undefined;
  const onPaste=(event:ClipboardEvent)=>{event.preventDefault();pasted=readPastedData(event.clipboardData);};
  clipboardText.value='';clipboardText.focus();clipboardText.select();clipboardText.addEventListener('paste',onPaste,{once:true});
  const accepted=document.execCommand('paste');
  clipboardText.removeEventListener('paste',onPaste);
  const fallbackText=clipboardText.value;clipboardText.value='';
  if(pasted)return pasted;
  if(!accepted)throw new Error('Chrome blocked background clipboard access. Reload ClipMesh from chrome://extensions.');
  if(fallbackText!=='')return textItem(fallbackText);
  return null;
}

async function writeClipboard(item:NormalizedClipboardItem):Promise<void>{
  validateItem(item);
  if(item.type!=='text/plain')throw new Error('Chrome requires a focused ClipMesh page to copy PNG images. Open ClipMesh and select Copy again.');
  clipboardText.value=new TextDecoder().decode(item.bytes);clipboardText.focus();clipboardText.select();
  try{if(!document.execCommand('copy'))throw new Error('Chrome blocked background clipboard writes. Reload ClipMesh from chrome://extensions.');}finally{clipboardText.value='';}
  lastHash=await contentHash(item);
}

async function readPastedData(data:DataTransfer|null):Promise<NormalizedClipboardItem|null>{
  if(!data)return null;
  const image=Array.from(data.items).find((entry)=>entry.kind==='file'&&entry.type.startsWith('image/'))?.getAsFile();
  if(image)return imageItem(image);
  if(Array.from(data.types).includes('text/plain'))return textItem(data.getData('text/plain'));
  if(data.types.length>0)throw new Error('Unsupported clipboard content');
  return null;
}

async function imageItem(source:Blob):Promise<NormalizedClipboardItem>{
  let bitmap:ImageBitmap;
  try{bitmap=await createImageBitmap(source);}catch{throw new Error('Malformed clipboard image');}
  try{const canvas=new OffscreenCanvas(bitmap.width,bitmap.height);const context=canvas.getContext('2d');if(!context)throw new Error('Unable to normalize clipboard image');context.drawImage(bitmap,0,0);const png=await canvas.convertToBlob({type:'image/png'});const item:NormalizedClipboardItem={type:'image/png',bytes:new Uint8Array(await png.arrayBuffer()),width:bitmap.width,height:bitmap.height};validateItem(item);return item;}finally{bitmap.close();}
}

function textItem(text:string):NormalizedClipboardItem{const item:NormalizedClipboardItem={type:'text/plain',bytes:new TextEncoder().encode(text)};validateItem(item);return item;}

function serialize(item:NormalizedClipboardItem):SerializedItem{return{type:item.type,bytes:base64(item.bytes),...(item.type==='image/png'?{width:item.width,height:item.height}:{})};}
function deserialize(item:SerializedItem):NormalizedClipboardItem{return item.type==='text/plain'?{type:'text/plain',bytes:fromBase64(item.bytes)}:{type:'image/png',bytes:fromBase64(item.bytes),width:item.width??0,height:item.height??0};}
