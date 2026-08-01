import { buffer, fromBase64 } from '../crypto/encoding';

interface SerializedClipboardItem {type:'text/plain'|'image/png';bytes:string;width?:number;height?:number}

export function installFocusedClipboardWriter():void{
  chrome.runtime.onMessage.addListener((message:unknown,_sender,sendResponse)=>{
    if(!isWriteRequest(message)||!document.hasFocus())return;
    void writeClipboard(message.item).then(()=>sendResponse({ok:true}),(error)=>sendResponse({ok:false,error:error instanceof Error?error.message:String(error)}));
    return true;
  });
}

function isWriteRequest(message:unknown):message is {target:'focused-extension';command:'write';item:SerializedClipboardItem}{
  return !!message&&typeof message==='object'&&'target'in message&&message.target==='focused-extension'&&'command'in message&&message.command==='write'&&'item'in message&&!!message.item&&typeof message.item==='object';
}

async function writeClipboard(item:SerializedClipboardItem):Promise<void>{
  if(item.type==='text/plain'){
    await navigator.clipboard.writeText(new TextDecoder().decode(fromBase64(item.bytes)));
    return;
  }
  if(item.type!=='image/png')throw new Error('Unsupported clipboard content');
  const blob=new Blob([buffer(fromBase64(item.bytes))],{type:'image/png'});
  let bitmap:ImageBitmap;
  try{bitmap=await createImageBitmap(blob);}catch{throw new Error('Malformed PNG');}
  try{
    if(bitmap.width!==item.width||bitmap.height!==item.height)throw new Error('PNG dimensions do not match');
  }finally{bitmap.close();}
  await navigator.clipboard.write([new ClipboardItem({'image/png':blob})]);
}
