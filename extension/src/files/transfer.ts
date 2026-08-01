import { createSHA256 } from 'hash-wasm';
import { ChromeStorageAdapter } from '../adapters/chrome/storage';
import { base64, buffer, randomBytes, uuidv7 } from '../crypto/encoding';
import { decryptFileChunk, encryptFileChunk, fileChunkCount, validateFileManifest } from '../crypto/protocol';
import { ApiClient } from '../network/api';
import { FILE_CHUNK_BYTES, FILE_MANIFEST_CONTENT_TYPE, type FileManifestItem, type JoinedChannel, type PauseState, type RouteSelection, type ServerConfig, type UUID } from '../shared/types';

const storage=new ChromeStorageAdapter();

export interface FileProgress {phase:'hashing'|'uploading'|'publishing'|'downloading'|'complete';completed:number;total:number;channel?:string}

export async function uploadBrowserFile(file:File,onProgress:(progress:FileProgress)=>void=()=>undefined):Promise<FileManifestItem[]>{
  const [config,channels,routes,pause]=await Promise.all([storage.get<ServerConfig>('serverConfig'),storage.get<JoinedChannel[]>('joinedChannels'),storage.get<RouteSelection[]>('routes'),storage.get<PauseState>('pause')]);
  if(!config)throw new Error('Pair ClipMesh with a server first');
  if(pause?.sending)throw new Error('Sending is paused');
  const targets=(routes??[]).filter((route)=>route.sendEnabled).map((route)=>route.channelId);
  if(targets.length===0)throw new Error('Enable a Send route first');
  const api=new ApiClient(config);const info=await ApiClient.info(config.url);const support=info.file_transfer;
  if(!support)throw new Error('This server does not support file transfer');
  if(support.chunk_bytes!==FILE_CHUNK_BYTES)throw new Error('Server uses an unsupported file chunk size');
  if(file.size>support.max_file_bytes)throw new Error(`File is ${formatBytes(file.size)}; this server allows at most ${formatBytes(support.max_file_bytes)}`);
  const sha256=await hashFile(file,onProgress);
  const results:FileManifestItem[]=[];
  for(const channelId of targets){
    const channel=channels?.find((value)=>value.id===channelId);if(!channel)continue;
    const fileId=uuidv7(),chunkCount=fileChunkCount(file.size),noncePrefix=base64(randomBytes(8));
    const manifest:FileManifestItem={type:FILE_MANIFEST_CONTENT_TYPE,fileId,filename:file.name,mediaType:file.type||'application/octet-stream',size:file.size,chunkSize:FILE_CHUNK_BYTES,chunkCount,noncePrefix,sha256,expiresAt:1};
    validateFileManifest(manifest);
    const created=await api.createFile(channelId,{file_id:fileId,plaintext_size:file.size,chunk_size:FILE_CHUNK_BYTES,chunk_count:chunkCount});
    try{
      for(let index=created.next_chunk;index<chunkCount;index++){
        const start=index*FILE_CHUNK_BYTES,end=Math.min(file.size,start+FILE_CHUNK_BYTES);const plaintext=new Uint8Array(await file.slice(start,end).arrayBuffer());
        const ciphertext=await encryptFileChunk(channel.secret,config.instanceId,manifest,index,plaintext);await api.uploadFileChunk(fileId,index,ciphertext);onProgress({phase:'uploading',completed:index+1,total:chunkCount,channel:channel.name});
      }
      const completed=await api.completeFile(fileId);manifest.expiresAt=completed.expires_at;onProgress({phase:'publishing',completed:results.length,total:targets.length,channel:channel.name});
      const response=await chrome.runtime.sendMessage({type:'publish-file-manifest',item:manifest,channelId});if(!response?.ok)throw new Error(response?.error??'Could not publish file manifest');results.push(manifest);
    }catch(error){await api.deleteFile(fileId).catch(()=>undefined);throw error;}
  }
  if(results.length===0)throw new Error('No joined Send route was available');
  onProgress({phase:'complete',completed:results.length,total:results.length});return results;
}

export async function downloadBrowserFile(manifest:FileManifestItem,channelId:UUID,onProgress:(progress:FileProgress)=>void=()=>undefined):Promise<void>{
  validateFileManifest(manifest);const picker=(globalThis as typeof globalThis&{showSaveFilePicker?:(options:{suggestedName:string})=>Promise<{createWritable:()=>Promise<{write:(data:ArrayBuffer)=>Promise<void>;close:()=>Promise<void>;abort:()=>Promise<void>}>}>}).showSaveFilePicker;const handle=picker?await picker({suggestedName:manifest.filename}):undefined;const [config,channels]=await Promise.all([storage.get<ServerConfig>('serverConfig'),storage.get<JoinedChannel[]>('joinedChannels')]);if(!config)throw new Error('Pair ClipMesh with a server first');const channel=channels?.find((value)=>value.id===channelId);if(!channel)throw new Error('Rejoin this channel to download the file');
  const api=new ApiClient(config),remote=await api.fileMetadata(manifest.fileId);if(remote.channel_id!==channelId||remote.plaintext_size!==manifest.size||remote.chunk_size!==manifest.chunkSize||remote.chunk_count!==manifest.chunkCount||remote.status!=='ready')throw new Error('Server returned mismatched file metadata');
  let writable:Awaited<ReturnType<Awaited<ReturnType<NonNullable<typeof picker>>>['createWritable']>>|undefined;const parts:ArrayBuffer[]=[];
  if(handle)writable=await handle.createWritable();else if(manifest.size>256*1024*1024)throw new Error('This browser cannot stream downloads to disk; use the ClipMesh CLI for files over 256 MiB');
  const hasher=await createSHA256();hasher.init();
  try{for(let index=0;index<manifest.chunkCount;index++){const ciphertext=await api.fileChunk(manifest.fileId,index,manifest.chunkSize+16);const plaintext=await decryptFileChunk(channel.secret,config.instanceId,manifest,index,ciphertext);hasher.update(plaintext);const data=buffer(plaintext);if(writable)await writable.write(data);else parts.push(data);onProgress({phase:'downloading',completed:index+1,total:manifest.chunkCount,channel:channel.name});}if(base64(hasher.digest('binary'))!==manifest.sha256)throw new Error('Downloaded file hash does not match its encrypted manifest');if(writable)await writable.close();else saveBlob(new Blob(parts,{type:manifest.mediaType}),manifest.filename);}catch(error){await writable?.abort().catch(()=>undefined);throw error;}onProgress({phase:'complete',completed:manifest.chunkCount,total:manifest.chunkCount,channel:channel.name});
}

async function hashFile(file:File,onProgress:(progress:FileProgress)=>void):Promise<string>{const hasher=await createSHA256();hasher.init();const chunks=fileChunkCount(file.size);for(let index=0;index<chunks;index++){const start=index*FILE_CHUNK_BYTES,end=Math.min(file.size,start+FILE_CHUNK_BYTES);hasher.update(new Uint8Array(await file.slice(start,end).arrayBuffer()));onProgress({phase:'hashing',completed:index+1,total:chunks});}return base64(hasher.digest('binary'));}
function saveBlob(blob:Blob,filename:string):void{const url=URL.createObjectURL(blob);const anchor=document.createElement('a');anchor.href=url;anchor.download=filename;anchor.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}
export function formatBytes(value:number):string{if(value<1024)return`${value} B`;const units=['KiB','MiB','GiB','TiB'];let amount=value/1024,index=0;while(amount>=1024&&index<units.length-1){amount/=1024;index++;}return`${amount.toFixed(amount>=10?1:2)} ${units[index]}`;}
