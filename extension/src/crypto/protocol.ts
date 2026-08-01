import { argon2id } from 'hash-wasm';
import { FILE_CHUNK_BYTES, FILE_MANIFEST_CONTENT_TYPE, type ChannelSecret, type EncryptedEnvelope, type FileManifestItem, type ItemMetadata, type KdfParameters, type MembershipPublicKey, type TransferItem, type UUID, type WrappedSecret } from '../shared/types';
import { base64, buffer, concat, decodeUtf8, fromBase64, i64, randomBytes, u16, u32, u64, utf8, uuidBytes, uuidFromBytes, uuidv7 } from './encoding';

const WRAP_INFO = utf8('clipboard-sync/channel-wrap-key/v1');
const PASSWORD_CHECK_INFO = utf8('clipboard-sync/channel-password-check-key/v1');
const PASSWORD_CHECK_LABEL = utf8('clipboard-sync/password-check/v1\0');
const ITEM_ROOT_INFO = utf8('clipboard-sync/channel-item-root/v1');
const HISTORY_ROOT_INFO = utf8('clipboard-sync/channel-history-root/v1');
const ITEM_KEY_INFO = utf8('clipboard-sync/item-key/v1\0');
const FILE_ROOT_INFO = utf8('clipboard-sync/channel-file-root/v1');
const FILE_KEY_INFO = utf8('clipboard-sync/file-key/v1\0');
const FILE_CHUNK_AAD_LABEL = utf8('clipboard-sync/file-chunk-aad/v1\0');
const WRAP_AAD_LABEL = utf8('clipboard-sync/channel-wrap-aad/v1\0');
const ITEM_AAD_LABEL = utf8('clipboard-sync/item-aad/v1\0');
const JOIN_LABEL = utf8('clipboard-sync/channel-join/v1\0');

export interface ChannelMaterial {
  channelId: UUID;
  cryptoVersion: 1;
  passwordKdf: KdfParameters;
  wrappedSecret: WrappedSecret;
  membershipPublicKey: MembershipPublicKey;
  secret: ChannelSecret;
}

export async function createChannelMaterial(password: string, channelId = crypto.randomUUID()): Promise<ChannelMaterial> {
  const salt = randomBytes(16);
  const kdf: KdfParameters = { name:'argon2id', salt:base64(salt), memory_kib:65_536, iterations:3, parallelism:4, output_bytes:32 };
  const rootKey = randomBytes(32);
  const membership = await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'}, true, ['sign','verify']);
  const privateKey = new Uint8Array(await crypto.subtle.exportKey('pkcs8',membership.privateKey));
  const publicKey = new Uint8Array(await crypto.subtle.exportKey('spki',membership.publicKey));
  const secret:ChannelSecret = {version:1,channelId,rootKey:base64(rootKey),membershipPrivateKey:base64(privateKey),membershipPublicKey:base64(publicKey),cryptoVersion:1};
  const wrappedSecret = await wrapChannelSecret(password,kdf,channelId,secret);
  return {channelId,cryptoVersion:1,passwordKdf:kdf,wrappedSecret,membershipPublicKey:{algorithm:'ecdsa-p256-sha256',spki:base64(publicKey)},secret};
}

export async function wrapChannelSecret(password:string,kdf:KdfParameters,channelId:UUID,secret:ChannelSecret):Promise<WrappedSecret>{
  validateKdf(kdf);
  const {wrapKey,checkKey} = await derivePasswordKeys(password,kdf);
  const nonce=randomBytes(12);
  const check=await passwordCheck(checkKey,channelId);
  const plaintext=encodeSecret(fromBase64(secret.rootKey),fromBase64(secret.membershipPrivateKey),check);
  const aad=wrapAad(channelId,kdf,fromBase64(secret.membershipPublicKey));
  const key=await crypto.subtle.importKey('raw',buffer(wrapKey),'AES-GCM',false,['encrypt']);
  const ciphertext=await crypto.subtle.encrypt({name:'AES-GCM',iv:buffer(nonce),additionalData:buffer(aad),tagLength:128},key,buffer(plaintext));
  return {algorithm:'aes-256-gcm',nonce:base64(nonce),ciphertext:base64(new Uint8Array(ciphertext))};
}

export async function unwrapChannelSecret(password:string,channelId:UUID,kdf:KdfParameters,wrapped:WrappedSecret,membershipPublicSpki:string):Promise<ChannelSecret>{
  validateKdf(kdf);
  if(wrapped.algorithm!=='aes-256-gcm')throw new Error('Unsupported channel wrapping algorithm');
  const {wrapKey,checkKey}=await derivePasswordKeys(password,kdf);
  const publicKey=fromBase64(membershipPublicSpki);
  const aad=wrapAad(channelId,kdf,publicKey);
  const key=await crypto.subtle.importKey('raw',buffer(wrapKey),'AES-GCM',false,['decrypt']);
  let plaintext:ArrayBuffer;
  try{plaintext=await crypto.subtle.decrypt({name:'AES-GCM',iv:buffer(fromBase64(wrapped.nonce)),additionalData:buffer(aad),tagLength:128},key,buffer(fromBase64(wrapped.ciphertext)));}
  catch{throw new Error('Incorrect password or corrupted channel data');}
  const decoded=decodeSecret(new Uint8Array(plaintext));
  const expectedCheck=await passwordCheck(checkKey,channelId);
  if(!constantTimeEqual(decoded.passwordCheck,expectedCheck))throw new Error('Incorrect password or corrupted channel data');
  const privateKey=await crypto.subtle.importKey('pkcs8',buffer(decoded.privateKey),{name:'ECDSA',namedCurve:'P-256'},true,['sign']);
  const probe=utf8('ClipMesh membership key check');
  const signature=await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},privateKey,buffer(probe));
  const verifying=await crypto.subtle.importKey('spki',buffer(publicKey),{name:'ECDSA',namedCurve:'P-256'},false,['verify']);
  if(!await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},verifying,signature,buffer(probe)))throw new Error('Channel membership key does not match');
  return {version:1,channelId,rootKey:base64(decoded.rootKey),membershipPrivateKey:base64(decoded.privateKey),membershipPublicKey:membershipPublicSpki,cryptoVersion:1};
}

export async function signJoinChallenge(secret:ChannelSecret,serverId:UUID,deviceId:UUID,challengeId:UUID,challengeRandom:string,expiresAt:number):Promise<string>{
  const message=buildJoinMessage(serverId,secret.channelId,deviceId,challengeId,fromBase64(challengeRandom),expiresAt);
  const key=await crypto.subtle.importKey('pkcs8',buffer(fromBase64(secret.membershipPrivateKey)),{name:'ECDSA',namedCurve:'P-256'},false,['sign']);
  return base64(new Uint8Array(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},key,buffer(message))));
}

export async function encryptItem(secret:ChannelSecret,serverId:UUID,originDeviceId:UUID,item:TransferItem,createdAt=new Date().toISOString()):Promise<EncryptedEnvelope>{
  validateItem(item);
  const itemId=uuidv7();
  const key=await deriveItemKey(secret,itemId);
  const nonce=randomBytes(12);
  const plaintext=encodeClipboardPayload(item);
  const aad=buildItemAad(serverId,secret.channelId,itemId,originDeviceId,item.type,createdAt);
  const aes=await crypto.subtle.importKey('raw',buffer(key),'AES-GCM',false,['encrypt']);
  const ciphertext=new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv:buffer(nonce),additionalData:buffer(aad),tagLength:128},aes,buffer(plaintext)));
  return {metadata:{id:itemId,channel_id:secret.channelId,origin_device_id:originDeviceId,crypto_version:1,content_type:item.type,ciphertext_size:ciphertext.length,plaintext_size:item.type===FILE_MANIFEST_CONTENT_TYPE?plaintext.length:item.bytes.length,...(item.type==='image/png'?{image_width:item.width,image_height:item.height}:{}),...(item.type===FILE_MANIFEST_CONTENT_TYPE?{file_id:item.fileId}:{}),nonce:base64(nonce),created_at_client:createdAt},ciphertext};
}

export async function decryptItem(secret:ChannelSecret,serverId:UUID,metadata:ItemMetadata,ciphertext:Uint8Array):Promise<TransferItem>{
  if(metadata.crypto_version!==1||metadata.channel_id!==secret.channelId||ciphertext.length!==metadata.ciphertext_size)throw new Error('Unsupported or inconsistent envelope');
  const key=await deriveItemKey(secret,metadata.id);
  const aad=buildItemAad(serverId,metadata.channel_id,metadata.id,metadata.origin_device_id,metadata.content_type,metadata.created_at_client??'');
  const aes=await crypto.subtle.importKey('raw',buffer(key),'AES-GCM',false,['decrypt']);
  let plaintext:ArrayBuffer;
  try{plaintext=await crypto.subtle.decrypt({name:'AES-GCM',iv:buffer(fromBase64(metadata.nonce)),additionalData:buffer(aad),tagLength:128},aes,buffer(ciphertext));}catch{throw new Error('Clipboard envelope authentication failed');}
  const item=decodeItem(new Uint8Array(plaintext)); validateItem(item);
  const plaintextSize=item.type===FILE_MANIFEST_CONTENT_TYPE?plaintext.byteLength:item.bytes.length;
  if(item.type!==metadata.content_type||plaintextSize!==metadata.plaintext_size||(item.type==='image/png'&&(item.width!==metadata.image_width||item.height!==metadata.image_height)))throw new Error('Authenticated item metadata mismatch');
  return item;
}

export async function contentHash(item:TransferItem):Promise<string>{
  const material=item.type===FILE_MANIFEST_CONTENT_TYPE?concat(uuidBytes(item.fileId),utf8(item.filename),utf8(item.sha256)):item.bytes;
  const kind=item.type==='text/plain'?1:item.type==='image/png'?2:3;
  const digest=await crypto.subtle.digest('SHA-256',buffer(concat(Uint8Array.of(kind),material)));
  return base64(new Uint8Array(digest));
}

async function derivePasswordMaster(password:string,kdf:KdfParameters):Promise<Uint8Array>{return argon2id({password:password===''?Uint8Array.of(0xff):utf8(password),salt:fromBase64(kdf.salt),memorySize:kdf.memory_kib,iterations:kdf.iterations,parallelism:kdf.parallelism,hashLength:kdf.output_bytes,outputType:'binary'});}
async function derivePasswordKeys(password:string,kdf:KdfParameters):Promise<{wrapKey:Uint8Array;checkKey:Uint8Array}>{const master=await derivePasswordMaster(password,kdf);const [wrapKey,checkKey]=await Promise.all([hkdf(master,new Uint8Array(),WRAP_INFO),hkdf(master,new Uint8Array(),PASSWORD_CHECK_INFO)]);return{wrapKey,checkKey};}
async function passwordCheck(key:Uint8Array,channelId:UUID):Promise<Uint8Array>{const hmac=await crypto.subtle.importKey('raw',buffer(key),{name:'HMAC',hash:'SHA-256'},false,['sign']);return new Uint8Array(await crypto.subtle.sign('HMAC',hmac,buffer(concat(PASSWORD_CHECK_LABEL,uuidBytes(channelId)))));}
async function hkdf(input:Uint8Array,salt:Uint8Array,info:Uint8Array):Promise<Uint8Array>{const key=await crypto.subtle.importKey('raw',buffer(input),'HKDF',false,['deriveBits']);return new Uint8Array(await crypto.subtle.deriveBits({name:'HKDF',hash:'SHA-256',salt:buffer(salt),info:buffer(info)},key,256));}
export async function deriveItemKey(secret:ChannelSecret,itemId:UUID):Promise<Uint8Array>{const {itemRoot}=await deriveChannelRoots(secret);return hkdf(itemRoot,uuidBytes(secret.channelId),concat(ITEM_KEY_INFO,uuidBytes(itemId)));}
export async function deriveFileKey(secret:ChannelSecret,fileId:UUID):Promise<Uint8Array>{const fileRoot=await hkdf(fromBase64(secret.rootKey),new Uint8Array(),FILE_ROOT_INFO);return hkdf(fileRoot,uuidBytes(secret.channelId),concat(FILE_KEY_INFO,uuidBytes(fileId)));}
export async function deriveChannelRoots(secret:ChannelSecret):Promise<{itemRoot:Uint8Array;historyRoot:Uint8Array}>{const key=fromBase64(secret.rootKey);const [itemRoot,historyRoot]=await Promise.all([hkdf(key,new Uint8Array(),ITEM_ROOT_INFO),hkdf(key,new Uint8Array(),HISTORY_ROOT_INFO)]);return{itemRoot,historyRoot};}

function wrapAad(channelId:UUID,kdf:KdfParameters,publicKey:Uint8Array):Uint8Array{const name=utf8(kdf.name);const salt=fromBase64(kdf.salt);return concat(WRAP_AAD_LABEL,u16(1),uuidBytes(channelId),Uint8Array.of(name.length),name,u32(kdf.memory_kib),u32(kdf.iterations),u32(kdf.parallelism),u16(kdf.output_bytes),u16(salt.length),salt,u16(publicKey.length),publicKey);}
export function buildJoinMessage(serverId:UUID,channelId:UUID,deviceId:UUID,challengeId:UUID,random:Uint8Array,expiresAt:number):Uint8Array{if(random.length!==32)throw new Error('Join challenge must be 32 bytes');return concat(JOIN_LABEL,uuidBytes(serverId),uuidBytes(channelId),uuidBytes(deviceId),uuidBytes(challengeId),random,i64(expiresAt));}
export function buildItemAad(serverId:UUID,channelId:UUID,itemId:UUID,deviceId:UUID,type:string,createdAt:string):Uint8Array{const timestamp=utf8(createdAt);const kind=type==='text/plain'?1:type==='image/png'?2:type===FILE_MANIFEST_CONTENT_TYPE?3:0;return concat(ITEM_AAD_LABEL,u16(1),uuidBytes(serverId),uuidBytes(channelId),uuidBytes(itemId),uuidBytes(deviceId),Uint8Array.of(kind),u16(timestamp.length),timestamp);}

export function fileChunkCount(size:number,chunkSize=FILE_CHUNK_BYTES):number{if(!Number.isSafeInteger(size)||size<0||!Number.isSafeInteger(chunkSize)||chunkSize<1)throw new Error('Invalid file chunk layout');return Math.max(1,Math.ceil(size/chunkSize));}
export function fileChunkPlaintextSize(manifest:FileManifestItem,index:number):number{if(!Number.isInteger(index)||index<0||index>=manifest.chunkCount)throw new Error('File chunk index is out of range');if(manifest.size===0)return 0;return Math.min(manifest.chunkSize,manifest.size-index*manifest.chunkSize);}
export function buildFileChunkAad(serverId:UUID,channelId:UUID,manifest:FileManifestItem,index:number):Uint8Array{return concat(FILE_CHUNK_AAD_LABEL,u16(1),uuidBytes(serverId),uuidBytes(channelId),uuidBytes(manifest.fileId),u32(index),u64(manifest.size),u32(manifest.chunkSize));}
export async function encryptFileChunk(secret:ChannelSecret,serverId:UUID,manifest:FileManifestItem,index:number,plaintext:Uint8Array):Promise<Uint8Array>{validateFileManifest(manifest);if(plaintext.length!==fileChunkPlaintextSize(manifest,index))throw new Error('File chunk length does not match manifest');const key=await crypto.subtle.importKey('raw',buffer(await deriveFileKey(secret,manifest.fileId)),'AES-GCM',false,['encrypt']);const nonce=concat(fromBase64(manifest.noncePrefix),u32(index));return new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv:buffer(nonce),additionalData:buffer(buildFileChunkAad(serverId,secret.channelId,manifest,index)),tagLength:128},key,buffer(plaintext)));}
export async function decryptFileChunk(secret:ChannelSecret,serverId:UUID,manifest:FileManifestItem,index:number,ciphertext:Uint8Array):Promise<Uint8Array>{validateFileManifest(manifest);if(ciphertext.length!==fileChunkPlaintextSize(manifest,index)+16)throw new Error('Encrypted file chunk length does not match manifest');const key=await crypto.subtle.importKey('raw',buffer(await deriveFileKey(secret,manifest.fileId)),'AES-GCM',false,['decrypt']);const nonce=concat(fromBase64(manifest.noncePrefix),u32(index));try{return new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:buffer(nonce),additionalData:buffer(buildFileChunkAad(serverId,secret.channelId,manifest,index)),tagLength:128},key,buffer(ciphertext)));}catch{throw new Error('File chunk authentication failed');}}

function encodeSecret(rootKey:Uint8Array,privateKey:Uint8Array,passwordCheck:Uint8Array):Uint8Array{return concat(Uint8Array.of(0xa4,0x01,0x01,0x02),cborBytes(rootKey),Uint8Array.of(0x03),cborBytes(privateKey),Uint8Array.of(0x04),cborBytes(passwordCheck));}
function cborBytes(value:Uint8Array):Uint8Array{if(value.length<24)return concat(Uint8Array.of(0x40+value.length),value);if(value.length<=255)return concat(Uint8Array.of(0x58,value.length),value);if(value.length<=65535)return concat(Uint8Array.of(0x59),u16(value.length),value);throw new Error('CBOR byte string too large');}
function decodeSecret(value:Uint8Array):{rootKey:Uint8Array;privateKey:Uint8Array;passwordCheck:Uint8Array}{let offset=0;const byte=()=>{const result=value[offset];if(result===undefined)throw new Error('Invalid secret bundle');offset++;return result;};const readBytes=()=>{const head=byte();let length;if(head>=0x40&&head<=0x57)length=head-0x40;else if(head===0x58)length=byte();else if(head===0x59)length=(byte()<<8)|byte();else throw new Error('Invalid secret bundle');const result=value.slice(offset,offset+length);offset+=length;if(result.length!==length)throw new Error('Invalid secret bundle');return result;};if(byte()!==0xa4||byte()!==1||byte()!==1||byte()!==2)throw new Error('Unsupported secret bundle');const rootKey=readBytes();if(byte()!==3)throw new Error('Invalid secret bundle');const privateKey=readBytes();if(byte()!==4)throw new Error('Invalid secret bundle');const passwordCheck=readBytes();if(offset!==value.length||rootKey.length!==32||passwordCheck.length!==32)throw new Error('Invalid secret bundle');return{rootKey,privateKey,passwordCheck};}
function constantTimeEqual(left:Uint8Array,right:Uint8Array):boolean{if(left.length!==right.length)return false;let difference=0;for(let index=0;index<left.length;index++)difference|=(left[index]??0)^(right[index]??0);return difference===0;}

export function encodeClipboardPayload(item:TransferItem):Uint8Array{
  if(item.type==='text/plain')return concat(u16(1),Uint8Array.of(1),u32(item.bytes.length),item.bytes);
  if(item.type==='image/png')return concat(u16(1),Uint8Array.of(2),u32(item.width),u32(item.height),u32(item.bytes.length),item.bytes);
  const filename=utf8(item.filename),mediaType=utf8(item.mediaType),nonce=fromBase64(item.noncePrefix),hash=fromBase64(item.sha256);
  return concat(u16(1),Uint8Array.of(3),uuidBytes(item.fileId),u16(filename.length),filename,u16(mediaType.length),mediaType,u64(item.size),u32(item.chunkSize),u32(item.chunkCount),nonce,hash,i64(item.expiresAt));
}
function decodeItem(value:Uint8Array):TransferItem{
  const view=new DataView(value.buffer,value.byteOffset,value.byteLength);if(value.length<7||view.getUint16(0)!==1)throw new Error('Unsupported clipboard payload');const type=value[2];
  if(type===1){const length=view.getUint32(3);if(value.length!==7+length)throw new Error('Invalid text payload');const bytes=value.slice(7);decodeUtf8(bytes);return{type:'text/plain',bytes};}
  if(type===2){if(value.length<15)throw new Error('Invalid image payload');const width=view.getUint32(3),height=view.getUint32(7),length=view.getUint32(11);if(value.length!==15+length)throw new Error('Invalid image payload');return{type:'image/png',width,height,bytes:value.slice(15)};}
  if(type===3){let offset=3;const take=(length:number)=>{const result=value.slice(offset,offset+length);if(result.length!==length)throw new Error('Invalid file manifest');offset+=length;return result;};const fileId=uuidFromBytes(take(16));const readU16=()=>{const bytes=take(2);return new DataView(bytes.buffer,bytes.byteOffset,2).getUint16(0);};const filename=decodeUtf8(take(readU16()));const mediaType=decodeUtf8(take(readU16()));const fixed=take(64);const data=new DataView(fixed.buffer,fixed.byteOffset,fixed.byteLength);const size=Number(data.getBigUint64(0));const chunkSize=data.getUint32(8),chunkCount=data.getUint32(12);const noncePrefix=base64(fixed.slice(16,24)),sha256=base64(fixed.slice(24,56)),expiresAt=Number(data.getBigInt64(56));if(offset!==value.length)throw new Error('Invalid file manifest');const item:FileManifestItem={type:FILE_MANIFEST_CONTENT_TYPE,fileId,filename,mediaType,size,chunkSize,chunkCount,noncePrefix,sha256,expiresAt};validateFileManifest(item);return item;}
  throw new Error('Unsupported clipboard type');
}

export function validateFileManifest(item:FileManifestItem):void{const filename=utf8(item.filename);if(filename.length<1||filename.length>255||item.filename==='.'||item.filename==='..'||item.filename.includes('/')||item.filename.includes('\\')||/\p{Cc}/u.test(item.filename))throw new Error('Invalid file name');if(item.mediaType.length<1||utf8(item.mediaType).length>255||![...item.mediaType].every((value)=>{const code=value.charCodeAt(0);return code>=33&&code<=126;}))throw new Error('Invalid file media type');if(!Number.isSafeInteger(item.size)||item.size<0||item.chunkSize!==FILE_CHUNK_BYTES||item.chunkCount!==fileChunkCount(item.size,item.chunkSize)||!Number.isSafeInteger(item.expiresAt)||item.expiresAt<=0||fromBase64(item.noncePrefix).length!==8||fromBase64(item.sha256).length!==32)throw new Error('Invalid file manifest');}
export function validateItem(item:TransferItem):void{if(item.type==='text/plain'){if(item.bytes.length>1024*1024)throw new Error('Text exceeds 1 MiB');const text=decodeUtf8(item.bytes);if(text.includes('\0'))throw new Error('Text contains a null byte');}else if(item.type==='image/png'){if(item.bytes.length>16*1024*1024||item.width<1||item.height<1||item.width>16_384||item.height>16_384||item.width*item.height>64_000_000)throw new Error('PNG exceeds image limits');const signature=[137,80,78,71,13,10,26,10];if(item.bytes.length<24||signature.some((byte,index)=>item.bytes[index]!==byte)||decodeUtf8(item.bytes.slice(12,16))!=='IHDR')throw new Error('Malformed PNG');const view=new DataView(item.bytes.buffer,item.bytes.byteOffset,item.bytes.byteLength);if(view.getUint32(16)!==item.width||view.getUint32(20)!==item.height)throw new Error('PNG dimensions do not match');}else validateFileManifest(item);}
function validateKdf(kdf:KdfParameters):void{if(kdf.name!=='argon2id'||kdf.memory_kib<65_536||kdf.memory_kib>1_048_576||kdf.iterations<3||kdf.iterations>32||kdf.parallelism<1||kdf.parallelism>16||kdf.output_bytes!==32||fromBase64(kdf.salt).length<16)throw new Error('Unsupported password KDF profile');}
