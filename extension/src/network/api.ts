import type { EncryptedEnvelope, ItemMetadata, KdfParameters, MembershipPublicKey, ServerConfig, UUID, WrappedSecret } from '../shared/types';
import { buffer } from '../crypto/encoding';

export interface FileTransferInfo {max_file_bytes:number;chunk_bytes:number;retention_seconds:number}
export interface FileObject {id:UUID;channel_id:UUID;origin_device_id:UUID;plaintext_size:number;ciphertext_size:number;chunk_size:number;chunk_count:number;next_chunk:number;status:string;expires_at:number;deduplicated:boolean}
export interface ServerInfo { name:string; server_instance_id:UUID; server_version:string; protocol_version:number; chrome_store_url:string;file_transfer?:FileTransferInfo }
export interface ChannelSummary { id:UUID; name:string; crypto_version:number; member_count:number; joined:boolean; current_sequence:number }
export interface JoinParameters { channel_id:UUID; crypto_version:number; password_kdf:KdfParameters; wrapped_secret:WrappedSecret; membership_public_key:MembershipPublicKey }
export interface JoinChallenge { challenge_id:UUID; challenge_random:string; expires_at:number; server_instance_id:UUID; channel_id:UUID; device_id:UUID }

export class ApiClient {
  constructor(readonly config:ServerConfig) {}

  static async info(serverUrl:string):Promise<ServerInfo>{return publicJson(serverUrl,'/api/v1/info',undefined,validServerInfo);}

  static async createPairingCode(serverUrl:string):Promise<{code:string;expires_at:string}>{return publicJson(serverUrl,'/api/v1/pairing',{method:'POST',body:'{}',headers:{'content-type':'application/json'}});}

  static async register(serverUrl:string,body:unknown):Promise<Registration>{return publicJson(serverUrl,'/api/v1/devices/register',{method:'POST',body:JSON.stringify(body),headers:{'content-type':'application/json'}},validRegistration);}

  async device():Promise<unknown>{return this.json('/api/v1/device');}
  async renameDevice(name:string):Promise<unknown>{return this.json('/api/v1/device',{method:'PATCH',body:JSON.stringify({name}),headers:{'content-type':'application/json'}});}
  async rotateToken():Promise<{device_token:string}>{return this.json('/api/v1/device/token/rotate',{method:'POST'});}
  async revokeDevice():Promise<void>{await this.empty('/api/v1/device',{method:'DELETE'});}
  async channels():Promise<ChannelSummary[]>{return this.json('/api/v1/channels',undefined,validChannels);}
  async createChannel(body:unknown):Promise<ChannelSummary>{return this.json('/api/v1/channels',{method:'POST',body:JSON.stringify(body),headers:{'content-type':'application/json'}},validChannelSummary);}
  async joinParameters(channelId:UUID):Promise<JoinParameters>{return this.json(`/api/v1/channels/${channelId}/join-parameters`,undefined,validJoinParameters);}
  async joinChallenge(channelId:UUID):Promise<JoinChallenge>{return this.json(`/api/v1/channels/${channelId}/join-challenge`,{method:'POST'},validJoinChallenge);}
  async join(channelId:UUID,challengeId:UUID,signature:string):Promise<void>{await this.empty(`/api/v1/channels/${channelId}/join`,{method:'POST',body:JSON.stringify({challenge_id:challengeId,signature_algorithm:'ecdsa-p256-sha256',signature}),headers:{'content-type':'application/json'}});}
  async leave(channelId:UUID):Promise<void>{await this.empty(`/api/v1/channels/${channelId}/leave`,{method:'POST'});}
  async deleteChannel(channelId:UUID):Promise<void>{await this.empty(`/api/v1/channels/${channelId}`,{method:'DELETE'});}
  async members(channelId:UUID):Promise<Member[]>{return this.json(`/api/v1/channels/${channelId}/members`,undefined,validMembers);}
  async current(channelId:UUID):Promise<ItemMetadata>{return this.json(`/api/v1/channels/${channelId}/current`,undefined,validItem);}
  async files(channelId:UUID):Promise<ItemMetadata[]>{return this.json(`/api/v1/channels/${channelId}/files`,undefined,validItems);}
  async content(itemId:UUID):Promise<Uint8Array>{const response=await this.fetch(`/api/v1/items/${itemId}/content`);const declared=Number(response.headers.get('content-length'));if(Number.isFinite(declared)&&declared>16*1024*1024+16)throw new Error('Server ciphertext exceeds limits');const bytes=new Uint8Array(await response.arrayBuffer());if(bytes.length>16*1024*1024+16)throw new Error('Server ciphertext exceeds limits');return bytes;}
  async ack(item:ItemMetadata):Promise<void>{await this.empty(`/api/v1/items/${item.id}/ack`,{method:'POST',body:JSON.stringify({channel_id:item.channel_id,sequence:item.channel_sequence}),headers:{'content-type':'application/json'}});}
  async ticket():Promise<Ticket>{return this.json('/api/v1/ws-ticket',{method:'POST'},validTicket);}
  async createFile(channelId:UUID,body:{file_id:UUID;plaintext_size:number;chunk_size:number;chunk_count:number}):Promise<FileObject>{return this.json(`/api/v1/channels/${channelId}/files`,{method:'POST',body:JSON.stringify(body),headers:{'content-type':'application/json'}},validFileObject);}
  async uploadFileChunk(fileId:UUID,index:number,ciphertext:Uint8Array):Promise<void>{await this.empty(`/api/v1/files/${fileId}/chunks/${index}`,{method:'PUT',headers:{'content-type':'application/octet-stream'},body:buffer(ciphertext)});}
  async completeFile(fileId:UUID):Promise<FileObject>{return this.json(`/api/v1/files/${fileId}/complete`,{method:'POST'},validFileObject);}
  async fileMetadata(fileId:UUID):Promise<FileObject>{return this.json(`/api/v1/files/${fileId}`,undefined,validFileObject);}
  async fileChunk(fileId:UUID,index:number,maximum:number):Promise<Uint8Array>{const response=await this.fetch(`/api/v1/files/${fileId}/chunks/${index}`);const declared=Number(response.headers.get('content-length'));if(Number.isFinite(declared)&&declared>maximum)throw new Error('Server file chunk exceeds limits');const bytes=new Uint8Array(await response.arrayBuffer());if(bytes.length>maximum)throw new Error('Server file chunk exceeds limits');return bytes;}
  async deleteFile(fileId:UUID):Promise<void>{await this.empty(`/api/v1/files/${fileId}`,{method:'DELETE'});}

  async upload(envelope:EncryptedEnvelope):Promise<{id:UUID;channel_sequence:number;accepted_at:string;deduplicated:boolean}>{
    const metadata=envelope.metadata;
    const headers:Record<string,string>={
      'content-type':'application/octet-stream','idempotency-key':metadata.id,'x-crypto-version':String(metadata.crypto_version),'x-content-type':metadata.content_type,'x-envelope-nonce':metadata.nonce,'x-client-created-at':metadata.created_at_client??'','x-plaintext-size':String(metadata.plaintext_size??0),
    };
    if(metadata.image_width!==undefined)headers['x-image-width']=String(metadata.image_width);
    if(metadata.image_height!==undefined)headers['x-image-height']=String(metadata.image_height);
    if(metadata.file_id!==undefined)headers['x-file-id']=metadata.file_id;
    const response=await this.json(`/api/v1/channels/${metadata.channel_id}/items`,{method:'POST',headers,body:buffer(envelope.ciphertext)},validUploadResponse);if(response.id!==metadata.id)throw new Error('Server returned a mismatched item receipt');return response;
  }

  async websocketUrl():Promise<string>{const {ticket}=await this.ticket();const url=new URL(this.config.url);url.protocol=url.protocol==='https:'?'wss:':'ws:';url.pathname='/api/v1/sync';url.search='';url.searchParams.set('ticket',ticket);return url.toString();}

  private async fetch(path:string,init:RequestInit={}):Promise<Response>{
    const headers=new Headers(init.headers);headers.set('authorization',`Bearer ${this.config.deviceToken}`);
    const response=await fetch(new URL(path,this.config.url),{...init,headers,cache:'no-store'});
    if(!response.ok){let message=`Server returned ${response.status}`;try{message=(await response.json() as {error?:string}).error??message;}catch{}throw new Error(message);}
    return response;
  }
  private async json<T>(path:string,init?:RequestInit,validator?:(value:unknown)=>value is T):Promise<T>{const value:unknown=await(await this.fetch(path,init)).json();if(validator&&!validator(value))throw new Error('Server returned an invalid protocol payload');return value as T;}
  private async empty(path:string,init?:RequestInit):Promise<void>{await this.fetch(path,init);}
}

interface Registration {device_id:UUID;device_token:string;server_instance_id:UUID;api_version:number}
interface Member {id:UUID;name:string;joined_at:string}
interface Ticket {ticket:string;expires_at:number}
interface UploadResponse {id:UUID;channel_sequence:number;accepted_at:string;deduplicated:boolean}

async function publicJson<T>(serverUrl:string,path:string,init?:RequestInit,validator?:(value:unknown)=>value is T):Promise<T>{const response=await fetch(new URL(path,serverUrl),{...init,cache:'no-store'});if(!response.ok)throw new Error(`Server returned ${response.status}`);const value:unknown=await response.json();if(validator&&!validator(value))throw new Error('Server returned an invalid protocol payload');return value as T;}
function record(value:unknown):value is Record<string,unknown>{return !!value&&typeof value==='object'&&!Array.isArray(value);}
function uuid(value:unknown):value is UUID{return typeof value==='string'&&/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);}
function finiteInteger(value:unknown):value is number{return typeof value==='number'&&Number.isSafeInteger(value)&&value>=0;}
function validServerInfo(value:unknown):value is ServerInfo{return record(value)&&typeof value.name==='string'&&uuid(value.server_instance_id)&&typeof value.server_version==='string'&&value.protocol_version===1&&typeof value.chrome_store_url==='string'&&(value.file_transfer===undefined||validFileTransfer(value.file_transfer));}
function validFileTransfer(value:unknown):value is FileTransferInfo{return record(value)&&finiteInteger(value.max_file_bytes)&&value.max_file_bytes>0&&finiteInteger(value.chunk_bytes)&&value.chunk_bytes>0&&finiteInteger(value.retention_seconds)&&value.retention_seconds>0;}
function validRegistration(value:unknown):value is Registration{return record(value)&&uuid(value.device_id)&&typeof value.device_token==='string'&&value.device_token.length>=40&&uuid(value.server_instance_id)&&value.api_version===1;}
function validChannelSummary(value:unknown):value is ChannelSummary{return record(value)&&uuid(value.id)&&typeof value.name==='string'&&value.name.length<=320&&value.crypto_version===1&&finiteInteger(value.member_count)&&typeof value.joined==='boolean'&&finiteInteger(value.current_sequence);}
function validChannels(value:unknown):value is ChannelSummary[]{return Array.isArray(value)&&value.length<=256&&value.every(validChannelSummary);}
function validKdf(value:unknown):value is KdfParameters{return record(value)&&value.name==='argon2id'&&typeof value.salt==='string'&&finiteInteger(value.memory_kib)&&finiteInteger(value.iterations)&&finiteInteger(value.parallelism)&&value.output_bytes===32;}
function validWrapped(value:unknown):value is WrappedSecret{return record(value)&&value.algorithm==='aes-256-gcm'&&typeof value.nonce==='string'&&typeof value.ciphertext==='string';}
function validMembershipKey(value:unknown):value is MembershipPublicKey{return record(value)&&value.algorithm==='ecdsa-p256-sha256'&&typeof value.spki==='string';}
function validJoinParameters(value:unknown):value is JoinParameters{return record(value)&&uuid(value.channel_id)&&value.crypto_version===1&&validKdf(value.password_kdf)&&validWrapped(value.wrapped_secret)&&validMembershipKey(value.membership_public_key);}
function validJoinChallenge(value:unknown):value is JoinChallenge{return record(value)&&uuid(value.challenge_id)&&typeof value.challenge_random==='string'&&finiteInteger(value.expires_at)&&uuid(value.server_instance_id)&&uuid(value.channel_id)&&uuid(value.device_id);}
function validMember(value:unknown):value is Member{return record(value)&&uuid(value.id)&&typeof value.name==='string'&&typeof value.joined_at==='string';}
function validMembers(value:unknown):value is Member[]{return Array.isArray(value)&&value.length<=64&&value.every(validMember);}
function validItem(value:unknown):value is ItemMetadata{if(!record(value))return false;const common=uuid(value.id)&&uuid(value.channel_id)&&uuid(value.origin_device_id)&&typeof value.origin_device_name==='string'&&finiteInteger(value.channel_sequence)&&value.crypto_version===1&&(value.content_type==='text/plain'||value.content_type==='image/png'||value.content_type==='application/vnd.clipmesh.file')&&finiteInteger(value.ciphertext_size)&&finiteInteger(value.plaintext_size)&&typeof value.nonce==='string'&&typeof value.accepted_at==='string';return common&&(value.content_type!=='image/png'||(finiteInteger(value.image_width)&&finiteInteger(value.image_height)));}
function validItems(value:unknown):value is ItemMetadata[]{return Array.isArray(value)&&value.length<=512&&value.every(validItem);}
function validFileObject(value:unknown):value is FileObject{return record(value)&&uuid(value.id)&&uuid(value.channel_id)&&uuid(value.origin_device_id)&&finiteInteger(value.plaintext_size)&&finiteInteger(value.ciphertext_size)&&finiteInteger(value.chunk_size)&&finiteInteger(value.chunk_count)&&finiteInteger(value.next_chunk)&&typeof value.status==='string'&&finiteInteger(value.expires_at)&&typeof value.deduplicated==='boolean';}
function validTicket(value:unknown):value is Ticket{return record(value)&&typeof value.ticket==='string'&&value.ticket.length>=40&&finiteInteger(value.expires_at);}
function validUploadResponse(value:unknown):value is UploadResponse{return record(value)&&uuid(value.id)&&finiteInteger(value.channel_sequence)&&typeof value.accepted_at==='string'&&typeof value.deduplicated==='boolean';}
