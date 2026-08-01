import { ChromeLifecycleAdapter } from '../adapters/chrome/lifecycle';
import { ChromeStorageAdapter } from '../adapters/chrome/storage';
import { addJoinedChannel, removeJoinedChannel, routingMode, toggleRoute } from '../channels/routing';
import { base64, fromBase64 } from '../crypto/encoding';
import { contentHash, createChannelMaterial, decryptItem, encryptItem, signJoinChallenge, unwrapChannelSecret } from '../crypto/protocol';
import { DEFAULT_HISTORY_SETTINGS, HistoryDatabase, type HistorySettings, type StoredHistoryEntry } from '../history/database';
import { ApiClient, type ChannelSummary } from '../network/api';
import { RealtimeClient, type ConnectionState } from '../network/realtime';
import { FILE_MANIFEST_CONTENT_TYPE, type ChannelSecret, type FileManifestItem, type JoinedChannel, type NormalizedClipboardItem, type PauseState, type RouteSelection, type ServerConfig, type TransferItem, type UUID } from '../shared/types';

const storage=new ChromeStorageAdapter();
const lifecycle=new ChromeLifecycleAdapter();
const history=new HistoryDatabase();

class ClipMeshService {
  private config?:ServerConfig;
  private channels:JoinedChannel[]=[];
  private directory:ChannelSummary[]=[];
  private routes:RouteSelection[]=[];
  private pause:PauseState={sending:false,receiving:false};
  private settings:HistorySettings=DEFAULT_HISTORY_SETTINGS;
  private lastSequences:Record<UUID,number>={};
  private realtime?:RealtimeClient;
  private connection:ConnectionState='not-configured';
  private current?:TransferItem;
  private currentSource?:{channel:string;device:string;channelId:UUID};
  private remoteWrites:Array<{hash:string;at:number;itemId:UUID;channelId:UUID;type:'text/plain'|'image/png'}>=[];
  private localSuppress?:{hash:string;at:number};
  private clipboardError?:string;
  private operationError?:string;
  private observationQueue=Promise.resolve();
  private lastConnection?:number;

  async initialize():Promise<void>{
    [this.config,this.channels,this.routes,this.pause,this.settings,this.lastSequences,this.lastConnection]=await Promise.all([
      storage.get<ServerConfig>('serverConfig'),storage.get<JoinedChannel[]>('joinedChannels').then((v)=>v??[]),storage.get<RouteSelection[]>('routes').then((v)=>v??[]),storage.get<PauseState>('pause').then((v)=>v??{sending:false,receiving:false}),storage.get<HistorySettings>('historySettings').then((v)=>v??DEFAULT_HISTORY_SETTINGS),storage.get<Record<UUID,number>>('lastSequences').then((v)=>v??{}),storage.get<number>('lastConnection'),
    ]);
    await lifecycle.ensureClipboardContext();await lifecycle.keepRealtimeConnectionAlive();
    await chrome.runtime.sendMessage({target:'offscreen',command:'start'}).catch(()=>undefined);
    await history.prune(this.settings);
    if(this.pause.until&&this.pause.until<=Date.now()){this.pause={sending:false,receiving:false};await storage.set('pause',this.pause);}
    if(this.config){await this.refreshChannels().catch(()=>undefined);this.startRealtime();void this.syncRetainedFiles();}
  }

  snapshot=async()=>{const [entries,outbox,historyUsage]=await Promise.all([history.recent(200),history.getOutbox(),history.usage()]);return{configured:!!this.config,server:this.config?{url:this.config.url,instanceId:this.config.instanceId,deviceId:this.config.deviceId,deviceName:this.config.deviceName,serverVersion:this.config.serverVersion}:undefined,client:{browser:navigator.userAgent,os:platform(),lastConnection:this.lastConnection},connection:this.connection,clipboardError:this.clipboardError,operationError:this.operationError,monitoring:{active:true,pollIntervalMs:this.connection==='connected'?1000:5000,recentRemoteSuppressions:this.remoteWrites.length},channels:this.directory,joined:this.channels.map(({secret:_,...channel})=>channel),routes:this.routes,mode:routingMode(this.routes),pause:this.pause,current:this.current?serializeItem(this.current):undefined,currentSource:this.currentSource,history:entries.map(({encryptedEnvelope:_,...entry})=>entry),historyUsage,pending:outbox?{capturedAt:outbox.capturedAt,targetChannelIds:outbox.targetChannelIds,contentType:outbox.item.type,byteSize:outbox.item.type===FILE_MANIFEST_CONTENT_TYPE?outbox.item.size??0:outbox.item.bytes?.byteLength??0}:undefined,historySettings:this.settings};};

  async pair(input:{serverUrl:string;pairingCode:string;deviceName:string}):Promise<void>{
    const url=validatedServerUrl(input.serverUrl);const info=await ApiClient.info(url.toString());if(info.protocol_version!==1)throw new Error('Server protocol is not compatible');
    if(!input.deviceName.trim())throw new Error('Device name is required');
    const deviceKeys=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']);
    const publicKey=base64(new Uint8Array(await crypto.subtle.exportKey('spki',deviceKeys.publicKey)));
    const privateKey=base64(new Uint8Array(await crypto.subtle.exportKey('pkcs8',deviceKeys.privateKey)));
    const registered=await ApiClient.register(url.toString(),{pairing_code:input.pairingCode,name:input.deviceName.trim(),signing_public_key:publicKey,browser_family:'chrome',browser_version:navigator.userAgent.match(/Chrome\/([\d.]+)/)?.[1],os_family:platform()});
    if(registered.server_instance_id!==info.server_instance_id||registered.api_version!==1)throw new Error('Server identity changed during pairing');
    this.config={url:url.toString(),instanceId:registered.server_instance_id,deviceId:registered.device_id,deviceName:input.deviceName.trim(),deviceToken:registered.device_token,serverVersion:info.server_version};
    await Promise.all([storage.set('serverConfig',this.config),storage.set('deviceSigningPrivateKey',privateKey)]);await this.refreshChannels();this.startRealtime();
  }

  async createChannel(name:string,password:string,confirmation:string):Promise<void>{
    if(password!==confirmation)throw new Error('Passwords do not match');const api=this.api();const material=await createChannelMaterial(password);
    await api.createChannel({channel_id:material.channelId,name:name.trim(),crypto_version:1,password_kdf:material.passwordKdf,wrapped_secret:material.wrappedSecret,membership_public_key:material.membershipPublicKey});
    const challenge=await api.joinChallenge(material.channelId);this.validateChallenge(challenge,material.channelId);const signature=await signJoinChallenge(material.secret,this.config!.instanceId,this.config!.deviceId,challenge.challenge_id,challenge.challenge_random,challenge.expires_at);await api.join(material.channelId,challenge.challenge_id,signature);
    this.channels.push({id:material.channelId,name:name.trim(),cryptoVersion:1,kdf:material.passwordKdf,secret:material.secret});this.routes=addJoinedChannel(this.routes,material.channelId);await this.persistChannels();await this.refreshChannels();this.realtime?.routingChanged();
  }

  async joinChannel(channelId:UUID,password:string):Promise<void>{
    if(this.channels.some((channel)=>channel.id===channelId))return;const api=this.api();const parameters=await api.joinParameters(channelId);
    if(parameters.channel_id!==channelId||parameters.crypto_version!==1)throw new Error('Server returned mismatched channel parameters');
    const secret=await unwrapChannelSecret(password,channelId,parameters.password_kdf,parameters.wrapped_secret,parameters.membership_public_key.spki);
    const challenge=await api.joinChallenge(channelId);this.validateChallenge(challenge,channelId);const signature=await signJoinChallenge(secret,this.config!.instanceId,this.config!.deviceId,challenge.challenge_id,challenge.challenge_random,challenge.expires_at);await api.join(channelId,challenge.challenge_id,signature);
    const summary=this.directory.find((channel)=>channel.id===channelId);this.channels.push({id:channelId,name:summary?.name??channelId,cryptoVersion:1,kdf:parameters.password_kdf,secret});this.routes=addJoinedChannel(this.routes,channelId);await this.persistChannels();await this.refreshChannels();this.realtime?.routingChanged();
  }

  async leaveChannel(channelId:UUID,deleteHistory:boolean):Promise<void>{await this.api().leave(channelId);await this.removeLocalChannel(channelId,deleteHistory);await this.refreshChannels();}
  async deleteChannel(channelId:UUID,deleteHistory:boolean):Promise<void>{await this.api().deleteChannel(channelId);await this.removeLocalChannel(channelId,deleteHistory);await this.refreshChannels();}
  async toggle(channelId:UUID,side:'send'|'receive',enabled:boolean):Promise<void>{this.routes=toggleRoute(this.routes,channelId,side,enabled);await storage.set('routes',this.routes);this.realtime?.routingChanged();}
  async setPause(pause:PauseState):Promise<void>{const wasSendingPaused=this.pause.sending;this.pause=pause;await storage.set('pause',pause);if(pause.until)await chrome.alarms.create('clipmesh-pause',{when:pause.until});if(!pause.receiving)this.realtime?.routingChanged();if(wasSendingPaused&&!pause.sending)await this.flushOutbox();}
  async setHistorySettings(settings:HistorySettings):Promise<void>{if(settings.historyEnabled&&settings.maxEntries===0&&settings.maxAgeDays===0&&settings.maxStorageBytes===0)throw new Error('At least one history bound must be active');this.settings=settings;await storage.set('historySettings',settings);await history.prune(settings);}
  async renameDevice(name:string):Promise<void>{if(!name.trim())throw new Error('Device name is required');await this.api().renameDevice(name.trim());if(this.config){this.config.deviceName=name.trim();await storage.set('serverConfig',this.config);}}
  async rotateToken():Promise<void>{const response=await this.api().rotateToken();if(!this.config)return;this.config.deviceToken=response.device_token;await storage.set('serverConfig',this.config);this.startRealtime();}
  async revokeDevice(deleteHistory:boolean):Promise<void>{await this.api().revokeDevice();await this.forgetServer(deleteHistory);}
  async forgetServer(deleteHistory:boolean):Promise<void>{const origin=this.config?`${new URL(this.config.url).origin}/*`:undefined;this.realtime?.stop();if(deleteHistory)await history.clear();await chrome.storage.local.remove(['serverConfig','deviceSigningPrivateKey','joinedChannels','routes','pause','lastSequences','lastConnection']);if(origin)await chrome.permissions.remove({origins:[origin]}).catch(()=>false);this.config=undefined;this.channels=[];this.directory=[];this.routes=[];this.lastSequences={};this.lastConnection=undefined;this.current=undefined;this.currentSource=undefined;this.connection='not-configured';}
  async members(channelId:UUID):Promise<Array<{id:UUID;name:string;joined_at:string}>>{return this.api().members(channelId);}
  async clearHistory():Promise<void>{await history.clear();}
  async clearChannelHistory(channelId:UUID):Promise<void>{await history.clear(channelId);}
  async deleteHistory(localId:UUID):Promise<void>{await history.delete(localId);}
  async copyHistory(localId:UUID):Promise<void>{const item=await this.decryptHistory(localId);if(item.type===FILE_MANIFEST_CONTENT_TYPE)throw new Error('Files cannot be copied; use Download');await this.writeClipboard(item);}
  async resendHistory(localId:UUID):Promise<void>{const item=await this.decryptHistory(localId);if(item.type===FILE_MANIFEST_CONTENT_TYPE)throw new Error('Send the original file again instead of resending an expired file link');await this.writeClipboard(item);await this.publish(item);}
  async previewHistory(localId:UUID):Promise<SerializedItem>{return serializeItem(await this.decryptHistory(localId));}

  async explicitText(text:string,send:boolean):Promise<void>{const item:NormalizedClipboardItem={type:'text/plain',bytes:new TextEncoder().encode(text)};await this.writeClipboard(item);if(send)await this.publish(item);}
  async explicitImage():Promise<void>{if(!this.current||this.current.type!=='image/png')throw new Error('Current clipboard is not an image');await this.publish(this.current);}
  async copyCurrent():Promise<void>{if(!this.current)throw new Error('No supported clipboard item');if(this.current.type===FILE_MANIFEST_CONTENT_TYPE)throw new Error('Files cannot be copied; use Download');await this.writeClipboard(this.current);}
  async publishFileManifest(item:FileManifestItem,channelId:UUID):Promise<void>{if(item.type!==FILE_MANIFEST_CONTENT_TYPE)throw new Error('Invalid file manifest');this.current=item;const channel=this.channels.find((value)=>value.id===channelId);this.currentSource={channel:channel?.name??channelId,device:this.config?.deviceName??'This device',channelId};if(!await this.publish(item,[channelId],true))throw new Error('The encrypted file was stored, but its manifest could not be published');}
  removePreview():void{this.current=undefined;this.currentSource=undefined;}
  async reloadClipboard():Promise<void>{const response=await chrome.runtime.sendMessage({target:'offscreen',command:'read'});if(response?.error)throw new Error(response.error);if(response){this.current=deserializeItem(response);this.currentSource=undefined;}this.clipboardError=undefined;}

  observe(item:NormalizedClipboardItem,hash:string):void{this.clipboardError=undefined;this.observationQueue=this.observationQueue.then(()=>this.processObservation(item,hash)).catch((error)=>this.reportError(error));}
  setClipboardError(message:string):void{this.clipboardError=message;}
  clearClipboardError():void{this.clipboardError=undefined;}
  async onRemote(item:import('../shared/types').ItemMetadata):Promise<void>{
    if(!this.config||this.pause.receiving||!this.routes.some((route)=>route.channelId===item.channel_id&&route.receiveEnabled)||item.channel_sequence<=(this.lastSequences[item.channel_id]??0))return;
    if(item.origin_device_id===this.config.deviceId){await this.acceptSequence(item);return;}
    if(item.content_type===FILE_MANIFEST_CONTENT_TYPE&&await history.containsItem(item.id)){await this.acceptSequence(item);return;}
    const channel=this.channels.find((value)=>value.id===item.channel_id);if(!channel)return;
    const ciphertext=await this.api().content(item.id);let plaintext:TransferItem;
    try{plaintext=await decryptItem(channel.secret,this.config.instanceId,item,ciphertext);}catch(error){
      await this.storeReceivedHistory(channel,item,ciphertext,'failed');
      await this.acceptSequence(item);this.reportError(error);return;
    }
    const hash=await contentHash(plaintext);this.current=plaintext;this.currentSource={channel:channel.name,device:item.origin_device_name,channelId:item.channel_id};
    await this.storeReceivedHistory(channel,item,ciphertext,'received');
    if(plaintext.type!==FILE_MANIFEST_CONTENT_TYPE)try{await this.writeClipboard(plaintext);this.remoteWrites.push({hash,at:Date.now(),itemId:item.id,channelId:item.channel_id,type:plaintext.type});this.remoteWrites=this.remoteWrites.filter((entry)=>Date.now()-entry.at<=5000).slice(-32);}catch(error){this.clipboardError=error instanceof Error?error.message:String(error);}
    await this.acceptSequence(item);
  }

  private async storeReceivedHistory(channel:JoinedChannel,item:import('../shared/types').ItemMetadata,ciphertext:Uint8Array,status:'received'|'failed'):Promise<void>{
    const envelope={metadata:{id:item.id,channel_id:item.channel_id,origin_device_id:item.origin_device_id,crypto_version:1 as const,content_type:item.content_type,ciphertext_size:item.ciphertext_size,plaintext_size:item.plaintext_size,image_width:item.image_width,image_height:item.image_height,nonce:item.nonce,created_at_client:item.created_at_client},ciphertext};
    await history.add({localId:crypto.randomUUID(),itemId:item.id,channelId:item.channel_id,channelNameSnapshot:channel.name,originDeviceId:item.origin_device_id,originDeviceNameSnapshot:item.origin_device_name,direction:'received',contentType:item.content_type,encryptedEnvelope:{metadata:envelope.metadata,ciphertext:ciphertext.buffer.slice(ciphertext.byteOffset,ciphertext.byteOffset+ciphertext.byteLength) as ArrayBuffer},createdAtClient:item.created_at_client,acceptedAtServer:item.accepted_at,storedAtLocal:Date.now(),deliveryStatus:status,byteSize:ciphertext.length},this.settings).catch((error)=>this.reportError(error));
  }

  async control(message:unknown):Promise<void>{if(!message||typeof message!=='object'||!('type'in message))return;const type=(message as {type:unknown}).type;if(type==='channel_deleted'&&'channel_id'in message&&typeof(message as {channel_id:unknown}).channel_id==='string')await this.removeLocalChannel((message as {channel_id:UUID}).channel_id,false);else if(type==='resync_required')this.realtime?.routingChanged();else if(type==='channel_updated'||type==='membership_changed')await this.refreshChannels();}
  async pruneHistory():Promise<void>{await history.prune(this.settings);}
  async resumeTimer():Promise<void>{if(this.pause.until&&this.pause.until<=Date.now())await this.setPause({sending:false,receiving:false});}
  async reconnect():Promise<void>{if(this.config){this.realtime?.stop();this.startRealtime();}}

  private async syncRetainedFiles():Promise<void>{if(!this.config||this.pause.receiving)return;for(const route of this.routes.filter((value)=>value.receiveEnabled)){const channel=this.channels.find((value)=>value.id===route.channelId);if(!channel)continue;let items:import('../shared/types').ItemMetadata[];try{items=await this.api().files(channel.id);}catch(error){this.reportError(error);continue;}for(const item of items.reverse()){if(item.origin_device_id===this.config.deviceId||await history.containsItem(item.id))continue;const ciphertext=await this.api().content(item.id);try{const plaintext=await decryptItem(channel.secret,this.config.instanceId,item,ciphertext);if(plaintext.type!==FILE_MANIFEST_CONTENT_TYPE)throw new Error('Server file list contained a non-file item');await this.storeReceivedHistory(channel,item,ciphertext,'received');}catch(error){await this.storeReceivedHistory(channel,item,ciphertext,'failed');this.reportError(error);}}}}

  private startRealtime():void{if(!this.config)return;this.realtime?.stop();this.realtime=new RealtimeClient(this.config,()=>this.pause.receiving?[]:this.routes.filter((route)=>route.receiveEnabled).map((route)=>route.channelId),()=>this.lastSequences,(item)=>this.onRemote(item),(state)=>{this.connection=state;void chrome.runtime.sendMessage({target:'offscreen',command:'connection',connected:state==='connected'}).catch(()=>undefined);if(state==='connected'){this.lastConnection=Date.now();void storage.set('lastConnection',this.lastConnection);void this.flushOutbox();void this.syncRetainedFiles();}},(message)=>this.control(message));this.realtime.start();}
  private async processObservation(item:NormalizedClipboardItem,hash:string):Promise<void>{this.current=item;this.currentSource=undefined;const now=Date.now();this.remoteWrites=this.remoteWrites.filter((entry)=>now-entry.at<=5000);if(this.remoteWrites.some((entry)=>entry.hash===hash)||(this.localSuppress?.hash===hash&&now-this.localSuppress.at<2000))return;await this.publish(item);}
  private async publish(item:TransferItem,targetSnapshot?:UUID[],forceNetwork=false):Promise<boolean>{
    if(!this.config)return false;const targets=targetSnapshot??this.routes.filter((route)=>route.sendEnabled).map((route)=>route.channelId);if(targets.length===0)return false;
    if(this.pause.sending||(!forceNetwork&&!this.realtime?.connected())){await history.setOutbox(item,targets);return false;}
    const statuses:Record<UUID,'pending'|'accepted'|'failed'>=Object.fromEntries(targets.map((id)=>[id,'pending']));let firstEnvelope:Awaited<ReturnType<typeof encryptItem>>|undefined;let firstChannel:JoinedChannel|undefined;let acceptedAt:string|undefined;
    for(const channelId of targets){const channel=this.channels.find((value)=>value.id===channelId);if(!channel){statuses[channelId]='failed';continue;}try{const envelope=await encryptItem(channel.secret,this.config.instanceId,this.config.deviceId,item);firstEnvelope??=envelope;firstChannel??=channel;const result=await this.api().upload(envelope);acceptedAt=result.accepted_at;statuses[channelId]='accepted';}catch(error){statuses[channelId]='failed';this.reportError(error);}}
    if(firstEnvelope&&firstChannel){const cipher=firstEnvelope.ciphertext;const allAccepted=Object.values(statuses).every((status)=>status==='accepted');await history.add({localId:crypto.randomUUID(),itemId:firstEnvelope.metadata.id,channelId:firstChannel.id,channelNameSnapshot:firstChannel.name,originDeviceId:this.config.deviceId,originDeviceNameSnapshot:this.config.deviceName,direction:'sent',targetChannelIds:targets,contentType:item.type,encryptedEnvelope:{metadata:firstEnvelope.metadata,ciphertext:cipher.buffer.slice(cipher.byteOffset,cipher.byteOffset+cipher.byteLength) as ArrayBuffer},createdAtClient:firstEnvelope.metadata.created_at_client,acceptedAtServer:acceptedAt,storedAtLocal:Date.now(),deliveryStatus:allAccepted?'accepted':'failed',deliveryByChannel:statuses,byteSize:cipher.length},this.settings).catch((error)=>this.reportError(error));}
    const failedTargets=targets.filter((channelId)=>statuses[channelId]!=='accepted');
    if(failedTargets.length>0&&!forceNetwork)await history.setOutbox(item,failedTargets);
    return failedTargets.length===0;
  }
  private async flushOutbox():Promise<void>{const record=await history.getOutbox();if(!record)return;let item:TransferItem;if(record.item.type==='text/plain')item={type:'text/plain',bytes:new Uint8Array(record.item.bytes??new ArrayBuffer(0))};else if(record.item.type==='image/png')item={type:'image/png',bytes:new Uint8Array(record.item.bytes??new ArrayBuffer(0)),width:record.item.width??0,height:record.item.height??0};else item={type:FILE_MANIFEST_CONTENT_TYPE,fileId:String(record.item.fileId),filename:String(record.item.filename),mediaType:String(record.item.mediaType),size:Number(record.item.size),chunkSize:Number(record.item.chunkSize),chunkCount:Number(record.item.chunkCount),noncePrefix:String(record.item.noncePrefix),sha256:String(record.item.sha256),expiresAt:Number(record.item.expiresAt)};if(await this.publish(item,record.targetChannelIds))await history.clearOutbox();}
  private async decryptHistory(localId:UUID):Promise<TransferItem>{const entry=await history.get(localId);if(!entry)throw new Error('History entry was deleted');const channel=this.channels.find((value)=>value.id===entry.channelId);if(!channel)throw new Error('This history entry is locked. Rejoin the channel to restore access.');if(!this.config)throw new Error('Pair ClipMesh first');const stored=entry.encryptedEnvelope;const metadata:import('../shared/types').ItemMetadata={...stored.metadata,origin_device_name:entry.originDeviceNameSnapshot,channel_sequence:0,accepted_at:entry.acceptedAtServer??entry.createdAtClient??new Date(entry.storedAtLocal).toISOString()};return decryptItem(channel.secret,this.config.instanceId,metadata,new Uint8Array(stored.ciphertext));}
  private async writeClipboard(item:NormalizedClipboardItem):Promise<void>{const hash=await contentHash(item);this.localSuppress={hash,at:Date.now()};const target=item.type==='image/png'?'focused-extension':'offscreen';const response=await chrome.runtime.sendMessage({target,command:'write',item:serializeItem(item)});if(item.type==='image/png'&&!response)throw new Error('Chrome requires a focused ClipMesh page to copy PNG images. Open ClipMesh and select Copy again.');if(response?.error||response?.ok===false)throw new Error(response.error??'Clipboard write failed');this.current=item;this.clipboardError=undefined;}
  private async acceptSequence(item:import('../shared/types').ItemMetadata):Promise<void>{this.lastSequences[item.channel_id]=item.channel_sequence;await storage.set('lastSequences',this.lastSequences);this.realtime?.ack(item);}
  private validateChallenge(challenge:import('../network/api').JoinChallenge,channelId:UUID):void{if(!this.config||challenge.server_instance_id!==this.config.instanceId||challenge.device_id!==this.config.deviceId||challenge.channel_id!==channelId||challenge.expires_at<=Math.floor(Date.now()/1000))throw new Error('Server returned a mismatched or expired join challenge');}
  private api():ApiClient{if(!this.config)throw new Error('Pair ClipMesh with a server first');return new ApiClient(this.config);}
  private async refreshChannels():Promise<void>{this.directory=await this.api().channels();}
  private async persistChannels():Promise<void>{await Promise.all([storage.set('joinedChannels',this.channels),storage.set('routes',this.routes)]);}
  private async removeLocalChannel(channelId:UUID,deleteHistory:boolean):Promise<void>{this.channels=this.channels.filter((channel)=>channel.id!==channelId);this.routes=removeJoinedChannel(this.routes,channelId);delete this.lastSequences[channelId];if(deleteHistory)await history.clear(channelId);await Promise.all([this.persistChannels(),storage.set('lastSequences',this.lastSequences)]);this.realtime?.routingChanged();}
  private reportError(error:unknown):void{this.operationError=error instanceof Error?error.message:String(error);console.warn('ClipMesh operation failed',this.operationError);}
}

const service=new ClipMeshService();
const ready=service.initialize();

chrome.runtime.onMessage.addListener((message:unknown,_sender,sendResponse)=>{
  if(!message||typeof message!=='object'||!('type'in message))return;
  const value=message as Record<string,unknown>;
  if(value.type==='clipboard-observed'&&value.item&&typeof value.hash==='string'){const item=deserializeItem(value.item as SerializedItem);if(item.type!==FILE_MANIFEST_CONTENT_TYPE)service.observe(item,value.hash);return;}
  if(value.type==='clipboard-error'){service.setClipboardError(String(value.message??'Clipboard permission required'));return;}
  if(value.type==='clipboard-ready'){service.clearClipboardError();return;}
  void ready.then(()=>dispatch(value)).then((result)=>sendResponse({ok:true,result}),(error)=>sendResponse({ok:false,error:error instanceof Error?error.message:String(error)}));return true;
});

chrome.runtime.onStartup.addListener(()=>void ready);
chrome.runtime.onInstalled.addListener(()=>void ready);
chrome.alarms.onAlarm.addListener((alarm)=>{if(alarm.name==='clipmesh-pause')void service.resumeTimer();if(alarm.name==='clipmesh-reconnect')void service.reconnect();if(alarm.name==='clipmesh-history-prune')void service.pruneHistory();});

async function dispatch(message:Record<string,unknown>):Promise<unknown>{switch(message.type){case'get-state':return service.snapshot();case'pair':return service.pair(message.input as {serverUrl:string;pairingCode:string;deviceName:string});case'create-channel':return service.createChannel(String(message.name),String(message.password),String(message.confirmation));case'join-channel':return service.joinChannel(String(message.channelId),String(message.password));case'leave-channel':return service.leaveChannel(String(message.channelId),Boolean(message.deleteHistory));case'delete-channel':return service.deleteChannel(String(message.channelId),Boolean(message.deleteHistory));case'channel-members':return service.members(String(message.channelId));case'clear-channel-history':return service.clearChannelHistory(String(message.channelId));case'toggle-route':return service.toggle(String(message.channelId),message.side as 'send'|'receive',Boolean(message.enabled));case'set-pause':return service.setPause(message.pause as PauseState);case'set-history-settings':return service.setHistorySettings(message.settings as HistorySettings);case'clear-history':return service.clearHistory();case'delete-history':return service.deleteHistory(String(message.localId));case'copy-history':return service.copyHistory(String(message.localId));case'resend-history':return service.resendHistory(String(message.localId));case'preview-history':return service.previewHistory(String(message.localId));case'rename-device':return service.renameDevice(String(message.name));case'rotate-token':return service.rotateToken();case'revoke-device':return service.revokeDevice(Boolean(message.deleteHistory));case'forget-server':return service.forgetServer(Boolean(message.deleteHistory));case'explicit-text':return service.explicitText(String(message.text),Boolean(message.send));case'explicit-image':return service.explicitImage();case'publish-file-manifest':return service.publishFileManifest(deserializeItem(message.item as SerializedItem) as FileManifestItem,String(message.channelId));case'copy-current':return service.copyCurrent();case'remove-preview':return service.removePreview();case'reload-clipboard':return service.reloadClipboard();case'reconnect':return service.reconnect();default:throw new Error('Unknown ClipMesh command');}}

interface SerializedItem{type:'text/plain'|'image/png'|typeof FILE_MANIFEST_CONTENT_TYPE;bytes?:string;width?:number;height?:number;fileId?:UUID;filename?:string;mediaType?:string;size?:number;chunkSize?:number;chunkCount?:number;noncePrefix?:string;sha256?:string;expiresAt?:number}
function serializeItem(item:TransferItem):SerializedItem{if(item.type===FILE_MANIFEST_CONTENT_TYPE)return{...item};return{type:item.type,bytes:base64(item.bytes),...(item.type==='image/png'?{width:item.width,height:item.height}:{})};}
function deserializeItem(value:SerializedItem):TransferItem{if(value.type==='text/plain')return{type:'text/plain',bytes:fromBase64(value.bytes??'')};if(value.type==='image/png')return{type:'image/png',bytes:fromBase64(value.bytes??''),width:value.width??0,height:value.height??0};return{type:FILE_MANIFEST_CONTENT_TYPE,fileId:String(value.fileId),filename:String(value.filename),mediaType:String(value.mediaType),size:Number(value.size),chunkSize:Number(value.chunkSize),chunkCount:Number(value.chunkCount),noncePrefix:String(value.noncePrefix),sha256:String(value.sha256),expiresAt:Number(value.expiresAt)};}
function validatedServerUrl(input:string):URL{const url=new URL(input);url.pathname='/';url.search='';url.hash='';const loopback=['localhost','127.0.0.1','[::1]'].includes(url.hostname);if(url.protocol!=='https:'&&!(loopback&&url.protocol==='http:'))throw new Error('HTTPS is required outside loopback development');return url;}
function platform():string{const value=navigator.userAgent.toLowerCase();return value.includes('win')?'windows':value.includes('mac')?'macos':'linux';}
