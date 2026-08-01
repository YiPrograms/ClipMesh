import { FILE_MANIFEST_CONTENT_TYPE, type ContentType, type EncryptedEnvelope, type TransferItem, type UUID } from '../shared/types';

export interface HistorySettings {
  historyEnabled:boolean;
  maxEntries:number;
  maxAgeDays:number;
  maxStorageBytes:number;
  storeSentItems:boolean;
  storeReceivedItems:boolean;
}

export const DEFAULT_HISTORY_SETTINGS:HistorySettings={historyEnabled:true,maxEntries:200,maxAgeDays:7,maxStorageBytes:256*1024*1024,storeSentItems:true,storeReceivedItems:true};

export interface StoredHistoryEntry {
  localId:UUID;
  itemId:UUID;
  channelId:UUID;
  channelNameSnapshot:string;
  originDeviceId:UUID;
  originDeviceNameSnapshot:string;
  direction:'sent'|'received';
  targetChannelIds?:UUID[];
  contentType:ContentType;
  encryptedEnvelope:{metadata:EncryptedEnvelope['metadata'];ciphertext:ArrayBuffer};
  createdAtClient?:string;
  acceptedAtServer?:string;
  storedAtLocal:number;
  deliveryStatus:'pending'|'accepted'|'failed'|'received';
  byteSize:number;
  deliveryByChannel?:Record<UUID,'pending'|'accepted'|'failed'>;
}

export interface OutboxRecord { id:'latest';item:{type:ContentType;bytes?:ArrayBuffer;width?:number;height?:number;fileId?:UUID;filename?:string;mediaType?:string;size?:number;chunkSize?:number;chunkCount?:number;noncePrefix?:string;sha256?:string;expiresAt?:number};capturedAt:string;targetChannelIds:UUID[] }

export class HistoryDatabase {
  private connection?:Promise<IDBDatabase>;
  constructor(private readonly databaseName='clipmesh'){}

  async add(entry:StoredHistoryEntry,settings:HistorySettings):Promise<void>{
    if(!settings.historyEnabled||(entry.direction==='sent'&&!settings.storeSentItems)||(entry.direction==='received'&&!settings.storeReceivedItems))return;
    const db=await this.open();const tx=transaction(db,'history','readwrite');await request(tx.store.put(entry));await tx.done;await this.prune(settings);
  }
  async recent(limit=5):Promise<StoredHistoryEntry[]>{const db=await this.open();const tx=transaction(db,'history');const values=await cursorValues<StoredHistoryEntry>(tx.store.index('storedAtLocal').openCursor(null,'prev'),limit);await tx.done;return values;}
  async usage():Promise<{entries:number;bytes:number}>{const db=await this.open();const tx=transaction(db,'history');const [entries,bytes]=await Promise.all([request(tx.store.count()),sumIndexKeys(tx.store.index('byteSize').openKeyCursor())]);await tx.done;return{entries,bytes};}
  async get(localId:UUID):Promise<StoredHistoryEntry|undefined>{const db=await this.open();return request(transaction(db,'history').store.get(localId));}
  async containsItem(itemId:UUID):Promise<boolean>{const db=await this.open();const entries=await request(transaction(db,'history').store.getAll()) as StoredHistoryEntry[];return entries.some((entry)=>entry.itemId===itemId);}
  async delete(localId:UUID):Promise<void>{const db=await this.open();const tx=transaction(db,'history','readwrite');await request(tx.store.delete(localId));await tx.done;}
  async clear(channelId?:UUID):Promise<void>{const db=await this.open();const tx=transaction(db,'history','readwrite');if(!channelId){await request(tx.store.clear());await tx.done;return;}const entries=await request(tx.store.getAll()) as StoredHistoryEntry[];for(const entry of entries)if(entry.channelId===channelId||entry.targetChannelIds?.includes(channelId))await request(tx.store.delete(entry.localId));await tx.done;}
  async setOutbox(item:TransferItem,targetChannelIds:UUID[]):Promise<void>{const db=await this.open();const stored=item.type===FILE_MANIFEST_CONTENT_TYPE?{...item,type:item.type}:{...item,bytes:item.bytes.buffer.slice(item.bytes.byteOffset,item.bytes.byteOffset+item.bytes.byteLength) as ArrayBuffer};const record:OutboxRecord={id:'latest',item:stored,capturedAt:new Date().toISOString(),targetChannelIds};const tx=transaction(db,'outbox','readwrite');await request(tx.store.put(record));await tx.done;}
  async getOutbox():Promise<OutboxRecord|undefined>{const db=await this.open();return request(transaction(db,'outbox').store.get('latest'));}
  async clearOutbox():Promise<void>{const db=await this.open();const tx=transaction(db,'outbox','readwrite');await request(tx.store.delete('latest'));await tx.done;}
  async prune(settings:HistorySettings):Promise<void>{const db=await this.open();const tx=transaction(db,'history','readwrite');const entries=await request(tx.store.index('storedAtLocal').getAll()) as StoredHistoryEntry[];entries.sort((a,b)=>b.storedAtLocal-a.storedAtLocal);const cutoff=settings.maxAgeDays>0?Date.now()-settings.maxAgeDays*86_400_000:0;let bytes=0;for(let index=0;index<entries.length;index++){const entry=entries[index];if(!entry)continue;bytes+=entry.byteSize;const overCount=settings.maxEntries>0&&index>=settings.maxEntries;const overAge=cutoff>0&&entry.storedAtLocal<cutoff;const overBytes=settings.maxStorageBytes>0&&bytes>settings.maxStorageBytes;if(overCount||overAge||overBytes)await request(tx.store.delete(entry.localId));}await tx.done;}

  private open():Promise<IDBDatabase>{return this.connection??=new Promise((resolve,reject)=>{const opening=indexedDB.open(this.databaseName,2);opening.onupgradeneeded=()=>{const db=opening.result;let store:IDBObjectStore;if(!db.objectStoreNames.contains('history')){store=db.createObjectStore('history',{keyPath:'localId'});store.createIndex('storedAtLocal','storedAtLocal');store.createIndex('channelId','channelId');}else store=opening.transaction!.objectStore('history');if(!store.indexNames.contains('byteSize'))store.createIndex('byteSize','byteSize');if(!db.objectStoreNames.contains('outbox'))db.createObjectStore('outbox',{keyPath:'id'});};opening.onsuccess=()=>resolve(opening.result);opening.onerror=()=>reject(opening.error);});}
}

function transaction(db:IDBDatabase,name:string,mode:IDBTransactionMode='readonly'):{store:IDBObjectStore;done:Promise<void>}{const tx=db.transaction(name,mode);const done=new Promise<void>((resolve,reject)=>{tx.oncomplete=()=>resolve();tx.onabort=()=>reject(tx.error??new Error('IndexedDB transaction aborted'));tx.onerror=()=>reject(tx.error??new Error('IndexedDB transaction failed'));});return{store:tx.objectStore(name),done};}
function request<T>(value:IDBRequest<T>):Promise<T>{return new Promise((resolve,reject)=>{value.onsuccess=()=>resolve(value.result);value.onerror=()=>reject(value.error);});}
function cursorValues<T>(request:IDBRequest<IDBCursorWithValue|null>,limit:number):Promise<T[]>{return new Promise((resolve,reject)=>{const values:T[]=[];request.onsuccess=()=>{const cursor=request.result;if(!cursor||values.length>=limit){resolve(values);return;}values.push(cursor.value as T);cursor.continue();};request.onerror=()=>reject(request.error);});}
function sumIndexKeys(request:IDBRequest<IDBCursor|null>):Promise<number>{return new Promise((resolve,reject)=>{let sum=0;request.onsuccess=()=>{const cursor=request.result;if(!cursor){resolve(sum);return;}if(typeof cursor.key==='number')sum+=cursor.key;cursor.continue();};request.onerror=()=>reject(request.error);});}
