import 'fake-indexeddb/auto';
import { describe, expect, it } from 'vitest';
import { DEFAULT_HISTORY_SETTINGS, HistoryDatabase, type StoredHistoryEntry } from './database';
import { FILE_CHUNK_BYTES, FILE_MANIFEST_CONTENT_TYPE } from '../shared/types';

const database=()=>new HistoryDatabase(`clipmesh-${crypto.randomUUID()}`);

function entry(index:number,age=0,bytes=10):StoredHistoryEntry{return{localId:crypto.randomUUID(),itemId:crypto.randomUUID(),channelId:'channel',channelNameSnapshot:'Channel',originDeviceId:'device',originDeviceNameSnapshot:'Device',direction:'sent',contentType:'text/plain',encryptedEnvelope:{metadata:{id:crypto.randomUUID(),channel_id:'channel',origin_device_id:'device',crypto_version:1,content_type:'text/plain',ciphertext_size:bytes,plaintext_size:Math.max(0,bytes-16),nonce:'nonce',created_at_client:new Date().toISOString()},ciphertext:new ArrayBuffer(bytes)},storedAtLocal:Date.now()-age-index,deliveryStatus:'accepted',byteSize:bytes};}

describe('local history bounds',()=>{
  it('prunes by entry count',async()=>{const db=database();const settings={...DEFAULT_HISTORY_SETTINGS,maxEntries:2,maxAgeDays:0,maxStorageBytes:0};await db.add(entry(1),settings);await db.add(entry(2),settings);await db.add(entry(3),settings);expect(await db.recent(10)).toHaveLength(2);});
  it('prunes by age',async()=>{const db=database();const settings={...DEFAULT_HISTORY_SETTINGS,maxEntries:0,maxAgeDays:1,maxStorageBytes:0};await db.add(entry(1,2*86_400_000),settings);await db.add(entry(2),settings);expect(await db.recent(10)).toHaveLength(1);});
  it('prunes by byte budget, reports usage without envelope scans, and keeps only one latest outbox item',async()=>{const db=database();const settings={...DEFAULT_HISTORY_SETTINGS,maxEntries:0,maxAgeDays:0,maxStorageBytes:15};await db.add(entry(1,0,10),settings);await db.add(entry(2,0,10),settings);expect(await db.recent(10)).toHaveLength(1);expect(await db.usage()).toEqual({entries:1,bytes:10});await db.setOutbox({type:'text/plain',bytes:new TextEncoder().encode('first')},['a']);await db.setOutbox({type:'text/plain',bytes:new TextEncoder().encode('newest')},['b']);const outbox=await db.getOutbox();expect(new TextDecoder().decode(outbox?.item.bytes)).toBe('newest');expect(outbox?.targetChannelIds).toEqual(['b']);});
  it('stores only a file manifest in the outbox',async()=>{const db=database();await db.setOutbox({type:FILE_MANIFEST_CONTENT_TYPE,fileId:crypto.randomUUID(),filename:'archive.zip',mediaType:'application/zip',size:99,chunkSize:FILE_CHUNK_BYTES,chunkCount:1,noncePrefix:'AAAAAAAAAAA=',sha256:'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',expiresAt:1_900_000_000},['channel']);const outbox=await db.getOutbox();expect(outbox?.item.filename).toBe('archive.zip');expect(outbox?.item.bytes).toBeUndefined();});
});
