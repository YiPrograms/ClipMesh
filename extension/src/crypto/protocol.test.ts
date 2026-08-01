import { argon2id } from 'hash-wasm';
import { describe, expect, it } from 'vitest';
import vectors from '../../../protocol/test-vectors.json';
import { FILE_CHUNK_BYTES, FILE_MANIFEST_CONTENT_TYPE, type ChannelSecret, type FileManifestItem, type ItemMetadata } from '../shared/types';
import { base64, fromBase64 } from './encoding';
import { buildItemAad, buildJoinMessage, createChannelMaterial, decryptFileChunk, decryptItem, deriveChannelRoots, deriveItemKey, encodeClipboardPayload, encryptFileChunk, encryptItem, unwrapChannelSecret } from './protocol';

const hex=(value:Uint8Array)=>[...value].map((byte)=>byte.toString(16).padStart(2,'0')).join('');

describe('cryptographic protocol',()=>{
  it('matches the shared Rust/TypeScript wire vectors',async()=>{
    const secret:ChannelSecret={version:1,channelId:vectors.channel_id,rootKey:base64(Uint8Array.from(vectors.channel_root_key_hex.match(/../g)??[],(value)=>Number.parseInt(value,16))),membershipPrivateKey:'',membershipPublicKey:'',cryptoVersion:1};
    expect(hex(await deriveItemKey(secret,vectors.item_id))).toBe(vectors.item_key_hex);
    const roots=await deriveChannelRoots(secret);expect(roots.itemRoot).not.toEqual(roots.historyRoot);
    expect(hex(buildJoinMessage(vectors.server_instance_id,vectors.channel_id,vectors.device_id,vectors.challenge_id,fromBase64(vectors.challenge_random_base64),vectors.expires_at))).toBe(vectors.join_message_hex);
    expect(hex(encodeClipboardPayload({type:'text/plain',bytes:new TextEncoder().encode('ClipMesh')}))).toBe(vectors.text_plaintext_hex);
    expect(hex(buildItemAad(vectors.server_instance_id,vectors.channel_id,vectors.item_id,vectors.device_id,'text/plain',vectors.created_at_client))).toBe(vectors.item_aad_hex);
  });
  it('matches an independently generated Argon2id v1.3 vector',async()=>{
    const output=await argon2id({password:'password',salt:'somesalt',iterations:2,memorySize:65536,parallelism:1,hashLength:32,outputType:'binary'});
    expect(hex(output)).toBe('09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7');
  });

  it('encrypts, authenticates, and decrypts an item',async()=>{
    const channelId=crypto.randomUUID(),serverId=crypto.randomUUID(),deviceId=crypto.randomUUID();
    const secret:ChannelSecret={version:1,channelId,rootKey:base64(crypto.getRandomValues(new Uint8Array(32))),membershipPrivateKey:'',membershipPublicKey:'',cryptoVersion:1};
    const item={type:'text/plain' as const,bytes:new TextEncoder().encode('ClipMesh text\nwith preserved lines')};
    const encrypted=await encryptItem(secret,serverId,deviceId,item,'2026-08-01T00:00:00Z');
    const second=await encryptItem(secret,serverId,deviceId,item,'2026-08-01T00:00:00Z');
    expect(encrypted.metadata.id[14]).toBe('7');
    expect(second.metadata.id).not.toBe(encrypted.metadata.id);
    expect(second.metadata.nonce).not.toBe(encrypted.metadata.nonce);
    expect(second.ciphertext).not.toEqual(encrypted.ciphertext);
    const metadata:ItemMetadata={...encrypted.metadata,origin_device_name:'Test device',channel_sequence:1,accepted_at:'2026-08-01T00:00:01Z'};
    await expect(decryptItem(secret,serverId,metadata,encrypted.ciphertext)).resolves.toEqual(item);
    await expect(decryptItem(secret,serverId,{...metadata,origin_device_id:crypto.randomUUID()},encrypted.ciphertext)).rejects.toThrow('authentication failed');
    await expect(decryptItem({...secret,channelId:crypto.randomUUID()},serverId,metadata,encrypted.ciphertext)).rejects.toThrow('inconsistent envelope');
    await expect(decryptItem(secret,serverId,{...metadata,crypto_version:2 as 1},encrypted.ciphertext)).rejects.toThrow('Unsupported');
    const corrupt=encrypted.ciphertext.slice();corrupt[0]=(corrupt[0]??0)^1;
    await expect(decryptItem(secret,serverId,metadata,corrupt)).rejects.toThrow('authentication failed');
  });

  it('round-trips a file manifest and independently authenticated chunks',async()=>{
    const channelId=crypto.randomUUID(),serverId=crypto.randomUUID(),deviceId=crypto.randomUUID();const secret:ChannelSecret={version:1,channelId,rootKey:base64(crypto.getRandomValues(new Uint8Array(32))),membershipPrivateKey:'',membershipPublicKey:'',cryptoVersion:1};const plaintext=new TextEncoder().encode('encrypted file content');
    const manifest:FileManifestItem={type:FILE_MANIFEST_CONTENT_TYPE,fileId:crypto.randomUUID(),filename:'notes.txt',mediaType:'text/plain',size:plaintext.length,chunkSize:FILE_CHUNK_BYTES,chunkCount:1,noncePrefix:base64(crypto.getRandomValues(new Uint8Array(8))),sha256:base64(new Uint8Array(await crypto.subtle.digest('SHA-256',plaintext))),expiresAt:1_900_000_000};
    const ciphertext=await encryptFileChunk(secret,serverId,manifest,0,plaintext);await expect(decryptFileChunk(secret,serverId,manifest,0,ciphertext)).resolves.toEqual(plaintext);const corrupt=ciphertext.slice();corrupt[0]=(corrupt[0]??0)^1;await expect(decryptFileChunk(secret,serverId,manifest,0,corrupt)).rejects.toThrow('authentication failed');
    const envelope=await encryptItem(secret,serverId,deviceId,manifest,'2026-08-01T00:00:00Z');const metadata:ItemMetadata={...envelope.metadata,origin_device_name:'Sender',channel_sequence:1,accepted_at:'2026-08-01T00:00:01Z'};await expect(decryptItem(secret,serverId,metadata,envelope.ciphertext)).resolves.toEqual(manifest);
  });

  it('fails locally for a wrong password',async()=>{
    const material=await createChannelMaterial('six unique words make a safer test passphrase');
    await expect(unwrapChannelSecret('six unique words make a safer test passphrase',material.channelId,material.passwordKdf,material.wrappedSecret,material.membershipPublicKey.spki)).resolves.toMatchObject({rootKey:material.secret.rootKey,membershipPublicKey:material.secret.membershipPublicKey});
    await expect(unwrapChannelSecret('this is the wrong password',material.channelId,material.passwordKdf,material.wrappedSecret,material.membershipPublicKey.spki)).rejects.toThrow('Incorrect password');
  },30_000);
});
