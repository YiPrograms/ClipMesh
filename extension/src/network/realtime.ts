import type { ItemMetadata, ServerConfig, UUID } from '../shared/types';
import { ApiClient } from './api';

export type ConnectionState='not-configured'|'connecting'|'connected'|'reconnecting'|'authentication-failed'|'server-error'|'paused';

export class RealtimeClient {
  private socket?:WebSocket;
  private retry?:number;
  private heartbeat?:number;
  private stopped=true;
  private stableSince=0;
  private retryAttempt=0;
  private messageQueue=Promise.resolve();

  constructor(private readonly config:ServerConfig,private readonly receiveChannels:()=>UUID[],private readonly lastSequences:()=>Record<UUID,number>,private readonly onItem:(item:ItemMetadata)=>Promise<void>,private readonly onState:(state:ConnectionState)=>void,private readonly onControl:(message:unknown)=>Promise<void>){ }

  start():void{if(!this.stopped)return;this.stopped=false;void this.connect();}
  stop():void{this.stopped=true;if(this.retry)clearTimeout(this.retry);if(this.heartbeat)clearInterval(this.heartbeat);this.socket?.close();this.socket=undefined;}
  connected():boolean{return this.socket?.readyState===WebSocket.OPEN;}
  routingChanged():void{this.send({type:'routing_update',receive_channel_ids:this.receiveChannels(),last_sequences:this.lastSequences()});}
  ack(item:ItemMetadata):void{this.send({type:'ack',channel_id:item.channel_id,item_id:item.id,sequence:item.channel_sequence});}

  private async connect():Promise<void>{
    if(this.stopped)return;this.onState(this.stableSince?'reconnecting':'connecting');
    try{
      const url=await new ApiClient(this.config).websocketUrl();
      const socket=new WebSocket(url);this.socket=socket;
      socket.onopen=()=>{this.stableSince=Date.now();this.onState('connected');this.send({type:'hello',last_sequences:this.lastSequences(),receive_channel_ids:this.receiveChannels()});this.heartbeat=globalThis.setInterval(()=>this.send({type:'ping',sent_at:new Date().toISOString()}),20_000);};
      socket.onmessage=(event)=>{this.messageQueue=this.messageQueue.then(()=>this.handleMessage(String(event.data))).catch(()=>this.onState('server-error'));};
      socket.onerror=()=>this.onState('server-error');
      socket.onclose=(event)=>{if(this.heartbeat)clearInterval(this.heartbeat);this.heartbeat=undefined;this.socket=undefined;if(event.code===1008)this.onState('authentication-failed');if(!this.stopped)this.scheduleReconnect();};
    }catch(error){this.onState(error instanceof Error&&/auth/i.test(error.message)?'authentication-failed':'server-error');this.scheduleReconnect();}
  }

  private async handleMessage(text:string):Promise<void>{
    let message:unknown;try{message=JSON.parse(text);}catch{return;}
    if(!message||typeof message!=='object'||!('type'in message)||typeof message.type!=='string')return;
    if(message.type==='item_created'&&'item'in message&&validItem(message.item))await this.onItem(message.item);
    else await this.onControl(message);
  }
  private send(value:unknown):void{if(this.socket?.readyState===WebSocket.OPEN)this.socket.send(JSON.stringify(value));}
  private scheduleReconnect():void{const stable=this.stableSince&&Date.now()-this.stableSince>30_000;this.retryAttempt=stable?0:this.retryAttempt+1;const delay=Math.min(60_000,1000*2**Math.min(this.retryAttempt,6))*(.75+Math.random()*.5);this.retry=globalThis.setTimeout(()=>void this.connect(),delay);}
}

function validItem(value:unknown):value is ItemMetadata{if(!value||typeof value!=='object')return false;const item=value as Partial<ItemMetadata>;const uuid=(candidate:unknown)=>typeof candidate==='string'&&/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(candidate);const integer=(candidate:unknown)=>typeof candidate==='number'&&Number.isSafeInteger(candidate)&&candidate>=0;const common=uuid(item.id)&&uuid(item.channel_id)&&uuid(item.origin_device_id)&&typeof item.origin_device_name==='string'&&item.origin_device_name.length<=320&&integer(item.channel_sequence)&&item.crypto_version===1&&(item.content_type==='text/plain'||item.content_type==='image/png')&&integer(item.ciphertext_size)&&(item.ciphertext_size as number)<=16*1024*1024+16&&integer(item.plaintext_size)&&typeof item.nonce==='string'&&item.nonce.length<=32&&typeof item.accepted_at==='string'&&(item.created_at_client===undefined||typeof item.created_at_client==='string');return common&&(item.content_type==='text/plain'||(integer(item.image_width)&&integer(item.image_height)&&item.image_width!<=16_384&&item.image_height!<=16_384&&item.image_width!*item.image_height!<=64_000_000));}
