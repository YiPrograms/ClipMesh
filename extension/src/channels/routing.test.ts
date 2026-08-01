import { describe, expect, it } from 'vitest';
import { addJoinedChannel, checkboxRules, removeJoinedChannel, routingMode, toggleRoute } from './routing';
import type { RouteSelection } from '../shared/types';

const routes = (...rows: Array<[string, boolean, boolean]>): RouteSelection[] => rows.map(([channelId, sendEnabled, receiveEnabled]) => ({channelId, sendEnabled, receiveEnabled}));

describe('routing state machine', () => {
  it('defaults the first channel to Sync and disables a second channel', () => {
    const first = addJoinedChannel([], 'a');
    expect(routingMode(first)).toBe('sync');
    const second = addJoinedChannel(first, 'b');
    expect(checkboxRules(second).get('b')).toMatchObject({sendDisabled:true,receiveDisabled:true});
  });

  it('leaves Sync through either enabled side', () => {
    const sync = routes(['a',true,true],['b',false,false]);
    const sendOnly = toggleRoute(sync,'a','receive',false);
    expect(routingMode(sendOnly)).toBe('send-only');
    expect(checkboxRules(sendOnly).get('b')?.sendDisabled).toBe(false);
    const receiveOnly = toggleRoute(sync,'a','send',false);
    expect(routingMode(receiveOnly)).toBe('receive-only');
    expect(checkboxRules(receiveOnly).get('b')?.receiveDisabled).toBe(false);
  });

  it('allows many channels only on one routing side', () => {
    let state = routes(['a',true,false],['b',false,false]);
    state = toggleRoute(state,'b','send',true);
    expect(routingMode(state)).toBe('send-only');
    expect([...checkboxRules(state).values()].every((rule)=>rule.receiveDisabled)).toBe(true);
    expect(()=>toggleRoute(state,'a','receive',true)).toThrow('disabled');
  });

  it('disables every Send checkbox when multiple Receives are selected',()=>{
    const state=routes(['a',false,true],['b',false,true],['c',false,false]);
    expect([...checkboxRules(state).values()].every((rule)=>rule.sendDisabled)).toBe(true);
    expect(()=>toggleRoute(state,'c','send',true)).toThrow('disabled');
  });

  it('never commits cross-channel Sync combinations',()=>{
    const sendA=routes(['a',true,false],['b',false,false]);
    expect(()=>toggleRoute(sendA,'b','receive',true)).toThrow('disabled');
    const receiveA=routes(['a',false,true],['b',false,false]);
    expect(()=>toggleRoute(receiveA,'b','send',true)).toThrow('disabled');
  });

  it('removes selected channels without invalid intermediate state', () => {
    expect(routingMode(removeJoinedChannel(routes(['a',true,true],['b',false,false]),'a'))).toBe('inactive');
    expect(routingMode(removeJoinedChannel(routes(['a',true,false],['b',true,false]),'a'))).toBe('send-only');
  });
});
