import type { RouteSelection, RoutingMode, UUID } from '../shared/types';

export interface CheckboxRule {
  sendDisabled: boolean;
  receiveDisabled: boolean;
  sendTooltip?: string;
  receiveTooltip?: string;
}

export function routingMode(routes: readonly RouteSelection[]): RoutingMode {
  const send = routes.filter((route) => route.sendEnabled);
  const receive = routes.filter((route) => route.receiveEnabled);
  if (send.length === 0 && receive.length === 0) return 'inactive';
  if (send.length > 0 && receive.length === 0) return 'send-only';
  if (send.length === 0 && receive.length > 0) return 'receive-only';
  if (send.length === 1 && receive.length === 1 && send[0]?.channelId === receive[0]?.channelId) return 'sync';
  throw new Error('Invalid ClipMesh routing state');
}

export function isValidRouting(routes: readonly RouteSelection[]): boolean {
  try { routingMode(routes); return true; } catch { return false; }
}

export function checkboxRules(routes: readonly RouteSelection[], channelName:(id:UUID)=>string=(id)=>id): Map<UUID, CheckboxRule> {
  const mode = routingMode(routes);
  const send = routes.filter((route) => route.sendEnabled);
  const receive = routes.filter((route) => route.receiveEnabled);
  return new Map(routes.map((route) => {
    const rule: CheckboxRule = { sendDisabled: false, receiveDisabled: false };
    if (mode === 'send-only') {
      rule.receiveDisabled = !(send.length === 1 && route.channelId === send[0]?.channelId);
      if (rule.receiveDisabled) rule.receiveTooltip = 'To enable Receive, uncheck Send on all channels except this one, or uncheck all Send channels to enter receive-only mode.';
    } else if (mode === 'receive-only') {
      rule.sendDisabled = !(receive.length === 1 && route.channelId === receive[0]?.channelId);
      if (rule.sendDisabled) rule.sendTooltip = 'To enable Send, uncheck Receive on all channels except this one, or uncheck all Receive channels to enter send-only mode.';
    } else if (mode === 'sync') {
      const synchronized = send[0]?.channelId;
      rule.sendDisabled = route.channelId !== synchronized;
      rule.receiveDisabled = route.channelId !== synchronized;
      if (rule.sendDisabled&&synchronized) rule.sendTooltip = `To send to multiple channels, first turn off Receive on ${channelName(synchronized)}.`;
      if (rule.receiveDisabled&&synchronized) rule.receiveTooltip = `To receive from multiple channels, first turn off Send on ${channelName(synchronized)}.`;
    }
    return [route.channelId, rule];
  }));
}

export function toggleRoute(routes: readonly RouteSelection[], channelId: UUID, side: 'send' | 'receive', enabled: boolean): RouteSelection[] {
  const rules = checkboxRules(routes);
  const rule = rules.get(channelId);
  if (!rule) throw new Error('Unknown channel');
  if (enabled && (side === 'send' ? rule.sendDisabled : rule.receiveDisabled)) throw new Error(`${side} checkbox is disabled`);
  const next = routes.map((route) => route.channelId === channelId ? {
    ...route,
    sendEnabled: side === 'send' ? enabled : route.sendEnabled,
    receiveEnabled: side === 'receive' ? enabled : route.receiveEnabled,
  } : route);
  if (!isValidRouting(next)) throw new Error('Transition would produce an invalid routing state');
  return next;
}

export function addJoinedChannel(routes: readonly RouteSelection[], channelId: UUID): RouteSelection[] {
  if (routes.some((route) => route.channelId === channelId)) return [...routes];
  const first = routes.length === 0;
  return [...routes, { channelId, sendEnabled: first, receiveEnabled: first }];
}

export function removeJoinedChannel(routes: readonly RouteSelection[], channelId: UUID): RouteSelection[] {
  const next = routes.filter((route) => route.channelId !== channelId);
  if (!isValidRouting(next)) throw new Error('Removing channel produced invalid routing state');
  return next;
}
