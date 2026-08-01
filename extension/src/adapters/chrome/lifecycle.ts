import type { BackgroundLifecycleAdapter } from '../../shared/types';

export class ChromeLifecycleAdapter implements BackgroundLifecycleAdapter {
  async ensureClipboardContext():Promise<void>{
    const url=chrome.runtime.getURL('offscreen.html');
    const contexts=await chrome.runtime.getContexts({contextTypes:[chrome.runtime.ContextType.OFFSCREEN_DOCUMENT],documentUrls:[url]});
    if(contexts.length===0)await chrome.offscreen.createDocument({url:'offscreen.html',reasons:[chrome.offscreen.Reason.CLIPBOARD],justification:'Monitor and apply supported clipboard items for encrypted synchronization'});
  }
  async keepRealtimeConnectionAlive():Promise<void>{
    await chrome.alarms.create('clipmesh-reconnect',{periodInMinutes:.4});
    await chrome.alarms.create('clipmesh-history-prune',{periodInMinutes:60});
  }
}
