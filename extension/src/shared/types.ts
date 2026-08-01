export type UUID = string;
export const FILE_MANIFEST_CONTENT_TYPE = 'application/vnd.clipmesh.file' as const;
export const FILE_CHUNK_BYTES = 4 * 1024 * 1024;
export type ContentType = 'text/plain' | 'image/png' | typeof FILE_MANIFEST_CONTENT_TYPE;

export interface TextClipboardItem {
  type: 'text/plain';
  bytes: Uint8Array;
}

export interface ImageClipboardItem {
  type: 'image/png';
  bytes: Uint8Array;
  width: number;
  height: number;
}

export interface FileManifestItem {
  type: typeof FILE_MANIFEST_CONTENT_TYPE;
  fileId: UUID;
  filename: string;
  mediaType: string;
  size: number;
  chunkSize: number;
  chunkCount: number;
  noncePrefix: string;
  sha256: string;
  expiresAt: number;
}

export type NormalizedClipboardItem = TextClipboardItem | ImageClipboardItem;
export type TransferItem = NormalizedClipboardItem | FileManifestItem;
export type StopWatching = () => void;

export interface ClipboardAdapter {
  readSupportedItem(): Promise<NormalizedClipboardItem | null>;
  writeItem(item: NormalizedClipboardItem): Promise<void>;
  watchChanges(onChange: () => void): Promise<StopWatching>;
}

export interface BackgroundLifecycleAdapter {
  ensureClipboardContext(): Promise<void>;
  keepRealtimeConnectionAlive(): Promise<void>;
}

export interface ExtensionStorageAdapter {
  get<T>(key: string): Promise<T | undefined>;
  set<T>(key: string, value: T): Promise<void>;
  remove(key: string): Promise<void>;
}

export interface RouteSelection {
  channelId: UUID;
  sendEnabled: boolean;
  receiveEnabled: boolean;
}

export type RoutingMode = 'inactive' | 'send-only' | 'receive-only' | 'sync';

export interface KdfParameters {
  name: 'argon2id';
  salt: string;
  memory_kib: number;
  iterations: number;
  parallelism: number;
  output_bytes: 32;
}

export interface WrappedSecret {
  algorithm: 'aes-256-gcm';
  nonce: string;
  ciphertext: string;
}

export interface MembershipPublicKey {
  algorithm: 'ecdsa-p256-sha256';
  spki: string;
}

export interface ChannelSecret {
  version: 1;
  channelId: UUID;
  rootKey: string;
  membershipPrivateKey: string;
  membershipPublicKey: string;
  cryptoVersion: 1;
}

export interface ServerConfig {
  url: string;
  instanceId: UUID;
  deviceId: UUID;
  deviceName: string;
  deviceToken: string;
  serverVersion?: string;
}

export interface JoinedChannel {
  id: UUID;
  name: string;
  cryptoVersion: 1;
  kdf: KdfParameters;
  secret: ChannelSecret;
}

export interface ItemMetadata {
  id: UUID;
  channel_id: UUID;
  origin_device_id: UUID;
  origin_device_name: string;
  channel_sequence: number;
  crypto_version: number;
  content_type: ContentType;
  ciphertext_size: number;
  plaintext_size?: number;
  image_width?: number;
  image_height?: number;
  nonce: string;
  created_at_client?: string;
  accepted_at: string;
}

export interface EncryptedEnvelope {
  metadata: Omit<ItemMetadata, 'origin_device_name' | 'channel_sequence' | 'accepted_at'> & {file_id?:UUID};
  ciphertext: Uint8Array;
}

export interface PauseState {
  sending: boolean;
  receiving: boolean;
  until?: number;
}
