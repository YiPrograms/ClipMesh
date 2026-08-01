//! ClipMesh protocol v1 primitives shared by the server and native client.

pub mod crypto;
pub mod routing;
pub mod wire;

pub const PROTOCOL_VERSION: u16 = 1;
pub const MAX_TEXT_BYTES: usize = 1024 * 1024;
pub const MAX_PNG_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_IMAGE_DIMENSION: u32 = 16_384;
pub const MAX_IMAGE_PIXELS: u64 = 64_000_000;
pub const FILE_MANIFEST_CONTENT_TYPE: &str = "application/vnd.clipmesh.file";
pub const FILE_CHUNK_BYTES: u32 = 4 * 1024 * 1024;
pub const MAX_FILE_MANIFEST_BYTES: usize = 4096;
pub const MAX_FILENAME_BYTES: usize = 255;
pub const MAX_MEDIA_TYPE_BYTES: usize = 255;
