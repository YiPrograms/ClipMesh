use std::{env, net::SocketAddr, path::PathBuf};

use anyhow::{Context, bail};
use url::{Host, Url};

#[derive(Clone, Debug)]
pub struct Config {
    pub listen: SocketAddr,
    pub database_url: String,
    pub blob_dir: PathBuf,
    pub public_url: Url,
    pub instance_name: String,
    pub chrome_store_url: Option<String>,
    pub extension_download_url: Option<Url>,
    pub native_client: Option<NativeClientRelease>,
    pub max_file_bytes: u64,
    pub file_retention: std::time::Duration,
    pub file_storage_quota: u64,
    pub file_channel_quota: u64,
    pub incomplete_upload_retention: std::time::Duration,
}

#[derive(Clone, Debug)]
pub struct NativeClientRelease {
    pub base_url: Url,
    pub version: String,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let listen = env::var("CLIPMESH_LISTEN")
            .unwrap_or_else(|_| "127.0.0.1:8787".into())
            .parse()
            .context("invalid CLIPMESH_LISTEN")?;
        let public_url = Url::parse(
            &env::var("CLIPMESH_PUBLIC_URL").unwrap_or_else(|_| "http://127.0.0.1:8787".into()),
        )
        .context("invalid CLIPMESH_PUBLIC_URL")?;
        if !public_url_is_secure(&public_url) {
            bail!("CLIPMESH_PUBLIC_URL must use HTTPS outside loopback development");
        }
        let loopback = public_url_is_loopback(&public_url);
        let chrome_store_url = env::var("CLIPMESH_CHROME_STORE_URL")
            .ok()
            .filter(|value| !value.trim().is_empty());
        if let Some(value) = chrome_store_url.as_deref()
            && !valid_store_url(value, !loopback)?
        {
            bail!("CLIPMESH_CHROME_STORE_URL must be an HTTPS Chrome Web Store listing URL");
        }
        let extension_download_url = env::var("CLIPMESH_EXTENSION_DOWNLOAD_URL")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .map(|value| valid_extension_download_url(&value))
            .transpose()?;
        if !loopback && chrome_store_url.is_none() && extension_download_url.is_none() {
            bail!(
                "set CLIPMESH_CHROME_STORE_URL or CLIPMESH_EXTENSION_DOWNLOAD_URL for non-loopback deployments"
            );
        }
        let native_client = native_release(
            env::var("CLIPMESH_CLIENT_RELEASE_BASE_URL")
                .ok()
                .filter(|value| !value.trim().is_empty()),
            env::var("CLIPMESH_CLIENT_VERSION")
                .ok()
                .filter(|value| !value.trim().is_empty()),
        )?;
        Ok(Self {
            listen,
            database_url: env::var("CLIPMESH_DATABASE_URL")
                .unwrap_or_else(|_| "sqlite://server/data/clipmesh.db".into()),
            blob_dir: env::var_os("CLIPMESH_BLOB_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("server/data/blobs")),
            public_url,
            instance_name: env::var("CLIPMESH_INSTANCE_NAME")
                .unwrap_or_else(|_| "My ClipMesh".into()),
            chrome_store_url,
            extension_download_url,
            native_client,
            max_file_bytes: env_bytes("CLIPMESH_MAX_FILE_BYTES", 2 * 1024 * 1024 * 1024)?,
            file_retention: env_duration("CLIPMESH_FILE_RETENTION", 7 * 24 * 60 * 60)?,
            file_storage_quota: env_bytes("CLIPMESH_FILE_STORAGE_QUOTA", 50 * 1024 * 1024 * 1024)?,
            file_channel_quota: env_bytes("CLIPMESH_FILE_CHANNEL_QUOTA", 10 * 1024 * 1024 * 1024)?,
            incomplete_upload_retention: env_duration(
                "CLIPMESH_INCOMPLETE_UPLOAD_RETENTION",
                60 * 60,
            )?,
        })
    }

    #[doc(hidden)]
    pub fn test(database_url: String, blob_dir: PathBuf) -> Self {
        Self {
            listen: "127.0.0.1:0".parse().unwrap(),
            database_url,
            blob_dir,
            public_url: Url::parse("http://127.0.0.1:8787").unwrap(),
            instance_name: "Test ClipMesh".into(),
            chrome_store_url: Some("https://example.test/store".into()),
            extension_download_url: None,
            native_client: None,
            max_file_bytes: 2 * 1024 * 1024 * 1024,
            file_retention: std::time::Duration::from_secs(7 * 24 * 60 * 60),
            file_storage_quota: 50 * 1024 * 1024 * 1024,
            file_channel_quota: 10 * 1024 * 1024 * 1024,
            incomplete_upload_retention: std::time::Duration::from_secs(60 * 60),
        }
    }
}

fn env_bytes(name: &str, default: u64) -> anyhow::Result<u64> {
    let Some(raw) = env::var(name).ok() else {
        return Ok(default);
    };
    let value = raw.trim();
    let split = value
        .find(|character: char| !character.is_ascii_digit())
        .unwrap_or(value.len());
    let number: u64 = value[..split]
        .parse()
        .with_context(|| format!("invalid {name}"))?;
    let unit = value[split..].trim().to_ascii_lowercase();
    let multiplier = match unit.as_str() {
        "" | "b" => 1,
        "kib" => 1024,
        "mib" => 1024 * 1024,
        "gib" => 1024 * 1024 * 1024,
        "tib" => 1024_u64.pow(4),
        _ => bail!("invalid {name}: use B, KiB, MiB, GiB, or TiB"),
    };
    let result = number
        .checked_mul(multiplier)
        .with_context(|| format!("{name} is too large"))?;
    if result == 0 || result > i64::MAX as u64 {
        bail!("{name} must be between 1 byte and {} bytes", i64::MAX);
    }
    Ok(result)
}

fn env_duration(name: &str, default_seconds: u64) -> anyhow::Result<std::time::Duration> {
    let Some(raw) = env::var(name).ok() else {
        return Ok(std::time::Duration::from_secs(default_seconds));
    };
    let value = raw.trim();
    let split = value
        .find(|character: char| !character.is_ascii_digit())
        .unwrap_or(value.len());
    let number: u64 = value[..split]
        .parse()
        .with_context(|| format!("invalid {name}"))?;
    let multiplier = match value[split..].trim().to_ascii_lowercase().as_str() {
        "s" => 1,
        "m" => 60,
        "h" => 60 * 60,
        "d" => 24 * 60 * 60,
        _ => bail!("invalid {name}: use s, m, h, or d"),
    };
    let seconds = number
        .checked_mul(multiplier)
        .with_context(|| format!("{name} is too large"))?;
    if seconds == 0 || seconds > i64::MAX as u64 {
        bail!("{name} must be positive");
    }
    Ok(std::time::Duration::from_secs(seconds))
}

fn native_release(
    base: Option<String>,
    version: Option<String>,
) -> anyhow::Result<Option<NativeClientRelease>> {
    let (base, version) = match (base, version) {
        (None, None) => return Ok(None),
        (Some(base), Some(version)) => (base, version),
        _ => bail!(
            "CLIPMESH_CLIENT_RELEASE_BASE_URL and CLIPMESH_CLIENT_VERSION must be set together"
        ),
    };
    if version.is_empty()
        || !version
            .chars()
            .all(|value| value.is_ascii_alphanumeric() || matches!(value, '.' | '-' | '+'))
    {
        bail!("CLIPMESH_CLIENT_VERSION is invalid");
    }
    let mut base_url = Url::parse(&base).context("invalid CLIPMESH_CLIENT_RELEASE_BASE_URL")?;
    if !public_url_is_secure(&base_url) {
        bail!("CLIPMESH_CLIENT_RELEASE_BASE_URL must use HTTPS outside loopback development");
    }
    if base_url.query().is_some() || base_url.fragment().is_some() {
        bail!("CLIPMESH_CLIENT_RELEASE_BASE_URL cannot contain a query or fragment");
    }
    if !base_url.path().ends_with('/') {
        base_url.set_path(&format!("{}/", base_url.path()));
    }
    Ok(Some(NativeClientRelease { base_url, version }))
}

fn public_url_is_secure(url: &Url) -> bool {
    if url.scheme() == "https" {
        return true;
    }
    if url.scheme() != "http" {
        return false;
    }
    public_url_is_loopback(url)
}

fn public_url_is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(Host::Domain("localhost")) => true,
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => address.is_loopback(),
        _ => false,
    }
}

fn valid_store_url(value: &str, require_listing: bool) -> anyhow::Result<bool> {
    let url = Url::parse(value)?;
    if url.scheme() != "https" {
        return Ok(false);
    }
    let valid_host = matches!(
        url.host_str(),
        Some("chromewebstore.google.com" | "chrome.google.com")
    );
    let listing = url.path().contains("/detail/");
    Ok(valid_host && (!require_listing || listing))
}

fn valid_extension_download_url(value: &str) -> anyhow::Result<Url> {
    let url = Url::parse(value).context("invalid CLIPMESH_EXTENSION_DOWNLOAD_URL")?;
    if !public_url_is_secure(&url) {
        bail!("CLIPMESH_EXTENSION_DOWNLOAD_URL must use HTTPS outside loopback development");
    }
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        bail!("CLIPMESH_EXTENSION_DOWNLOAD_URL cannot contain credentials, a query, or a fragment");
    }
    if !url.path().to_ascii_lowercase().ends_with(".zip") {
        bail!("CLIPMESH_EXTENSION_DOWNLOAD_URL must point to a ZIP file");
    }
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_policy_allows_https_and_loopback_only() {
        for value in [
            "https://mesh.example",
            "http://localhost:8787",
            "http://127.0.0.1:8787",
            "http://[::1]:8787",
        ] {
            assert!(public_url_is_secure(&Url::parse(value).unwrap()), "{value}");
        }
        for value in [
            "http://mesh.example",
            "http://192.168.1.2",
            "ftp://localhost",
        ] {
            assert!(
                !public_url_is_secure(&Url::parse(value).unwrap()),
                "{value}"
            );
        }
    }

    #[test]
    fn production_store_url_must_be_a_chrome_web_store_listing() {
        assert!(
            valid_store_url(
                "https://chromewebstore.google.com/detail/clipmesh/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                true
            )
            .unwrap()
        );
        for value in [
            "https://chromewebstore.google.com/",
            "https://example.com/detail/clipmesh",
            "http://chromewebstore.google.com/detail/clipmesh/id",
        ] {
            assert!(!valid_store_url(value, true).unwrap(), "{value}");
        }
    }

    #[test]
    fn manual_extension_download_must_be_a_secure_zip() {
        let value = valid_extension_download_url(
            "https://github.com/YiPrograms/ClipMesh/releases/download/v0.3.0/clipmesh-extension-v0.3.0.zip",
        )
        .unwrap();
        assert_eq!(value.scheme(), "https");
        for value in [
            "http://downloads.example/clipmesh.zip",
            "https://downloads.example/clipmesh.crx",
            "https://user:secret@downloads.example/clipmesh.zip",
            "https://downloads.example/clipmesh.zip?token=secret",
            "https://downloads.example/clipmesh.zip#fragment",
        ] {
            assert!(valid_extension_download_url(value).is_err(), "{value}");
        }
    }

    #[test]
    fn native_release_requires_a_complete_secure_pair() {
        assert!(native_release(None, None).unwrap().is_none());
        assert!(native_release(Some("https://downloads.example/v1".into()), None).is_err());
        assert!(
            native_release(
                Some("http://downloads.example/v1".into()),
                Some("0.3.0".into())
            )
            .is_err()
        );
        let value = native_release(
            Some("https://downloads.example/v0.3.0".into()),
            Some("0.3.0".into()),
        )
        .unwrap()
        .unwrap();
        assert_eq!(value.base_url.as_str(), "https://downloads.example/v0.3.0/");
    }
}
