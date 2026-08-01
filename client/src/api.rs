use anyhow::{Context, bail};
use clipmesh_protocol::{crypto::EncryptedEnvelope, wire::*};
use reqwest::{Client, StatusCode};
use serde::{Serialize, de::DeserializeOwned};
use url::Url;
use uuid::Uuid;

use crate::state::{ServerRecord, ServerSecrets};

#[derive(Clone)]
pub struct Api {
    client: Client,
    base: Url,
    token: Option<String>,
}

impl Api {
    pub fn public(server_url: &str) -> anyhow::Result<Self> {
        let base = validated_server_url(server_url)?;
        Ok(Self {
            client: Client::builder()
                .user_agent(concat!("clipmesh/", env!("CARGO_PKG_VERSION")))
                .build()?,
            base,
            token: None,
        })
    }

    pub fn authenticated(server: &ServerRecord, secrets: &ServerSecrets) -> anyhow::Result<Self> {
        let mut api = Self::public(&server.url)?;
        api.token = Some(secrets.device_token.clone());
        Ok(api)
    }

    pub async fn info(&self) -> anyhow::Result<ServerInfo> {
        self.get("api/v1/info").await
    }

    pub async fn register(
        &self,
        request: &RegisterDeviceRequest,
    ) -> anyhow::Result<RegisterDeviceResponse> {
        self.post_json("api/v1/devices/register", request).await
    }
    pub async fn channels(&self) -> anyhow::Result<Vec<ChannelSummary>> {
        self.get("api/v1/channels").await
    }
    pub async fn create_channel(
        &self,
        request: &CreateChannelRequest,
    ) -> anyhow::Result<ChannelSummary> {
        self.post_json("api/v1/channels", request).await
    }
    pub async fn join_parameters(&self, id: Uuid) -> anyhow::Result<JoinParametersResponse> {
        self.get(&format!("api/v1/channels/{id}/join-parameters"))
            .await
    }
    pub async fn join_challenge(&self, id: Uuid) -> anyhow::Result<JoinChallengeResponse> {
        self.post_empty(&format!("api/v1/channels/{id}/join-challenge"))
            .await
    }
    pub async fn join(&self, id: Uuid, request: &JoinChannelRequest) -> anyhow::Result<()> {
        self.send_empty(
            self.request(reqwest::Method::POST, &format!("api/v1/channels/{id}/join"))?
                .json(request),
        )
        .await
    }
    pub async fn leave(&self, id: Uuid) -> anyhow::Result<()> {
        self.send_empty(self.request(
            reqwest::Method::POST,
            &format!("api/v1/channels/{id}/leave"),
        )?)
        .await
    }
    pub async fn delete_channel(&self, id: Uuid) -> anyhow::Result<()> {
        self.send_empty(self.request(reqwest::Method::DELETE, &format!("api/v1/channels/{id}"))?)
            .await
    }
    pub async fn current(&self, id: Uuid) -> anyhow::Result<Option<ItemMetadata>> {
        let response = self
            .request(
                reqwest::Method::GET,
                &format!("api/v1/channels/{id}/current"),
            )?
            .send()
            .await?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        Ok(Some(decode(response).await?))
    }
    pub async fn files(&self, channel_id: Uuid) -> anyhow::Result<Vec<ItemMetadata>> {
        self.get(&format!("api/v1/channels/{channel_id}/files"))
            .await
    }
    pub async fn content(&self, id: Uuid) -> anyhow::Result<Vec<u8>> {
        let response = self
            .request(reqwest::Method::GET, &format!("api/v1/items/{id}/content"))?
            .send()
            .await?;
        let response = ensure_success(response).await?;
        let value = response.bytes().await?;
        if value.len() > clipmesh_protocol::MAX_PNG_BYTES + 16 {
            bail!("server ciphertext exceeds limits");
        }
        Ok(value.to_vec())
    }
    pub async fn ack(&self, item: &ItemMetadata) -> anyhow::Result<()> {
        self.send_empty(
            self.request(
                reqwest::Method::POST,
                &format!("api/v1/items/{}/ack", item.id),
            )?
            .json(
                &serde_json::json!({"channel_id":item.channel_id,"sequence":item.channel_sequence}),
            ),
        )
        .await
    }

    pub async fn upload(&self, envelope: &EncryptedEnvelope) -> anyhow::Result<UploadResponse> {
        let mut request = self
            .request(
                reqwest::Method::POST,
                &format!("api/v1/channels/{}/items", envelope.channel_id),
            )?
            .header("content-type", "application/octet-stream")
            .header("idempotency-key", envelope.id.to_string())
            .header("x-crypto-version", envelope.crypto_version)
            .header("x-content-type", &envelope.content_type)
            .header("x-envelope-nonce", &envelope.nonce)
            .header("x-client-created-at", &envelope.created_at_client)
            .header("x-plaintext-size", envelope.plaintext_size);
        if let Some(value) = envelope.image_width {
            request = request.header("x-image-width", value);
        }
        if let Some(value) = envelope.image_height {
            request = request.header("x-image-height", value);
        }
        if let Some(value) = envelope.file_id {
            request = request.header("x-file-id", value.to_string());
        }
        let result: UploadResponse =
            decode(request.body(envelope.ciphertext.clone()).send().await?).await?;
        if result.id != envelope.id {
            bail!("server returned a mismatched item receipt");
        }
        Ok(result)
    }

    pub async fn create_file(
        &self,
        channel_id: Uuid,
        request: &CreateFileRequest,
    ) -> anyhow::Result<FileObjectResponse> {
        self.post_json(&format!("api/v1/channels/{channel_id}/files"), request)
            .await
    }

    pub async fn upload_file_chunk(
        &self,
        file_id: Uuid,
        index: u32,
        ciphertext: Vec<u8>,
    ) -> anyhow::Result<()> {
        self.send_empty(
            self.request(
                reqwest::Method::PUT,
                &format!("api/v1/files/{file_id}/chunks/{index}"),
            )?
            .header("content-type", "application/octet-stream")
            .body(ciphertext),
        )
        .await
    }

    pub async fn complete_file(&self, file_id: Uuid) -> anyhow::Result<FileObjectResponse> {
        self.post_empty(&format!("api/v1/files/{file_id}/complete"))
            .await
    }

    pub async fn file_metadata(&self, file_id: Uuid) -> anyhow::Result<FileObjectResponse> {
        self.get(&format!("api/v1/files/{file_id}")).await
    }

    pub async fn file_chunk(&self, file_id: Uuid, index: u32) -> anyhow::Result<Vec<u8>> {
        let response = ensure_success(
            self.request(
                reqwest::Method::GET,
                &format!("api/v1/files/{file_id}/chunks/{index}"),
            )?
            .send()
            .await?,
        )
        .await?;
        let declared = response.content_length();
        if declared.is_some_and(|value| value > u64::from(clipmesh_protocol::FILE_CHUNK_BYTES) + 16)
        {
            bail!("server file chunk exceeds limits");
        }
        let bytes = response.bytes().await?;
        if bytes.len() > clipmesh_protocol::FILE_CHUNK_BYTES as usize + 16 {
            bail!("server file chunk exceeds limits");
        }
        Ok(bytes.to_vec())
    }

    fn request(
        &self,
        method: reqwest::Method,
        path: &str,
    ) -> anyhow::Result<reqwest::RequestBuilder> {
        let url = self.base.join(path)?;
        let mut request = self.client.request(method, url);
        if let Some(token) = &self.token {
            request = request.bearer_auth(token);
        }
        Ok(request)
    }
    async fn get<T: DeserializeOwned>(&self, path: &str) -> anyhow::Result<T> {
        decode(self.request(reqwest::Method::GET, path)?.send().await?).await
    }
    async fn post_json<T: DeserializeOwned>(
        &self,
        path: &str,
        value: &impl Serialize,
    ) -> anyhow::Result<T> {
        decode(
            self.request(reqwest::Method::POST, path)?
                .json(value)
                .send()
                .await?,
        )
        .await
    }
    async fn post_empty<T: DeserializeOwned>(&self, path: &str) -> anyhow::Result<T> {
        decode(self.request(reqwest::Method::POST, path)?.send().await?).await
    }
    async fn send_empty(&self, request: reqwest::RequestBuilder) -> anyhow::Result<()> {
        ensure_success(request.send().await?).await?;
        Ok(())
    }
}

pub fn validated_server_url(value: &str) -> anyhow::Result<Url> {
    let mut url = Url::parse(value).context("server must be a valid URL")?;
    let loopback = match url.host() {
        Some(url::Host::Domain("localhost")) => true,
        Some(url::Host::Ipv4(address)) => address.is_loopback(),
        Some(url::Host::Ipv6(address)) => address.is_loopback(),
        _ => false,
    };
    if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
        bail!("server must use HTTPS (HTTP is allowed only on loopback)");
    }
    if url.query().is_some() || url.fragment().is_some() {
        bail!("server URL cannot contain a query or fragment");
    }
    if !url.path().ends_with('/') {
        url.set_path(&format!("{}/", url.path()));
    }
    Ok(url)
}

async fn decode<T: DeserializeOwned>(response: reqwest::Response) -> anyhow::Result<T> {
    ensure_success(response)
        .await?
        .json()
        .await
        .context("server returned an invalid protocol payload")
}
async fn ensure_success(response: reqwest::Response) -> anyhow::Result<reqwest::Response> {
    if response.status().is_success() {
        return Ok(response);
    }
    let status = response.status();
    let body: serde_json::Value = response.json().await.unwrap_or_default();
    bail!(
        "{}",
        body.get("error")
            .and_then(|value| value.as_str())
            .map(str::to_owned)
            .unwrap_or_else(|| format!("server returned {status}"))
    )
}
