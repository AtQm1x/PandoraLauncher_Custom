use std::sync::Arc;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Yggdrasil authentication client for authlib-injector compatible servers (e.g. Ely.by).
pub struct YggdrasilClient {
    client: reqwest::Client,
}

#[derive(thiserror::Error, Debug)]
pub enum YggdrasilError {
    #[error("Connection error: {0}")]
    ConnectionError(#[from] reqwest::Error),
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    #[error("Server returned HTTP {0}")]
    NonOkHttpStatus(reqwest::StatusCode),
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),
}

impl YggdrasilError {
    pub fn is_connection_error(&self) -> bool {
        matches!(self, Self::ConnectionError(_))
    }
}

// --- Request/Response types ---

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct YggdrasilAuthenticateRequest<'a> {
    agent: YggdrasilAgent,
    username: &'a str,
    password: &'a str,
    client_token: &'a str,
    request_user: bool,
}

#[derive(Serialize)]
struct YggdrasilAgent {
    name: &'static str,
    version: u32,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct YggdrasilAuthenticateResponse {
    pub access_token: Arc<str>,
    pub client_token: Arc<str>,
    pub selected_profile: Option<YggdrasilProfile>,
    pub available_profiles: Option<Vec<YggdrasilProfile>>,
}

#[derive(Deserialize, Clone)]
pub struct YggdrasilProfile {
    pub id: Arc<str>,
    pub name: Arc<str>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct YggdrasilRefreshRequest<'a> {
    access_token: &'a str,
    client_token: &'a str,
    request_user: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct YggdrasilRefreshResponse {
    pub access_token: Arc<str>,
    pub client_token: Arc<str>,
    pub selected_profile: Option<YggdrasilProfile>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct YggdrasilValidateRequest<'a> {
    access_token: &'a str,
    client_token: &'a str,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct YggdrasilErrorResponse {
    #[serde(default)]
    error_message: Option<String>,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    cause: Option<String>,
}

impl YggdrasilErrorResponse {
    fn into_error_string(self, status: reqwest::StatusCode) -> String {
        let err_msg = self.error_message.or(self.message);
        let msg = match (self.error, err_msg) {
            (Some(err_type), Some(msg)) => format!("{}: {}", err_type, msg),
            (None, Some(msg)) => msg,
            (Some(err_type), None) => err_type,
            (None, None) => format!("HTTP {}", status),
        };
        if let Some(cause) = self.cause {
            format!("{} ({})", msg, cause)
        } else {
            msg
        }
    }
}

async fn parse_error_response(response: reqwest::Response) -> YggdrasilError {
    let status = response.status();
    if let Ok(text) = response.text().await {
        if let Ok(err) = serde_json::from_str::<YggdrasilErrorResponse>(&text) {
            return YggdrasilError::AuthenticationFailed(err.into_error_string(status));
        }
        let trimmed = text.trim();
        if !trimmed.is_empty() && trimmed.len() < 300 && !trimmed.starts_with('<') {
            return YggdrasilError::AuthenticationFailed(format!("HTTP {}: {}", status, trimmed));
        }
    }
    YggdrasilError::NonOkHttpStatus(status)
}

impl YggdrasilClient {
    pub fn new(client: reqwest::Client) -> Self {
        Self { client }
    }

    /// Authenticate with a Yggdrasil-compatible server.
    /// `server_url` should be the base URL of the auth server, e.g. `https://authserver.ely.by`.
    pub async fn authenticate(
        &self,
        server_url: &str,
        username: &str,
        password: &str,
        client_token: &str,
    ) -> Result<YggdrasilAuthenticateResponse, YggdrasilError> {
        let url = format!("{}/authserver/authenticate", server_url.trim_end_matches('/'));

        let request = YggdrasilAuthenticateRequest {
            agent: YggdrasilAgent {
                name: "Minecraft",
                version: 1,
            },
            username,
            password,
            client_token,
            request_user: true,
        };

        let response = self.client.post(&url).json(&request).send().await?;

        if response.status() != reqwest::StatusCode::OK {
            return Err(parse_error_response(response).await);
        }

        let bytes = response.bytes().await?;
        serde_json::from_slice(&bytes).map_err(YggdrasilError::SerializationError)
    }

    /// Refresh an existing Yggdrasil access token.
    pub async fn refresh(
        &self,
        server_url: &str,
        access_token: &str,
        client_token: &str,
    ) -> Result<YggdrasilRefreshResponse, YggdrasilError> {
        let url = format!("{}/authserver/refresh", server_url.trim_end_matches('/'));

        let request = YggdrasilRefreshRequest {
            access_token,
            client_token,
            request_user: true,
        };

        let response = self.client.post(&url).json(&request).send().await?;

        if response.status() != reqwest::StatusCode::OK {
            return Err(parse_error_response(response).await);
        }

        let bytes = response.bytes().await?;
        serde_json::from_slice(&bytes).map_err(YggdrasilError::SerializationError)
    }

    /// Validate an existing Yggdrasil access token. Returns true if valid, false otherwise.
    pub async fn validate(
        &self,
        server_url: &str,
        access_token: &str,
        client_token: &str,
    ) -> Result<bool, YggdrasilError> {
        let url = format!("{}/authserver/validate", server_url.trim_end_matches('/'));

        let request = YggdrasilValidateRequest {
            access_token,
            client_token,
        };

        let response = self.client.post(&url).json(&request).send().await?;

        // 204 No Content = valid, 403 = invalid
        Ok(response.status() == reqwest::StatusCode::NO_CONTENT)
    }

    /// Parse a UUID from a Yggdrasil profile ID (which lacks hyphens).
    pub fn parse_profile_uuid(id: &str) -> Option<Uuid> {
        // Yggdrasil returns UUIDs without hyphens
        Uuid::try_parse(id).ok()
            .or_else(|| {
                if id.len() == 32 {
                    let with_hyphens = format!(
                        "{}-{}-{}-{}-{}",
                        &id[0..8], &id[8..12], &id[12..16], &id[16..20], &id[20..32]
                    );
                    Uuid::try_parse(&with_hyphens).ok()
                } else {
                    None
                }
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_response_formatting() {
        let err = YggdrasilErrorResponse {
            error_message: Some("Invalid credentials. Invalid username or password.".into()),
            message: None,
            error: Some("ForbiddenOperationException".into()),
            cause: None,
        };
        assert_eq!(
            err.into_error_string(reqwest::StatusCode::FORBIDDEN),
            "ForbiddenOperationException: Invalid credentials. Invalid username or password."
        );

        let err2 = YggdrasilErrorResponse {
            error_message: None,
            message: Some("Invalid email or password".into()),
            error: None,
            cause: Some("Bad credentials".into()),
        };
        assert_eq!(
            err2.into_error_string(reqwest::StatusCode::UNAUTHORIZED),
            "Invalid email or password (Bad credentials)"
        );
    }

    #[test]
    fn test_parse_profile_uuid() {
        let unhyphenated = "4566e69f3c7343029f4297a7da9336b9";
        let parsed = YggdrasilClient::parse_profile_uuid(unhyphenated);
        assert!(parsed.is_some());
        assert_eq!(parsed.unwrap().to_string(), "4566e69f-3c73-4302-9f42-97a7da9336b9");
    }
}

