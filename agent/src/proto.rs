use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration, Serialize, Deserialize)]
#[repr(i32)]
pub enum ExecutionMode {
    Unspecified = 0,
    Passive = 1,
    Active = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration, Serialize, Deserialize)]
#[repr(i32)]
pub enum CryptoRole {
    Unspecified = 0,
    Kem = 1,
    KeyExchange = 2,
    Signature = 3,
    CertPublicKey = 4,
    CertSignature = 5,
    Symmetric = 6,
    Hash = 7,
    Mac = 8,
    Kdf = 9,
    Random = 10,
    KeyStorage = 11,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration, Serialize, Deserialize)]
#[repr(i32)]
pub enum RiskSeverity {
    Unspecified = 0,
    Info = 1,
    Low = 2,
    Medium = 3,
    High = 4,
    Critical = 5,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration, Serialize, Deserialize)]
#[repr(i32)]
pub enum MigrationState {
    Unspecified = 0,
    Pending = 1,
    Locked = 2,
    Applying = 3,
    Validating = 4,
    RollingBack = 5,
    Succeeded = 6,
    Failed = 7,
}

#[derive(Clone, PartialEq, ::prost::Message, Serialize, Deserialize)]
pub struct AgentRegistration {
    #[prost(string, tag = "1")]
    pub host_uuid: String,
    #[prost(string, tag = "2")]
    pub hostname: String,
    #[prost(string, repeated, tag = "3")]
    pub hardware_signatures: Vec<String>,
    #[prost(string, tag = "4")]
    pub os_name: String,
    #[prost(string, tag = "5")]
    pub os_version: String,
    #[prost(string, tag = "6")]
    pub arch: String,
    #[prost(enumeration = "ExecutionMode", tag = "7")]
    pub execution_mode: i32,
    #[prost(string, tag = "8")]
    pub agent_version: String,
    #[prost(string, repeated, tag = "9")]
    pub capabilities: Vec<String>,
    #[prost(int64, tag = "10")]
    pub registered_at_unix: i64,
}

#[derive(Clone, PartialEq, ::prost::Message, Serialize, Deserialize)]
pub struct AgentRegistrationAck {
    #[prost(string, tag = "1")]
    pub host_uuid: String,
    #[prost(bool, tag = "2")]
    pub accepted: bool,
    #[prost(string, tag = "3")]
    pub controller_id: String,
    #[prost(string, tag = "4")]
    pub policy_version: String,
    #[prost(string, repeated, tag = "5")]
    pub enabled_capabilities: Vec<String>,
    #[prost(string, tag = "6")]
    pub message: String,
}

#[derive(Clone, PartialEq, ::prost::Message, Serialize, Deserialize)]
pub struct CbomTelemetryPayload {
    #[prost(string, tag = "1")]
    pub telemetry_id: String,
    #[prost(string, tag = "2")]
    pub host_uuid: String,
    #[prost(int64, tag = "3")]
    pub scan_started_unix: i64,
    #[prost(int64, tag = "4")]
    pub scan_finished_unix: i64,
    #[prost(message, repeated, tag = "5")]
    pub components: Vec<CbomComponent>,
    #[prost(message, repeated, tag = "6")]
    pub findings: Vec<CryptoFinding>,
    #[prost(message, repeated, tag = "7")]
    pub network_observations: Vec<NetworkObservation>,
    #[prost(message, repeated, tag = "8")]
    pub evidence: Vec<Evidence>,
    #[prost(string, tag = "9")]
    pub cyclone_dx_json: String,
}

#[derive(Clone, PartialEq, ::prost::Message, Serialize, Deserialize)]
pub struct CbomComponent {
    #[prost(string, tag = "1")]
    pub bom_ref: String,
    #[prost(string, tag = "2")]
    pub name: String,
    #[prost(string, tag = "3")]
    pub version: String,
    #[prost(string, tag = "4")]
    pub component_type: String,
    #[prost(string, tag = "5")]
    pub purl: String,
    #[prost(string, tag = "6")]
    pub file_path: String,
    #[prost(string, tag = "7")]
    pub language: String,
    #[prost(message, repeated, tag = "8")]
    pub algorithms: Vec<CryptoAlgorithm>,
    #[prost(string, repeated, tag = "9")]
    pub dependencies: Vec<String>,
    #[prost(bool, tag = "10")]
    pub reachable: bool,
}

#[derive(Clone, PartialEq, ::prost::Message, Serialize, Deserialize)]
pub struct CryptoAlgorithm {
    #[prost(string, tag = "1")]
    pub name: String,
    #[prost(string, tag = "2")]
    pub family: String,
    #[prost(enumeration = "CryptoRole", tag = "3")]
    pub role: i32,
    #[prost(string, tag = "4")]
    pub status: String,
    #[prost(uint32, tag = "5")]
    pub key_bits: u32,
    #[prost(string, tag = "6")]
    pub curve: String,
    #[prost(string, tag = "7")]
    pub implementation_library: String,
    #[prost(string, tag = "8")]
    pub source_file: String,
    #[prost(uint32, tag = "9")]
    pub source_line: u32,
    #[prost(uint32, tag = "10")]
    pub source_column: u32,
    #[prost(string, tag = "11")]
    pub symbol: String,
    #[prost(double, tag = "12")]
    pub confidence: f64,
    #[prost(bool, tag = "13")]
    pub quantum_vulnerable: bool,
    #[prost(string, tag = "14")]
    pub context_snippet: String,
}

#[derive(Clone, PartialEq, ::prost::Message, Serialize, Deserialize)]
pub struct CryptoFinding {
    #[prost(string, tag = "1")]
    pub finding_id: String,
    #[prost(enumeration = "RiskSeverity", tag = "2")]
    pub severity: i32,
    #[prost(string, tag = "3")]
    pub title: String,
    #[prost(string, tag = "4")]
    pub description: String,
    #[prost(string, tag = "5")]
    pub asset_ref: String,
    #[prost(string, tag = "6")]
    pub algorithm: String,
    #[prost(string, tag = "7")]
    pub policy_rule_id: String,
    #[prost(string, repeated, tag = "8")]
    pub evidence_ids: Vec<String>,
    #[prost(string, tag = "9")]
    pub migration_profile: String,
}

#[derive(Clone, PartialEq, ::prost::Message, Serialize, Deserialize)]
pub struct NetworkObservation {
    #[prost(string, tag = "1")]
    pub endpoint: String,
    #[prost(string, tag = "2")]
    pub protocol: String,
    #[prost(string, tag = "3")]
    pub tls_version: String,
    #[prost(string, tag = "4")]
    pub cipher_suite: String,
    #[prost(string, tag = "5")]
    pub named_group: String,
    #[prost(string, tag = "6")]
    pub signature_algorithm: String,
    #[prost(string, tag = "7")]
    pub certificate_subject: String,
    #[prost(string, tag = "8")]
    pub certificate_issuer: String,
    #[prost(int64, tag = "9")]
    pub certificate_not_after_unix: i64,
    #[prost(bool, tag = "10")]
    pub pqc_hybrid: bool,
    #[prost(bool, tag = "11")]
    pub cleartext: bool,
}

#[derive(Clone, PartialEq, ::prost::Message, Serialize, Deserialize)]
pub struct Evidence {
    #[prost(string, tag = "1")]
    pub evidence_id: String,
    #[prost(string, tag = "2")]
    pub source_type: String,
    #[prost(string, tag = "3")]
    pub source_tool: String,
    #[prost(string, tag = "4")]
    pub target: String,
    #[prost(int64, tag = "5")]
    pub collection_time_unix: i64,
    #[prost(string, tag = "6")]
    pub raw_artifact_sha256: String,
    #[prost(double, tag = "7")]
    pub confidence: f64,
    #[prost(string, tag = "8")]
    pub sensitivity_class: String,
}

#[derive(Clone, PartialEq, ::prost::Message, Serialize, Deserialize)]
pub struct MigrationCommand {
    #[prost(string, tag = "1")]
    pub command_id: String,
    #[prost(string, tag = "2")]
    pub host_uuid: String,
    #[prost(string, tag = "3")]
    pub target_service: String,
    #[prost(string, tag = "4")]
    pub migration_profile: String,
    #[prost(string, tag = "5")]
    pub target_kem: String,
    #[prost(string, tag = "6")]
    pub target_signature: String,
    #[prost(string, tag = "7")]
    pub config_path: String,
    #[prost(string, repeated, tag = "8")]
    pub validation_checklist: Vec<String>,
    #[prost(uint32, tag = "9")]
    pub rollback_window_seconds: u32,
    #[prost(string, tag = "10")]
    pub patch_unified_diff: String,
    #[prost(bytes, tag = "11")]
    pub signed_directive: Vec<u8>,
    #[prost(int64, tag = "12")]
    pub issued_at_unix: i64,
    #[prost(bool, tag = "13")]
    pub dry_run: bool,
}

#[derive(Clone, PartialEq, ::prost::Message, Serialize, Deserialize)]
pub struct MigrationStatusReport {
    #[prost(string, tag = "1")]
    pub command_id: String,
    #[prost(string, tag = "2")]
    pub host_uuid: String,
    #[prost(enumeration = "MigrationState", tag = "3")]
    pub state: i32,
    #[prost(bool, tag = "4")]
    pub success: bool,
    #[prost(string, tag = "5")]
    pub error_vector: String,
    #[prost(string, tag = "6")]
    pub output: String,
    #[prost(string, repeated, tag = "7")]
    pub validation_signatures: Vec<String>,
    #[prost(message, optional, tag = "8")]
    pub observed_tls: Option<NetworkObservation>,
    #[prost(int64, tag = "9")]
    pub reported_at_unix: i64,
}

#[derive(Clone, PartialEq, ::prost::Message, Serialize, Deserialize)]
pub struct MigrationStatusAck {
    #[prost(string, tag = "1")]
    pub command_id: String,
    #[prost(bool, tag = "2")]
    pub accepted: bool,
    #[prost(string, tag = "3")]
    pub message: String,
}

pub mod janus_telemetry_client {
    use super::*;
    use tonic::codegen::{http, Body, Bytes, StdError};

    #[derive(Debug, Clone)]
    pub struct JanusTelemetryClient<T> {
        inner: tonic::client::Grpc<T>,
    }

/* toreview and todel
    impl JanusTelemetryClient<tonic::transport::Channel> {
        pub async fn connect<D>(dst: D) -> Result<Self, tonic::transport::Error>
        where
            D: TryInto<tonic::transport::Endpoint>,
            D::Error: Into<StdError>,
        {
            let conn = tonic::transport::Endpoint::new(dst)?.connect().await?;
            Ok(Self::new(conn))
        }
    }
*/

    impl<T> JanusTelemetryClient<T>
    where
        T: tonic::client::GrpcService<tonic::body::BoxBody>,
        T::Error: Into<StdError>,
        T::ResponseBody: Body<Data = Bytes> + Send + 'static,
        <T::ResponseBody as Body>::Error: Into<StdError> + Send,
    {
        pub fn new(inner: T) -> Self {
            Self {
                inner: tonic::client::Grpc::new(inner),
            }
        }

        pub async fn register_agent(
            &mut self,
            request: impl tonic::IntoRequest<AgentRegistration>,
        ) -> Result<tonic::Response<AgentRegistrationAck>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::unknown(format!("service was not ready: {}", e.into()))
            })?;
            let path = http::uri::PathAndQuery::from_static("/janus.v1.JanusTelemetry/RegisterAgent");
            self.inner
                .unary(request.into_request(), path, tonic::codec::ProstCodec::default())
                .await
        }

        pub async fn stream_telemetry(
            &mut self,
            request: impl tonic::IntoStreamingRequest<Message = CbomTelemetryPayload>,
        ) -> Result<tonic::Response<tonic::codec::Streaming<MigrationCommand>>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::unknown(format!("service was not ready: {}", e.into()))
            })?;
            let path = http::uri::PathAndQuery::from_static("/janus.v1.JanusTelemetry/StreamTelemetry");
            self.inner
                .streaming(request.into_streaming_request(), path, tonic::codec::ProstCodec::default())
                .await
        }

        pub async fn report_migration_status(
            &mut self,
            request: impl tonic::IntoStreamingRequest<Message = MigrationStatusReport>,
        ) -> Result<tonic::Response<MigrationStatusAck>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::unknown(format!("service was not ready: {}", e.into()))
            })?;
            let path = http::uri::PathAndQuery::from_static("/janus.v1.JanusTelemetry/ReportMigrationStatus");
            self.inner
                .client_streaming(request.into_streaming_request(), path, tonic::codec::ProstCodec::default())
                .await
        }
    }
}

