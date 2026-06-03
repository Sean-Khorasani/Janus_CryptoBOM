package pb

import proto "github.com/golang/protobuf/proto"

const (
	ExecutionModeUnspecified int32 = 0
	ExecutionModePassive     int32 = 1
	ExecutionModeActive      int32 = 2
)

const (
	CryptoRoleUnspecified   int32 = 0
	CryptoRoleKEM           int32 = 1
	CryptoRoleKeyExchange   int32 = 2
	CryptoRoleSignature     int32 = 3
	CryptoRoleCertPublicKey int32 = 4
	CryptoRoleCertSignature int32 = 5
	CryptoRoleSymmetric     int32 = 6
	CryptoRoleHash          int32 = 7
	CryptoRoleMAC           int32 = 8
	CryptoRoleKDF           int32 = 9
	CryptoRoleRandom        int32 = 10
	CryptoRoleKeyStorage    int32 = 11
)

const (
	RiskSeverityUnspecified int32 = 0
	RiskSeverityInfo        int32 = 1
	RiskSeverityLow         int32 = 2
	RiskSeverityMedium      int32 = 3
	RiskSeverityHigh        int32 = 4
	RiskSeverityCritical    int32 = 5
)

const (
	MigrationStateUnspecified int32 = 0
	MigrationStatePending     int32 = 1
	MigrationStateLocked      int32 = 2
	MigrationStateApplying    int32 = 3
	MigrationStateValidating  int32 = 4
	MigrationStateRollingBack int32 = 5
	MigrationStateSucceeded   int32 = 6
	MigrationStateFailed      int32 = 7
)

type AgentRegistration struct {
	HostUuid           string   `protobuf:"bytes,1,opt,name=host_uuid,json=hostUuid,proto3" json:"host_uuid,omitempty"`
	Hostname           string   `protobuf:"bytes,2,opt,name=hostname,proto3" json:"hostname,omitempty"`
	HardwareSignatures []string `protobuf:"bytes,3,rep,name=hardware_signatures,json=hardwareSignatures,proto3" json:"hardware_signatures,omitempty"`
	OsName             string   `protobuf:"bytes,4,opt,name=os_name,json=osName,proto3" json:"os_name,omitempty"`
	OsVersion          string   `protobuf:"bytes,5,opt,name=os_version,json=osVersion,proto3" json:"os_version,omitempty"`
	Arch               string   `protobuf:"bytes,6,opt,name=arch,proto3" json:"arch,omitempty"`
	ExecutionMode      int32    `protobuf:"varint,7,opt,name=execution_mode,json=executionMode,proto3" json:"execution_mode,omitempty"`
	AgentVersion       string   `protobuf:"bytes,8,opt,name=agent_version,json=agentVersion,proto3" json:"agent_version,omitempty"`
	Capabilities       []string `protobuf:"bytes,9,rep,name=capabilities,proto3" json:"capabilities,omitempty"`
	RegisteredAtUnix   int64    `protobuf:"varint,10,opt,name=registered_at_unix,json=registeredAtUnix,proto3" json:"registered_at_unix,omitempty"`
}

type AgentRegistrationAck struct {
	HostUuid            string   `protobuf:"bytes,1,opt,name=host_uuid,json=hostUuid,proto3" json:"host_uuid,omitempty"`
	Accepted            bool     `protobuf:"varint,2,opt,name=accepted,proto3" json:"accepted,omitempty"`
	ControllerId        string   `protobuf:"bytes,3,opt,name=controller_id,json=controllerId,proto3" json:"controller_id,omitempty"`
	PolicyVersion       string   `protobuf:"bytes,4,opt,name=policy_version,json=policyVersion,proto3" json:"policy_version,omitempty"`
	EnabledCapabilities []string `protobuf:"bytes,5,rep,name=enabled_capabilities,json=enabledCapabilities,proto3" json:"enabled_capabilities,omitempty"`
	Message             string   `protobuf:"bytes,6,opt,name=message,proto3" json:"message,omitempty"`
}

type CbomTelemetryPayload struct {
	TelemetryId          string                `protobuf:"bytes,1,opt,name=telemetry_id,json=telemetryId,proto3" json:"telemetry_id,omitempty"`
	HostUuid             string                `protobuf:"bytes,2,opt,name=host_uuid,json=hostUuid,proto3" json:"host_uuid,omitempty"`
	ScanStartedUnix      int64                 `protobuf:"varint,3,opt,name=scan_started_unix,json=scanStartedUnix,proto3" json:"scan_started_unix,omitempty"`
	ScanFinishedUnix     int64                 `protobuf:"varint,4,opt,name=scan_finished_unix,json=scanFinishedUnix,proto3" json:"scan_finished_unix,omitempty"`
	Components           []*CbomComponent      `protobuf:"bytes,5,rep,name=components,proto3" json:"components,omitempty"`
	Findings             []*CryptoFinding      `protobuf:"bytes,6,rep,name=findings,proto3" json:"findings,omitempty"`
	NetworkObservations  []*NetworkObservation `protobuf:"bytes,7,rep,name=network_observations,json=networkObservations,proto3" json:"network_observations,omitempty"`
	Evidence             []*Evidence           `protobuf:"bytes,8,rep,name=evidence,proto3" json:"evidence,omitempty"`
	CycloneDxJson        string                `protobuf:"bytes,9,opt,name=cyclone_dx_json,json=cycloneDxJson,proto3" json:"cyclone_dx_json,omitempty"`
}

type CbomComponent struct {
	BomRef        string             `protobuf:"bytes,1,opt,name=bom_ref,json=bomRef,proto3" json:"bom_ref,omitempty"`
	Name          string             `protobuf:"bytes,2,opt,name=name,proto3" json:"name,omitempty"`
	Version       string             `protobuf:"bytes,3,opt,name=version,proto3" json:"version,omitempty"`
	ComponentType string             `protobuf:"bytes,4,opt,name=component_type,json=componentType,proto3" json:"component_type,omitempty"`
	Purl          string             `protobuf:"bytes,5,opt,name=purl,proto3" json:"purl,omitempty"`
	FilePath      string             `protobuf:"bytes,6,opt,name=file_path,json=filePath,proto3" json:"file_path,omitempty"`
	Language      string             `protobuf:"bytes,7,opt,name=language,proto3" json:"language,omitempty"`
	Algorithms    []*CryptoAlgorithm `protobuf:"bytes,8,rep,name=algorithms,proto3" json:"algorithms,omitempty"`
	Dependencies  []string           `protobuf:"bytes,9,rep,name=dependencies,proto3" json:"dependencies,omitempty"`
	Reachable     bool               `protobuf:"varint,10,opt,name=reachable,proto3" json:"reachable,omitempty"`
}

type CryptoAlgorithm struct {
	Name                  string  `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Family                string  `protobuf:"bytes,2,opt,name=family,proto3" json:"family,omitempty"`
	Role                  int32   `protobuf:"varint,3,opt,name=role,proto3" json:"role,omitempty"`
	Status                string  `protobuf:"bytes,4,opt,name=status,proto3" json:"status,omitempty"`
	KeyBits               uint32  `protobuf:"varint,5,opt,name=key_bits,json=keyBits,proto3" json:"key_bits,omitempty"`
	Curve                 string  `protobuf:"bytes,6,opt,name=curve,proto3" json:"curve,omitempty"`
	ImplementationLibrary string  `protobuf:"bytes,7,opt,name=implementation_library,json=implementationLibrary,proto3" json:"implementation_library,omitempty"`
	SourceFile            string  `protobuf:"bytes,8,opt,name=source_file,json=sourceFile,proto3" json:"source_file,omitempty"`
	SourceLine            uint32  `protobuf:"varint,9,opt,name=source_line,json=sourceLine,proto3" json:"source_line,omitempty"`
	SourceColumn          uint32  `protobuf:"varint,10,opt,name=source_column,json=sourceColumn,proto3" json:"source_column,omitempty"`
	Symbol                string  `protobuf:"bytes,11,opt,name=symbol,proto3" json:"symbol,omitempty"`
	Confidence            float64 `protobuf:"fixed64,12,opt,name=confidence,proto3" json:"confidence,omitempty"`
	QuantumVulnerable     bool    `protobuf:"varint,13,opt,name=quantum_vulnerable,json=quantumVulnerable,proto3" json:"quantum_vulnerable,omitempty"`
}

type CryptoFinding struct {
	FindingId        string   `protobuf:"bytes,1,opt,name=finding_id,json=findingId,proto3" json:"finding_id,omitempty"`
	Severity         int32    `protobuf:"varint,2,opt,name=severity,proto3" json:"severity,omitempty"`
	Title            string   `protobuf:"bytes,3,opt,name=title,proto3" json:"title,omitempty"`
	Description      string   `protobuf:"bytes,4,opt,name=description,proto3" json:"description,omitempty"`
	AssetRef         string   `protobuf:"bytes,5,opt,name=asset_ref,json=assetRef,proto3" json:"asset_ref,omitempty"`
	Algorithm        string   `protobuf:"bytes,6,opt,name=algorithm,proto3" json:"algorithm,omitempty"`
	PolicyRuleId     string   `protobuf:"bytes,7,opt,name=policy_rule_id,json=policyRuleId,proto3" json:"policy_rule_id,omitempty"`
	EvidenceIds      []string `protobuf:"bytes,8,rep,name=evidence_ids,json=evidenceIds,proto3" json:"evidence_ids,omitempty"`
	MigrationProfile string   `protobuf:"bytes,9,opt,name=migration_profile,json=migrationProfile,proto3" json:"migration_profile,omitempty"`
}

type NetworkObservation struct {
	Endpoint                string `protobuf:"bytes,1,opt,name=endpoint,proto3" json:"endpoint,omitempty"`
	Protocol                string `protobuf:"bytes,2,opt,name=protocol,proto3" json:"protocol,omitempty"`
	TlsVersion              string `protobuf:"bytes,3,opt,name=tls_version,json=tlsVersion,proto3" json:"tls_version,omitempty"`
	CipherSuite             string `protobuf:"bytes,4,opt,name=cipher_suite,json=cipherSuite,proto3" json:"cipher_suite,omitempty"`
	NamedGroup              string `protobuf:"bytes,5,opt,name=named_group,json=namedGroup,proto3" json:"named_group,omitempty"`
	SignatureAlgorithm      string `protobuf:"bytes,6,opt,name=signature_algorithm,json=signatureAlgorithm,proto3" json:"signature_algorithm,omitempty"`
	CertificateSubject      string `protobuf:"bytes,7,opt,name=certificate_subject,json=certificateSubject,proto3" json:"certificate_subject,omitempty"`
	CertificateIssuer       string `protobuf:"bytes,8,opt,name=certificate_issuer,json=certificateIssuer,proto3" json:"certificate_issuer,omitempty"`
	CertificateNotAfterUnix int64  `protobuf:"varint,9,opt,name=certificate_not_after_unix,json=certificateNotAfterUnix,proto3" json:"certificate_not_after_unix,omitempty"`
	PqcHybrid               bool   `protobuf:"varint,10,opt,name=pqc_hybrid,json=pqcHybrid,proto3" json:"pqc_hybrid,omitempty"`
	Cleartext               bool   `protobuf:"varint,11,opt,name=cleartext,proto3" json:"cleartext,omitempty"`
}

type Evidence struct {
	EvidenceId          string  `protobuf:"bytes,1,opt,name=evidence_id,json=evidenceId,proto3" json:"evidence_id,omitempty"`
	SourceType          string  `protobuf:"bytes,2,opt,name=source_type,json=sourceType,proto3" json:"source_type,omitempty"`
	SourceTool          string  `protobuf:"bytes,3,opt,name=source_tool,json=sourceTool,proto3" json:"source_tool,omitempty"`
	Target              string  `protobuf:"bytes,4,opt,name=target,proto3" json:"target,omitempty"`
	CollectionTimeUnix  int64   `protobuf:"varint,5,opt,name=collection_time_unix,json=collectionTimeUnix,proto3" json:"collection_time_unix,omitempty"`
	RawArtifactSha256   string  `protobuf:"bytes,6,opt,name=raw_artifact_sha256,json=rawArtifactSha256,proto3" json:"raw_artifact_sha256,omitempty"`
	Confidence          float64 `protobuf:"fixed64,7,opt,name=confidence,proto3" json:"confidence,omitempty"`
	SensitivityClass    string  `protobuf:"bytes,8,opt,name=sensitivity_class,json=sensitivityClass,proto3" json:"sensitivity_class,omitempty"`
}

type MigrationCommand struct {
	CommandId             string   `protobuf:"bytes,1,opt,name=command_id,json=commandId,proto3" json:"command_id,omitempty"`
	HostUuid              string   `protobuf:"bytes,2,opt,name=host_uuid,json=hostUuid,proto3" json:"host_uuid,omitempty"`
	TargetService         string   `protobuf:"bytes,3,opt,name=target_service,json=targetService,proto3" json:"target_service,omitempty"`
	MigrationProfile      string   `protobuf:"bytes,4,opt,name=migration_profile,json=migrationProfile,proto3" json:"migration_profile,omitempty"`
	TargetKem             string   `protobuf:"bytes,5,opt,name=target_kem,json=targetKem,proto3" json:"target_kem,omitempty"`
	TargetSignature       string   `protobuf:"bytes,6,opt,name=target_signature,json=targetSignature,proto3" json:"target_signature,omitempty"`
	ConfigPath            string   `protobuf:"bytes,7,opt,name=config_path,json=configPath,proto3" json:"config_path,omitempty"`
	ValidationChecklist   []string `protobuf:"bytes,8,rep,name=validation_checklist,json=validationChecklist,proto3" json:"validation_checklist,omitempty"`
	RollbackWindowSeconds uint32   `protobuf:"varint,9,opt,name=rollback_window_seconds,json=rollbackWindowSeconds,proto3" json:"rollback_window_seconds,omitempty"`
	PatchUnifiedDiff      string   `protobuf:"bytes,10,opt,name=patch_unified_diff,json=patchUnifiedDiff,proto3" json:"patch_unified_diff,omitempty"`
	SignedDirective       []byte   `protobuf:"bytes,11,opt,name=signed_directive,json=signedDirective,proto3" json:"signed_directive,omitempty"`
	IssuedAtUnix          int64    `protobuf:"varint,12,opt,name=issued_at_unix,json=issuedAtUnix,proto3" json:"issued_at_unix,omitempty"`
	DryRun                bool     `protobuf:"varint,13,opt,name=dry_run,json=dryRun,proto3" json:"dry_run,omitempty"`
}

type MigrationStatusReport struct {
	CommandId            string              `protobuf:"bytes,1,opt,name=command_id,json=commandId,proto3" json:"command_id,omitempty"`
	HostUuid             string              `protobuf:"bytes,2,opt,name=host_uuid,json=hostUuid,proto3" json:"host_uuid,omitempty"`
	State                int32               `protobuf:"varint,3,opt,name=state,proto3" json:"state,omitempty"`
	Success              bool                `protobuf:"varint,4,opt,name=success,proto3" json:"success,omitempty"`
	ErrorVector          string              `protobuf:"bytes,5,opt,name=error_vector,json=errorVector,proto3" json:"error_vector,omitempty"`
	Output               string              `protobuf:"bytes,6,opt,name=output,proto3" json:"output,omitempty"`
	ValidationSignatures []string            `protobuf:"bytes,7,rep,name=validation_signatures,json=validationSignatures,proto3" json:"validation_signatures,omitempty"`
	ObservedTls          *NetworkObservation `protobuf:"bytes,8,opt,name=observed_tls,json=observedTls,proto3" json:"observed_tls,omitempty"`
	ReportedAtUnix       int64               `protobuf:"varint,9,opt,name=reported_at_unix,json=reportedAtUnix,proto3" json:"reported_at_unix,omitempty"`
}

type MigrationStatusAck struct {
	CommandId string `protobuf:"bytes,1,opt,name=command_id,json=commandId,proto3" json:"command_id,omitempty"`
	Accepted  bool   `protobuf:"varint,2,opt,name=accepted,proto3" json:"accepted,omitempty"`
	Message   string `protobuf:"bytes,3,opt,name=message,proto3" json:"message,omitempty"`
}

func (m *AgentRegistration) Reset()         { *m = AgentRegistration{} }
func (m *AgentRegistration) String() string { return proto.CompactTextString(m) }
func (*AgentRegistration) ProtoMessage()    {}

func (m *AgentRegistrationAck) Reset()         { *m = AgentRegistrationAck{} }
func (m *AgentRegistrationAck) String() string { return proto.CompactTextString(m) }
func (*AgentRegistrationAck) ProtoMessage()    {}

func (m *CbomTelemetryPayload) Reset()         { *m = CbomTelemetryPayload{} }
func (m *CbomTelemetryPayload) String() string { return proto.CompactTextString(m) }
func (*CbomTelemetryPayload) ProtoMessage()    {}

func (m *CbomComponent) Reset()         { *m = CbomComponent{} }
func (m *CbomComponent) String() string { return proto.CompactTextString(m) }
func (*CbomComponent) ProtoMessage()    {}

func (m *CryptoAlgorithm) Reset()         { *m = CryptoAlgorithm{} }
func (m *CryptoAlgorithm) String() string { return proto.CompactTextString(m) }
func (*CryptoAlgorithm) ProtoMessage()    {}

func (m *CryptoFinding) Reset()         { *m = CryptoFinding{} }
func (m *CryptoFinding) String() string { return proto.CompactTextString(m) }
func (*CryptoFinding) ProtoMessage()    {}

func (m *NetworkObservation) Reset()         { *m = NetworkObservation{} }
func (m *NetworkObservation) String() string { return proto.CompactTextString(m) }
func (*NetworkObservation) ProtoMessage()    {}

func (m *Evidence) Reset()         { *m = Evidence{} }
func (m *Evidence) String() string { return proto.CompactTextString(m) }
func (*Evidence) ProtoMessage()    {}

func (m *MigrationCommand) Reset()         { *m = MigrationCommand{} }
func (m *MigrationCommand) String() string { return proto.CompactTextString(m) }
func (*MigrationCommand) ProtoMessage()    {}

func (m *MigrationStatusReport) Reset()         { *m = MigrationStatusReport{} }
func (m *MigrationStatusReport) String() string { return proto.CompactTextString(m) }
func (*MigrationStatusReport) ProtoMessage()    {}

func (m *MigrationStatusAck) Reset()         { *m = MigrationStatusAck{} }
func (m *MigrationStatusAck) String() string { return proto.CompactTextString(m) }
func (*MigrationStatusAck) ProtoMessage()    {}

