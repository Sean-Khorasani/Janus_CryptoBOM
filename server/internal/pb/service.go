package pb

import (
	"context"
	"io"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const JanusTelemetryServiceName = "janus.v1.JanusTelemetry"

type JanusTelemetryClient interface {
	RegisterAgent(ctx context.Context, in *AgentRegistration, opts ...grpc.CallOption) (*AgentRegistrationAck, error)
	StreamTelemetry(ctx context.Context, opts ...grpc.CallOption) (JanusTelemetry_StreamTelemetryClient, error)
	ReportMigrationStatus(ctx context.Context, opts ...grpc.CallOption) (JanusTelemetry_ReportMigrationStatusClient, error)
}

type janusTelemetryClient struct {
	cc grpc.ClientConnInterface
}

func NewJanusTelemetryClient(cc grpc.ClientConnInterface) JanusTelemetryClient {
	return &janusTelemetryClient{cc: cc}
}

func (c *janusTelemetryClient) RegisterAgent(ctx context.Context, in *AgentRegistration, opts ...grpc.CallOption) (*AgentRegistrationAck, error) {
	out := new(AgentRegistrationAck)
	err := c.cc.Invoke(ctx, "/janus.v1.JanusTelemetry/RegisterAgent", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *janusTelemetryClient) StreamTelemetry(ctx context.Context, opts ...grpc.CallOption) (JanusTelemetry_StreamTelemetryClient, error) {
	stream, err := c.cc.NewStream(ctx, &JanusTelemetry_ServiceDesc.Streams[0], "/janus.v1.JanusTelemetry/StreamTelemetry", opts...)
	if err != nil {
		return nil, err
	}
	return &janusTelemetryStreamTelemetryClient{ClientStream: stream}, nil
}

type JanusTelemetry_StreamTelemetryClient interface {
	Send(*CbomTelemetryPayload) error
	Recv() (*MigrationCommand, error)
	grpc.ClientStream
}

type janusTelemetryStreamTelemetryClient struct {
	grpc.ClientStream
}

func (x *janusTelemetryStreamTelemetryClient) Send(m *CbomTelemetryPayload) error {
	return x.ClientStream.SendMsg(m)
}

func (x *janusTelemetryStreamTelemetryClient) Recv() (*MigrationCommand, error) {
	m := new(MigrationCommand)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *janusTelemetryClient) ReportMigrationStatus(ctx context.Context, opts ...grpc.CallOption) (JanusTelemetry_ReportMigrationStatusClient, error) {
	stream, err := c.cc.NewStream(ctx, &JanusTelemetry_ServiceDesc.Streams[1], "/janus.v1.JanusTelemetry/ReportMigrationStatus", opts...)
	if err != nil {
		return nil, err
	}
	return &janusTelemetryReportMigrationStatusClient{ClientStream: stream}, nil
}

type JanusTelemetry_ReportMigrationStatusClient interface {
	Send(*MigrationStatusReport) error
	CloseAndRecv() (*MigrationStatusAck, error)
	grpc.ClientStream
}

type janusTelemetryReportMigrationStatusClient struct {
	grpc.ClientStream
}

func (x *janusTelemetryReportMigrationStatusClient) Send(m *MigrationStatusReport) error {
	return x.ClientStream.SendMsg(m)
}

func (x *janusTelemetryReportMigrationStatusClient) CloseAndRecv() (*MigrationStatusAck, error) {
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	m := new(MigrationStatusAck)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

type JanusTelemetryServer interface {
	RegisterAgent(context.Context, *AgentRegistration) (*AgentRegistrationAck, error)
	StreamTelemetry(JanusTelemetry_StreamTelemetryServer) error
	ReportMigrationStatus(JanusTelemetry_ReportMigrationStatusServer) error
}

type UnimplementedJanusTelemetryServer struct{}

func (UnimplementedJanusTelemetryServer) RegisterAgent(context.Context, *AgentRegistration) (*AgentRegistrationAck, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RegisterAgent not implemented")
}

func (UnimplementedJanusTelemetryServer) StreamTelemetry(JanusTelemetry_StreamTelemetryServer) error {
	return status.Errorf(codes.Unimplemented, "method StreamTelemetry not implemented")
}

func (UnimplementedJanusTelemetryServer) ReportMigrationStatus(JanusTelemetry_ReportMigrationStatusServer) error {
	return status.Errorf(codes.Unimplemented, "method ReportMigrationStatus not implemented")
}

func RegisterJanusTelemetryServer(s grpc.ServiceRegistrar, srv JanusTelemetryServer) {
	s.RegisterService(&JanusTelemetry_ServiceDesc, srv)
}

func _JanusTelemetry_RegisterAgent_Handler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	in := new(AgentRegistration)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(JanusTelemetryServer).RegisterAgent(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/janus.v1.JanusTelemetry/RegisterAgent",
	}
	handler := func(ctx context.Context, req any) (any, error) {
		return srv.(JanusTelemetryServer).RegisterAgent(ctx, req.(*AgentRegistration))
	}
	return interceptor(ctx, in, info, handler)
}

func _JanusTelemetry_StreamTelemetry_Handler(srv any, stream grpc.ServerStream) error {
	return srv.(JanusTelemetryServer).StreamTelemetry(&janusTelemetryStreamTelemetryServer{ServerStream: stream})
}

type JanusTelemetry_StreamTelemetryServer interface {
	Send(*MigrationCommand) error
	Recv() (*CbomTelemetryPayload, error)
	grpc.ServerStream
}

type janusTelemetryStreamTelemetryServer struct {
	grpc.ServerStream
}

func (x *janusTelemetryStreamTelemetryServer) Send(m *MigrationCommand) error {
	return x.ServerStream.SendMsg(m)
}

func (x *janusTelemetryStreamTelemetryServer) Recv() (*CbomTelemetryPayload, error) {
	m := new(CbomTelemetryPayload)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func _JanusTelemetry_ReportMigrationStatus_Handler(srv any, stream grpc.ServerStream) error {
	return srv.(JanusTelemetryServer).ReportMigrationStatus(&janusTelemetryReportMigrationStatusServer{ServerStream: stream})
}

type JanusTelemetry_ReportMigrationStatusServer interface {
	SendAndClose(*MigrationStatusAck) error
	Recv() (*MigrationStatusReport, error)
	grpc.ServerStream
}

type janusTelemetryReportMigrationStatusServer struct {
	grpc.ServerStream
}

func (x *janusTelemetryReportMigrationStatusServer) SendAndClose(m *MigrationStatusAck) error {
	return x.ServerStream.SendMsg(m)
}

func (x *janusTelemetryReportMigrationStatusServer) Recv() (*MigrationStatusReport, error) {
	m := new(MigrationStatusReport)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

var JanusTelemetry_ServiceDesc = grpc.ServiceDesc{
	ServiceName: JanusTelemetryServiceName,
	HandlerType: (*JanusTelemetryServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "RegisterAgent",
			Handler:    _JanusTelemetry_RegisterAgent_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "StreamTelemetry",
			Handler:       _JanusTelemetry_StreamTelemetry_Handler,
			ServerStreams: true,
			ClientStreams: true,
		},
		{
			StreamName:    "ReportMigrationStatus",
			Handler:       _JanusTelemetry_ReportMigrationStatus_Handler,
			ClientStreams: true,
		},
	},
	Metadata: "proto/janus.proto",
}

func IsEOF(err error) bool {
	return err == io.EOF
}
