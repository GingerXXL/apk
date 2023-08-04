/*
 *  Copyright (c) 2020, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package config

import (
	"sync"
	"time"
)

// Experimenting asynchronous communication between go routines using channels
// This uses singleton pattern where creating a single channel for communication
//
// To get a instance of the channel for a data publisher go routine
//
//	`publisher := NewSender()`
//
// Create a receiver channel in worker go routine
// receiver := NewReceiver()
//
// From publisher go routine, feed string value to the channel
// publisher<- "some value"
//
// In worker go routine, read the value sent by the publisher
// message := <-receiver
var once sync.Once

// C represents the channel to identify modifications added to the configuration file
// TODO: (VirajSalaka) remove this as unused.
var (
	C chan string // better to be interface{} type which could send any type of data.
)

// NewSender initializes the channel if it is not created an returns
func NewSender() chan string {
	once.Do(func() {
		C = make(chan string)
	})
	return C
}

// NewReceiver initializes the channel if it is not created an returns
func NewReceiver() chan string {
	once.Do(func() {
		C = make(chan string)
	})
	return C
}

const (
	//UnassignedAsDeprecated is used by the configurations which are deprecated.
	UnassignedAsDeprecated string = "unassigned-as-deprecated"
)

// Config represents the adapter configuration.
// It is created directly from the configuration toml file.
// Note :
//
//	Don't use toml tag for configuration properties as it may affect environment variable based
//	config resolution.
type Config struct {
	Adapter          adapter
	Enforcer         enforcer
	Envoy            envoy            `toml:"router"`
	ManagementServer managementServer `toml:"managementServer"`
	PartitionServer  partitionServer  `toml:"partitionServer"`
	Analytics        analytics        `toml:"analytics"`
	Tracing          tracing
}

// Adapter related Configurations
type adapter struct {
	// Consul represents the configuration required to connect to consul service discovery
	Consul consul
	// Keystore contains the keyFile and Cert File of the adapter
	Keystore keystore
	// Trusted Certificates
	Truststore truststore
	// SoapErrorInXMLEnabled is used to configure gateway error responses(local reply) as soap envelope
	SoapErrorInXMLEnabled bool
	// Operator represents the operator related configurations
	Operator operator
}

// Envoy Listener Component related configurations.
type envoy struct {
	ListenerCodecType                string
	ClusterTimeoutInSeconds          time.Duration
	EnforcerResponseTimeoutInSeconds time.Duration `default:"20"`
	KeyStore                         keystore
	SystemHost                       string `default:"localhost"`
	Upstream                         envoyUpstream
	Downstream                       envoyDownstream
	Connection                       connection
	PayloadPassingToEnforcer         payloadPassingToEnforcer
	UseRemoteAddress                 bool
	Filters                          filters
	RateLimit                        rateLimit
}

type connectionTimeouts struct {
	RequestTimeoutInSeconds        time.Duration
	RequestHeadersTimeoutInSeconds time.Duration // default disabled
	StreamIdleTimeoutInSeconds     time.Duration // Default 5 mins
	IdleTimeoutInSeconds           time.Duration // default 1hr
}

type connection struct {
	Timeouts connectionTimeouts
}

type rateLimit struct {
	Enabled                bool
	Host                   string
	Port                   uint32
	XRateLimitHeaders      xRateLimitHeaders
	FailureModeDeny        bool
	RequestTimeoutInMillis int64
	KeyFilePath            string
	CertFilePath           string
	CaCertFilePath         string
	SSLCertSANHostname     string
}

type xRateLimitHeaders struct {
	Enabled    bool
	RFCVersion string
}

type enforcer struct {
	Security     security
	AuthService  authService
	JwtGenerator jwtGenerator
	Cache        cache
	JwtIssuer    jwtIssuer
	Management   management
	RestServer   restServer
	Filters      []filter
	Metrics      metrics
}

type consul struct {
	// Deprecated: Use Enabled instead
	Enable bool
	// Enabled whether consul service discovery should be enabled
	Enabled bool
	// URL url of the consul client in format: http(s)://host:port
	URL string
	// PollInterval how frequently consul API should be polled to get updates (in seconds)
	PollInterval int
	// ACLToken Access Control Token required to invoke HTTP API
	ACLToken string
	// ApkServiceName service name that Microgateway registered in Consul Service Mesh
	ApkServiceName string
	// ServiceMeshEnabled whether Consul service mesh is enabled
	ServiceMeshEnabled bool
	// CaCertFile path to the CA cert file(PEM encoded) required for tls connection between adapter and a consul client
	CaCertFile string
	// CertFile path to the cert file(PEM encoded) required for tls connection between adapter and a consul client
	CertFile string
	// KeyFile path to the key file(PEM encoded) required for tls connection between adapter and a consul client
	KeyFile string
}

// Router to enforcer request body passing configurations
type payloadPassingToEnforcer struct {
	PassRequestPayload  bool
	MaxRequestBytes     uint32
	AllowPartialMessage bool
	PackAsBytes         bool
}

// Envoy Upstream Related Configurations
type envoyUpstream struct {
	// UpstreamTLS related Configuration
	TLS   upstreamTLS
	DNS   upstreamDNS
	HTTP2 upstreamHTTP2Options
}

// Envoy Downstream Related Configurations
type envoyDownstream struct {
	// DownstreamTLS related Configuration
	TLS downstreamTLS
}

type downstreamTLS struct {
	TrustedCertPath string
	MTLSAPIsEnabled bool
}

type upstreamTLS struct {
	MinimumProtocolVersion string
	MaximumProtocolVersion string
	Ciphers                string
	TrustedCertPath        string
	VerifyHostName         bool
	DisableSslVerification bool
}

type upstreamDNS struct {
	DNSRefreshRate int32
	RespectDNSTtl  bool
}

type upstreamHTTP2Options struct {
	HpackTableSize       uint32
	MaxConcurrentStreams uint32
}

type security struct {
	InternalKey internalKey
	APIkey      apiKey
	MutualSSL   mutualSSL
}
type internalKey struct {
	Enabled             bool
	Issuer              string
	CertificateFilePath string
}
type apiKey struct {
	Enabled             bool
	Issuer              string
	CertificateFilePath string
}

type authService struct {
	Port           int32
	MaxMessageSize int32
	MaxHeaderLimit int32
	KeepAliveTime  int32
	ThreadPool     threadPool
}

type threadPool struct {
	CoreSize      int32
	MaxSize       int32
	KeepAliveTime int32
	QueueSize     int32
}

type keystore struct {
	KeyPath  string
	CertPath string
}

type truststore struct {
	Location string
}

type jwtGenerator struct {
	// Deprecated: Use Enabled instead
	Enable               bool
	Enabled              bool
	Encoding             string
	ClaimDialect         string
	ConvertDialect       bool
	Header               string
	SigningAlgorithm     string
	EnableUserClaims     bool
	GatewayGeneratorImpl string
	ClaimsExtractorImpl  string
	TokenTTL             int32
	Keypair              []KeyPair
}

// KeyPair represents hthe rsa keypair used for signing JWTs
type KeyPair struct {
	PrivateKeyPath        string
	PublicCertificatePath string
	UseForSigning         bool
}

type claimMapping struct {
	RemoteClaim string
	LocalClaim  string
}

type cache struct {
	Enabled     bool
	MaximumSize int32
	ExpiryTime  int32
}

type analytics struct {
	Enabled  bool
	Type     string
	Adapter  analyticsAdapter
	Enforcer analyticsEnforcer
}

type tracing struct {
	Enabled          bool
	Type             string
	ConfigProperties map[string]string
}

type metrics struct {
	Enabled bool
	Type    string
}

type analyticsAdapter struct {
	BufferFlushInterval time.Duration
	BufferSizeBytes     uint32
	GRPCRequestTimeout  time.Duration
}

type analyticsEnforcer struct {
	// TODO: (VirajSalaka) convert it to map[string]{}interface
	ConfigProperties map[string]string
	LogReceiver      authService
}

type jwtIssuer struct {
	Enabled               bool
	Issuer                string
	Encoding              string
	ClaimDialect          string
	SigningAlgorithm      string
	PublicCertificatePath string
	PrivateKeyPath        string
	ValidityPeriod        int32
	JwtUser               []JwtUser
}

// JwtUser represents allowed users to generate JWT tokens
type JwtUser struct {
	Username string
	Password string
}

type repository struct {
	URL         string
	Branch      string
	Username    string
	AccessToken string
	SSHKeyFile  string // SSHKeyFile path to the private key file
}

type requestWorkerPool struct {
	PoolSize              int
	QueueSizePerPool      int
	PauseTimeAfterFailure time.Duration
}

type managementServer struct {
	Enabled bool
	Host    string
	// XDSPort represents the configuration related to XDS connection to Management server from agent
	XDSPort   int
	NodeLabel string
	// GRPCClient represents the configuration related to gRPC connection from Management server to agent
	GRPCClient gRPCClient
}

type partitionServer struct {
	Enabled                bool
	Host                   string
	Port                   int
	ServiceBasePath        string
	PartitionName          string
	DisableSslVerification bool
}

// Configuration for Enforcer admin rest api
type restServer struct {
	// Deprecated: Use Enabled Instead
	Enable  bool
	Enabled bool
}

// Enforcer admin credentials
type management struct {
	Username string
	Password string
}

type filter struct {
	ClassName        string
	Position         int32
	ConfigProperties map[string]string
}

type httpClient struct {
	RequestTimeOut time.Duration
}

type mutualSSL struct {
	CertificateHeader               string
	EnableClientValidation          bool
	ClientCertificateEncode         bool
	EnableOutboundCertificateHeader bool
}

type gRPCClient struct {
	Port                  int
	MaxAttempts           int
	BackOffInMilliSeconds int
}

type filters struct {
	Compression compression
}

type compression struct {
	Enabled           bool
	Library           string
	RequestDirection  requestDirection
	ResponseDirection responseDirection
	LibraryProperties map[string]interface{}
}

type requestDirection struct {
	Enabled              bool
	MinimumContentLength int
	ContentType          []string
}

type responseDirection struct {
	Enabled              bool
	MinimumContentLength int
	ContentType          []string
	EnableForEtagHeader  bool
}

type operator struct {
	Namespaces []string
}
