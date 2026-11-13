package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// MockDynamoDBClient is a mock of the DynamoDBAPI interface.
type MockDynamoDBClient struct {
	GetItemFunc    func(ctx context.Context, params *dynamodb.GetItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error)
	UpdateItemFunc func(ctx context.Context, params *dynamodb.UpdateItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error)

	getItemCalls    int
	updateItemCalls []*dynamodb.UpdateItemInput
}

func (m *MockDynamoDBClient) GetItem(ctx context.Context, params *dynamodb.GetItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
	m.getItemCalls++
	if m.GetItemFunc != nil {
		return m.GetItemFunc(ctx, params, optFns...)
	}
	return &dynamodb.GetItemOutput{}, nil
}

func (m *MockDynamoDBClient) UpdateItem(ctx context.Context, params *dynamodb.UpdateItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error) {
	m.updateItemCalls = append(m.updateItemCalls, params)
	if m.UpdateItemFunc != nil {
		return m.UpdateItemFunc(ctx, params, optFns...)
	}
	return &dynamodb.UpdateItemOutput{}, nil
}

const (
	tableName         = "test-table"
	testMAC           = "38:18:2B:84:56:F4"
	gatewayTemplate   = "esp32-s3-fleet-template"
	vaktusTemplate    = "esp32-ztp-vaktus-fleet-template"
	templateARNPrefix = "arn:aws:iot:eu-central-1:123456789012:provisioningtemplate/"
)

func testTemplates() map[string]TemplateProduct {
	return map[string]TemplateProduct{
		gatewayTemplate: {Product: "gateway"},
		vaktusTemplate:  {Product: "vaktus"},
	}
}

// deviceKey is a P-256 key standing in for the one in the device's ATECC608,
// with a certificate AWS IoT would have issued for it.
type deviceKey struct {
	key     *ecdsa.PrivateKey
	certPEM string
}

func newDeviceKey(t *testing.T) deviceKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "AWS IoT Certificate"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return deviceKey{key: key, certPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
}

// rawXY is the key as an ATECC608 GenKey returns it: X||Y, 64 bytes, as hex.
func (d deviceKey) rawXY() string {
	pt, err := d.key.PublicKey.ECDH()
	if err != nil {
		panic(err)
	}
	return strings.ToUpper(hex.EncodeToString(pt.Bytes()[1:]))
}

func (d deviceKey) pem() string {
	der, err := x509.MarshalPKIXPublicKey(&d.key.PublicKey)
	if err != nil {
		panic(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func record(attrs map[string]types.AttributeValue) func(ctx context.Context, params *dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
	return func(ctx context.Context, params *dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
		return &dynamodb.GetItemOutput{Item: attrs}, nil
	}
}

// fixedNow is the handler's clock in tests.
var fixedNow = time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)

func s(v string) types.AttributeValue { return &types.AttributeValueMemberS{Value: v} }
func n(v int64) types.AttributeValue {
	return &types.AttributeValueMemberN{Value: strconv.FormatInt(v, 10)}
}

// lookupMust returns the record only when it is looked up by exactly mac.
func lookupMust(mac string, attrs map[string]types.AttributeValue) func(ctx context.Context, params *dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
	return func(ctx context.Context, params *dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
		if params.Key["mac_address"].(*types.AttributeValueMemberS).Value != mac {
			return &dynamodb.GetItemOutput{}, nil
		}
		return &dynamodb.GetItemOutput{Item: attrs}, nil
	}
}
func b(v bool) types.AttributeValue { return &types.AttributeValueMemberBOOL{Value: v} }
func colons(hexKey string) string {
	var parts []string
	for i := 0; i < len(hexKey); i += 2 {
		parts = append(parts, hexKey[i:i+2])
	}
	return strings.Join(parts, ":")
}

func TestHandler(t *testing.T) {
	device := newDeviceKey(t)
	other := newDeviceKey(t)

	keyRecord := func(product, publicKey string) map[string]types.AttributeValue {
		return map[string]types.AttributeValue{
			"mac_address": s(testMAC), "product": s(product), "allowed": b(true), "public_key": s(publicKey),
		}
	}
	gatewayRecord := keyRecord("gateway", device.rawXY())
	vaktusRecord := func(publicKey string) map[string]types.AttributeValue { return keyRecord("vaktus", publicKey) }
	params := map[string]string{"MacAddress": testMAC, "SerialNumber": "38182B8456F4"}
	gateway := func(p map[string]string) PreProvisioningEvent {
		return PreProvisioningEvent{TemplateARN: templateARNPrefix + gatewayTemplate, CertificatePem: device.certPEM, Parameters: p}
	}
	vaktus := func(p map[string]string) PreProvisioningEvent {
		return PreProvisioningEvent{TemplateARN: templateARNPrefix + vaktusTemplate, CertificatePem: device.certPEM, Parameters: p}
	}
	with := func(attrs map[string]types.AttributeValue, extra map[string]types.AttributeValue) map[string]types.AttributeValue {
		out := map[string]types.AttributeValue{}
		for k, v := range attrs {
			out[k] = v
		}
		for k, v := range extra {
			out[k] = v
		}
		return out
	}

	tests := []struct {
		name            string
		event           PreProvisioningEvent
		getItemFunc     func(ctx context.Context, params *dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error)
		updateItemFunc  func(ctx context.Context, params *dynamodb.UpdateItemInput) (*dynamodb.UpdateItemOutput, error)
		wantAllow       bool
		wantNoLookup    bool
		wantUpdateTried bool // rejected, but only after trying to record the enrolment
	}{
		// --- The gateway (NVS soft key) ---
		{
			name:        "Gateway - certificate key matches the registered key",
			event:       PreProvisioningEvent{TemplateARN: templateARNPrefix + gatewayTemplate, CertificateID: "cert-1", CertificatePem: device.certPEM, Parameters: params},
			getItemFunc: record(gatewayRecord),
			wantAllow:   true,
		},
		{
			name:        "Rejected - the enrolment cannot be recorded (fail closed)",
			event:       gateway(params),
			getItemFunc: record(gatewayRecord),
			updateItemFunc: func(ctx context.Context, params *dynamodb.UpdateItemInput) (*dynamodb.UpdateItemOutput, error) {
				return nil, errors.New("database update error")
			},
			wantUpdateTried: true,
		},
		{
			name:        "Rejected - a concurrent request enrolled the record first",
			event:       gateway(params),
			getItemFunc: record(gatewayRecord),
			updateItemFunc: func(ctx context.Context, params *dynamodb.UpdateItemInput) (*dynamodb.UpdateItemOutput, error) {
				return nil, &types.ConditionalCheckFailedException{Message: aws.String("The conditional request failed")}
			},
			wantUpdateTried: true,
		},

		// --- No shared secret: only a registered key enrols ---
		{
			name:  "Rejected - a gateway record with only a secret (the secret path is gone)",
			event: gateway(map[string]string{"MacAddress": testMAC, "Secret": "supersecret", "SerialNumber": "38182B8456F4"}),
			getItemFunc: record(map[string]types.AttributeValue{
				"mac_address": s(testMAC), "product": s("gateway"), "secret": s("supersecret"), "allowed": b(true),
			}),
		},
		{
			name:  "Rejected - a record without product (no legacy product any more)",
			event: gateway(params),
			getItemFunc: record(map[string]types.AttributeValue{
				"mac_address": s(testMAC), "allowed": b(true), "public_key": s(device.rawXY()),
			}),
		},
		{
			name:        "Gateway - certificate for another key",
			event:       PreProvisioningEvent{TemplateARN: templateARNPrefix + gatewayTemplate, CertificatePem: other.certPEM, Parameters: params},
			getItemFunc: record(gatewayRecord),
		},

		// --- One enrolment per record, inside its window ---
		{
			name:        "Rejected - already provisioned, even with its own key",
			event:       vaktus(params),
			getItemFunc: record(with(vaktusRecord(device.rawXY()), map[string]types.AttributeValue{"provisioned": b(true)})),
		},
		{
			name:        "Approved - provisioned=false is a fresh record",
			event:       gateway(params),
			getItemFunc: record(with(gatewayRecord, map[string]types.AttributeValue{"provisioned": b(false)})),
			wantAllow:   true,
		},
		{
			name:        "Approved - inside the enrolment window",
			event:       gateway(params),
			getItemFunc: record(with(gatewayRecord, map[string]types.AttributeValue{"enrol_by": n(fixedNow.Unix() + 60)})),
			wantAllow:   true,
		},
		{
			name:        "Rejected - the enrolment window has closed",
			event:       gateway(params),
			getItemFunc: record(with(gatewayRecord, map[string]types.AttributeValue{"enrol_by": n(fixedNow.Unix() - 1)})),
		},

		// --- MAC spellings ---
		{
			name:        "Approved - lowercase MAC with dashes finds the AA:BB:.. record",
			event:       gateway(map[string]string{"MacAddress": "38-18-2b-84-56-f4", "SerialNumber": "38182B8456F4"}),
			getItemFunc: lookupMust(testMAC, gatewayRecord),
			wantAllow:   true,
		},
		{
			name:        "Approved - MAC without separators",
			event:       gateway(map[string]string{"MacAddress": "38182b8456f4", "SerialNumber": "38182B8456F4"}),
			getItemFunc: lookupMust(testMAC, gatewayRecord),
			wantAllow:   true,
		},
		{
			name:         "Rejected - MAC is not 12 hex digits",
			event:        gateway(map[string]string{"MacAddress": "38:18:2B:84:56:G4", "SerialNumber": "38182B8456G4"}),
			wantNoLookup: true,
		},

		// --- The thing name is the MAC ---
		{
			name:        "Rejected - SerialNumber names another thing (a gateway's)",
			event:       vaktus(map[string]string{"MacAddress": testMAC, "SerialNumber": "28848553144F"}),
			getItemFunc: record(vaktusRecord(device.rawXY())),
		},
		{
			name:        "Rejected - SerialNumber missing",
			event:       gateway(map[string]string{"MacAddress": testMAC}),
			getItemFunc: record(gatewayRecord),
		},
		{
			name:        "Rejected - lowercase SerialNumber is not the thing name",
			event:       gateway(map[string]string{"MacAddress": testMAC, "SerialNumber": "38182b8456f4"}),
			getItemFunc: record(gatewayRecord),
		},

		// --- Common checks ---
		{
			name:         "Rejected - missing MAC address",
			event:        gateway(map[string]string{"SerialNumber": "38182B8456F4"}),
			wantNoLookup: true,
		},
		{
			name:         "Rejected - unknown template",
			event:        PreProvisioningEvent{TemplateARN: templateARNPrefix + "someone-elses-template", CertificatePem: device.certPEM, Parameters: params},
			wantNoLookup: true,
		},
		{
			name:         "Rejected - no template ARN",
			event:        PreProvisioningEvent{CertificatePem: device.certPEM, Parameters: params},
			wantNoLookup: true,
		},
		{
			name:  "Rejected - DynamoDB error",
			event: gateway(params),
			getItemFunc: func(ctx context.Context, params *dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
				return nil, errors.New("dynamo read error")
			},
		},
		{
			name:        "Rejected - item not found",
			event:       gateway(params),
			getItemFunc: record(nil),
		},
		{
			name:        "Rejected - allowed=false",
			event:       gateway(params),
			getItemFunc: record(with(gatewayRecord, map[string]types.AttributeValue{"allowed": b(false)})),
		},

		// --- Key formats and broken keys (Vaktus, ATECC608) ---
		{
			name:        "Vaktus - certificate key matches the registered X||Y",
			event:       PreProvisioningEvent{TemplateARN: templateARNPrefix + vaktusTemplate, CertificateID: "cert-2", CertificatePem: device.certPEM, Parameters: params},
			getItemFunc: record(vaktusRecord(device.rawXY())),
			wantAllow:   true,
		},
		{
			name:        "Vaktus - registered key with 04 prefix, lowercase and colons",
			event:       vaktus(params),
			getItemFunc: record(vaktusRecord(colons("04" + strings.ToLower(device.rawXY())))),
			wantAllow:   true,
		},
		{
			name:        "Vaktus - registered key as PEM",
			event:       vaktus(params),
			getItemFunc: record(vaktusRecord(device.pem())),
			wantAllow:   true,
		},
		{
			name:        "Vaktus - no registered key",
			event:       vaktus(params),
			getItemFunc: record(map[string]types.AttributeValue{"mac_address": s(testMAC), "product": s("vaktus"), "allowed": b(true)}),
		},
		{
			name:        "Vaktus - no certificate in the request",
			event:       PreProvisioningEvent{TemplateARN: templateARNPrefix + vaktusTemplate, Parameters: params},
			getItemFunc: record(vaktusRecord(device.rawXY())),
		},
		{
			name:        "Vaktus - certificatePem is not a certificate",
			event:       PreProvisioningEvent{TemplateARN: templateARNPrefix + vaktusTemplate, CertificatePem: device.pem(), Parameters: params},
			getItemFunc: record(vaktusRecord(device.rawXY())),
		},
		{
			name:        "Vaktus - registered key is not a point on the curve",
			event:       vaktus(params),
			getItemFunc: record(vaktusRecord(strings.Repeat("11", 64))),
		},
		{
			name:        "Vaktus - registered key is garbage",
			event:       vaktus(params),
			getItemFunc: record(vaktusRecord("not-a-key")),
		},

		// --- A device can only enrol as its own product ---
		{
			name:        "Cross-product - gateway record through the vaktus template",
			event:       vaktus(params),
			getItemFunc: record(gatewayRecord),
		},
		{
			name:        "Cross-product - vaktus record through the gateway template",
			event:       gateway(params),
			getItemFunc: record(vaktusRecord(device.rawXY())),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &MockDynamoDBClient{
				GetItemFunc: func(ctx context.Context, params *dynamodb.GetItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
					if tt.getItemFunc != nil {
						return tt.getItemFunc(ctx, params)
					}
					return &dynamodb.GetItemOutput{}, nil
				},
				UpdateItemFunc: func(ctx context.Context, params *dynamodb.UpdateItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error) {
					if tt.updateItemFunc != nil {
						return tt.updateItemFunc(ctx, params)
					}
					return &dynamodb.UpdateItemOutput{}, nil
				},
			}

			app := &App{
				dbClient:  mockClient,
				tableName: tableName,
				templates: testTemplates(),
				now:       func() time.Time { return fixedNow },
			}

			resp, err := app.Handler(context.Background(), tt.event)
			if err != nil {
				t.Fatalf("unexpected handler error: %v", err)
			}

			if resp.AllowProvisioning != tt.wantAllow {
				t.Errorf("expected allowProvisioning %v, got %v", tt.wantAllow, resp.AllowProvisioning)
			}
			if tt.wantNoLookup && mockClient.getItemCalls != 0 {
				t.Errorf("expected no registry lookup, got %d", mockClient.getItemCalls)
			}

			if !tt.wantAllow {
				if resp.ParameterOverrides != nil {
					t.Errorf("expected nil parameter overrides, got %v", resp.ParameterOverrides)
				}
				if tried := len(mockClient.updateItemCalls) != 0; tried != tt.wantUpdateTried {
					t.Errorf("registry update attempted = %v, want %v", tried, tt.wantUpdateTried)
				}
				return
			}

			if resp.ParameterOverrides["MacAddress"] != testMAC || resp.ParameterOverrides["SerialNumber"] != "38182B8456F4" {
				t.Errorf("expected MacAddress %s and SerialNumber 38182B8456F4 overrides, got %v", testMAC, resp.ParameterOverrides)
			}
			if len(mockClient.updateItemCalls) != 1 {
				t.Fatalf("expected 1 UpdateItem call, got %d", len(mockClient.updateItemCalls))
			}
			upd := mockClient.updateItemCalls[0]
			if *upd.TableName != tableName {
				t.Errorf("expected table name %s, got %s", tableName, *upd.TableName)
			}
			via := upd.ExpressionAttributeValues[":m"].(*types.AttributeValueMemberS).Value
			if via != "public_key" {
				t.Errorf("expected last_provisioned_via public_key, got %q", via)
			}
			certID := upd.ExpressionAttributeValues[":c"].(*types.AttributeValueMemberS).Value
			if certID != tt.event.CertificateID {
				t.Errorf("expected last_certificate_id %q, got %q", tt.event.CertificateID, certID)
			}
			key := upd.Key["mac_address"].(*types.AttributeValueMemberS).Value
			if key != testMAC {
				t.Errorf("expected the update keyed on %s, got %s", testMAC, key)
			}
			cond := aws.ToString(upd.ConditionExpression)
			if !strings.Contains(cond, "attribute_not_exists(provisioned) OR provisioned = :f") || !strings.Contains(cond, "allowed = :t") {
				t.Errorf("the update must claim the record conditionally, got condition %q", cond)
			}
		})
	}
}

func TestTemplateNameFromARN(t *testing.T) {
	tests := map[string]string{
		templateARNPrefix + vaktusTemplate:                         vaktusTemplate,
		"arn:aws:iot:eu-central-1:123456789012:thing/28848553144F": "",
		"": "",
	}
	for in, want := range tests {
		if got := templateNameFromARN(in); got != want {
			t.Errorf("templateNameFromARN(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLoadTemplates(t *testing.T) {
	got, err := loadTemplates(`{"esp32-s3-fleet-template":{"product":"gateway"},"esp32-ztp-vaktus-fleet-template":{"product":"vaktus"}}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got[vaktusTemplate] != (TemplateProduct{Product: "vaktus"}) || got[gatewayTemplate].Product != "gateway" {
		t.Errorf("unexpected templates: %+v", got)
	}

	for _, bad := range []string{"", "not json", "{}", `{"t":{}}`, `{"":{"product":"x"}}`} {
		if _, err := loadTemplates(bad); err == nil {
			t.Errorf("expected an error for %q", bad)
		}
	}
}

func TestThingNameForMAC(t *testing.T) {
	for in, want := range map[string]string{
		"38:18:2B:84:56:F4": "38182B8456F4",
		"28:84:85:53:14:4f": "28848553144F",
		"AA-BB-CC-DD-EE-FF": "AABBCCDDEEFF",
	} {
		if got := thingNameForMAC(in); got != want {
			t.Errorf("thingNameForMAC(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormalizeMAC(t *testing.T) {
	for in, want := range map[string]string{
		"38:18:2B:84:56:F4": "38:18:2B:84:56:F4",
		"38:18:2b:84:56:f4": "38:18:2B:84:56:F4",
		"38-18-2B-84-56-F4": "38:18:2B:84:56:F4",
		"38182b8456f4":      "38:18:2B:84:56:F4",
		" 38182B8456F4 ":    "38:18:2B:84:56:F4",
	} {
		got, ok := normalizeMAC(in)
		if !ok || got != want {
			t.Errorf("normalizeMAC(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
	for _, bad := range []string{"", "38:18:2B:84:56", "38:18:2B:84:56:F4:00", "38:18:2B:84:56:G4", "38.18.2B.84.56.F4"} {
		if got, ok := normalizeMAC(bad); ok {
			t.Errorf("normalizeMAC(%q) = %q, want rejection", bad, got)
		}
	}
}
