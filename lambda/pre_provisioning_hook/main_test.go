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
	"strings"
	"testing"
	"time"

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
		vaktusTemplate:  {Product: "vaktus", RequirePublicKey: true},
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

func s(v string) types.AttributeValue { return &types.AttributeValueMemberS{Value: v} }
func b(v bool) types.AttributeValue   { return &types.AttributeValueMemberBOOL{Value: v} }
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

	// A gateway record from before products existed: no product, no key.
	legacyGateway := map[string]types.AttributeValue{
		"mac_address": s(testMAC), "secret": s("supersecret"), "allowed": b(true),
	}
	vaktusRecord := func(publicKey string) map[string]types.AttributeValue {
		return map[string]types.AttributeValue{
			"mac_address": s(testMAC), "product": s("vaktus"), "allowed": b(true), "public_key": s(publicKey),
		}
	}
	gatewayParams := map[string]string{"MacAddress": testMAC, "Secret": "supersecret", "SerialNumber": "38182B8456F4"}
	vaktusParams := map[string]string{"MacAddress": testMAC, "SerialNumber": "38182B8456F4"}

	tests := []struct {
		name           string
		event          PreProvisioningEvent
		getItemFunc    func(ctx context.Context, params *dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error)
		updateItemFunc func(ctx context.Context, params *dynamodb.UpdateItemInput) (*dynamodb.UpdateItemOutput, error)
		wantAllow      bool
		wantVia        string // last_provisioned_via written on approval
		wantNoLookup   bool
	}{
		// --- Secret-based products (the gateway) ---
		{
			name:        "Gateway - legacy record approved with its secret",
			event:       PreProvisioningEvent{TemplateARN: templateARNPrefix + gatewayTemplate, CertificateID: "cert-1", Parameters: gatewayParams},
			getItemFunc: record(legacyGateway),
			wantAllow:   true,
			wantVia:     "secret",
		},
		{
			name:        "Gateway - record with product gateway approved",
			event:       PreProvisioningEvent{TemplateARN: templateARNPrefix + gatewayTemplate, Parameters: gatewayParams},
			getItemFunc: record(map[string]types.AttributeValue{"mac_address": s(testMAC), "secret": s("supersecret"), "allowed": b(true), "product": s("gateway")}),
			wantAllow:   true,
			wantVia:     "secret",
		},
		{
			name:        "Gateway - approved even if the DynamoDB update fails (best effort)",
			event:       PreProvisioningEvent{TemplateARN: templateARNPrefix + gatewayTemplate, Parameters: gatewayParams},
			getItemFunc: record(legacyGateway),
			updateItemFunc: func(ctx context.Context, params *dynamodb.UpdateItemInput) (*dynamodb.UpdateItemOutput, error) {
				return nil, errors.New("database update error")
			},
			wantAllow: true,
			wantVia:   "secret",
		},
		{
			name:        "Gateway - secret missing",
			event:       PreProvisioningEvent{TemplateARN: templateARNPrefix + gatewayTemplate, Parameters: map[string]string{"MacAddress": testMAC}},
			getItemFunc: record(legacyGateway),
		},
		{
			name:        "Gateway - secret mismatch",
			event:       PreProvisioningEvent{TemplateARN: templateARNPrefix + gatewayTemplate, Parameters: map[string]string{"MacAddress": testMAC, "Secret": "wrongsecret"}},
			getItemFunc: record(legacyGateway),
		},
		{
			name:  "Gateway - a registered key is required even for a secret product",
			event: PreProvisioningEvent{TemplateARN: templateARNPrefix + gatewayTemplate, CertificatePem: other.certPEM, Parameters: gatewayParams},
			getItemFunc: record(map[string]types.AttributeValue{
				"mac_address": s(testMAC), "secret": s("supersecret"), "allowed": b(true), "public_key": s(device.rawXY()),
			}),
		},

		// --- Common checks ---
		{
			name:         "Rejected - missing MAC address",
			event:        PreProvisioningEvent{TemplateARN: templateARNPrefix + gatewayTemplate, Parameters: map[string]string{"Secret": "supersecret"}},
			wantNoLookup: true,
		},
		{
			name:         "Rejected - unknown template",
			event:        PreProvisioningEvent{TemplateARN: templateARNPrefix + "someone-elses-template", Parameters: gatewayParams},
			wantNoLookup: true,
		},
		{
			name:         "Rejected - no template ARN",
			event:        PreProvisioningEvent{Parameters: gatewayParams},
			wantNoLookup: true,
		},
		{
			name:  "Rejected - DynamoDB error",
			event: PreProvisioningEvent{TemplateARN: templateARNPrefix + gatewayTemplate, Parameters: gatewayParams},
			getItemFunc: func(ctx context.Context, params *dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
				return nil, errors.New("dynamo read error")
			},
		},
		{
			name:        "Rejected - item not found",
			event:       PreProvisioningEvent{TemplateARN: templateARNPrefix + gatewayTemplate, Parameters: gatewayParams},
			getItemFunc: record(nil),
		},
		{
			name:        "Rejected - allowed=false",
			event:       PreProvisioningEvent{TemplateARN: templateARNPrefix + gatewayTemplate, Parameters: gatewayParams},
			getItemFunc: record(map[string]types.AttributeValue{"mac_address": s(testMAC), "secret": s("supersecret"), "allowed": b(false)}),
		},

		// --- Public-key products (Vaktus, ATECC608) ---
		{
			name:        "Vaktus - certificate key matches the registered X||Y",
			event:       PreProvisioningEvent{TemplateARN: templateARNPrefix + vaktusTemplate, CertificateID: "cert-2", CertificatePem: device.certPEM, Parameters: vaktusParams},
			getItemFunc: record(vaktusRecord(device.rawXY())),
			wantAllow:   true,
			wantVia:     "public_key",
		},
		{
			name:        "Vaktus - registered key with 04 prefix, lowercase and colons",
			event:       PreProvisioningEvent{TemplateARN: templateARNPrefix + vaktusTemplate, CertificatePem: device.certPEM, Parameters: vaktusParams},
			getItemFunc: record(vaktusRecord(colons("04" + strings.ToLower(device.rawXY())))),
			wantAllow:   true,
			wantVia:     "public_key",
		},
		{
			name:        "Vaktus - registered key as PEM",
			event:       PreProvisioningEvent{TemplateARN: templateARNPrefix + vaktusTemplate, CertificatePem: device.certPEM, Parameters: vaktusParams},
			getItemFunc: record(vaktusRecord(device.pem())),
			wantAllow:   true,
			wantVia:     "public_key",
		},
		{
			name:        "Vaktus - certificate for another key",
			event:       PreProvisioningEvent{TemplateARN: templateARNPrefix + vaktusTemplate, CertificatePem: other.certPEM, Parameters: vaktusParams},
			getItemFunc: record(vaktusRecord(device.rawXY())),
		},
		{
			name:  "Vaktus - a correct secret is not enough without a registered key",
			event: PreProvisioningEvent{TemplateARN: templateARNPrefix + vaktusTemplate, CertificatePem: device.certPEM, Parameters: gatewayParams},
			getItemFunc: record(map[string]types.AttributeValue{
				"mac_address": s(testMAC), "product": s("vaktus"), "secret": s("supersecret"), "allowed": b(true),
			}),
		},
		{
			name:        "Vaktus - no certificate in the request",
			event:       PreProvisioningEvent{TemplateARN: templateARNPrefix + vaktusTemplate, Parameters: vaktusParams},
			getItemFunc: record(vaktusRecord(device.rawXY())),
		},
		{
			name:        "Vaktus - certificatePem is not a certificate",
			event:       PreProvisioningEvent{TemplateARN: templateARNPrefix + vaktusTemplate, CertificatePem: device.pem(), Parameters: vaktusParams},
			getItemFunc: record(vaktusRecord(device.rawXY())),
		},
		{
			name:        "Vaktus - registered key is not a point on the curve",
			event:       PreProvisioningEvent{TemplateARN: templateARNPrefix + vaktusTemplate, CertificatePem: device.certPEM, Parameters: vaktusParams},
			getItemFunc: record(vaktusRecord(strings.Repeat("11", 64))),
		},
		{
			name:        "Vaktus - registered key is garbage",
			event:       PreProvisioningEvent{TemplateARN: templateARNPrefix + vaktusTemplate, CertificatePem: device.certPEM, Parameters: vaktusParams},
			getItemFunc: record(vaktusRecord("not-a-key")),
		},

		// --- A device can only enrol as its own product ---
		{
			name:        "Cross-product - gateway record through the vaktus template",
			event:       PreProvisioningEvent{TemplateARN: templateARNPrefix + vaktusTemplate, CertificatePem: device.certPEM, Parameters: gatewayParams},
			getItemFunc: record(legacyGateway),
		},
		{
			name:        "Cross-product - vaktus record through the gateway template",
			event:       PreProvisioningEvent{TemplateARN: templateARNPrefix + gatewayTemplate, CertificatePem: device.certPEM, Parameters: gatewayParams},
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
				dbClient:            mockClient,
				tableName:           tableName,
				templates:           testTemplates(),
				legacyRecordProduct: "gateway",
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
				if len(mockClient.updateItemCalls) != 0 {
					t.Errorf("a rejected request must not update the registry")
				}
				return
			}

			if resp.ParameterOverrides["MacAddress"] != testMAC {
				t.Errorf("expected MacAddress override %s, got %v", testMAC, resp.ParameterOverrides)
			}
			if len(mockClient.updateItemCalls) != 1 {
				t.Fatalf("expected 1 UpdateItem call, got %d", len(mockClient.updateItemCalls))
			}
			upd := mockClient.updateItemCalls[0]
			if *upd.TableName != tableName {
				t.Errorf("expected table name %s, got %s", tableName, *upd.TableName)
			}
			via := upd.ExpressionAttributeValues[":m"].(*types.AttributeValueMemberS).Value
			if via != tt.wantVia {
				t.Errorf("expected last_provisioned_via %q, got %q", tt.wantVia, via)
			}
			certID := upd.ExpressionAttributeValues[":c"].(*types.AttributeValueMemberS).Value
			if certID != tt.event.CertificateID {
				t.Errorf("expected last_certificate_id %q, got %q", tt.event.CertificateID, certID)
			}
		})
	}
}

// Without a legacy product, a record that names no product belongs to none.
func TestRecordWithoutProductAndNoLegacyProduct(t *testing.T) {
	mockClient := &MockDynamoDBClient{
		GetItemFunc: func(ctx context.Context, params *dynamodb.GetItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
			return &dynamodb.GetItemOutput{Item: map[string]types.AttributeValue{
				"mac_address": s(testMAC), "secret": s("supersecret"), "allowed": b(true),
			}}, nil
		},
	}
	app := &App{dbClient: mockClient, tableName: tableName, templates: testTemplates()}
	resp, err := app.Handler(context.Background(), PreProvisioningEvent{
		TemplateARN: templateARNPrefix + gatewayTemplate,
		Parameters:  map[string]string{"MacAddress": testMAC, "Secret": "supersecret"},
	})
	if err != nil || resp.AllowProvisioning {
		t.Errorf("expected a rejection, got %+v, %v", resp, err)
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
	got, err := loadTemplates(`{"esp32-s3-fleet-template":{"product":"gateway","require_public_key":false},"esp32-ztp-vaktus-fleet-template":{"product":"vaktus","require_public_key":true}}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got[vaktusTemplate] != (TemplateProduct{Product: "vaktus", RequirePublicKey: true}) || got[gatewayTemplate].Product != "gateway" {
		t.Errorf("unexpected templates: %+v", got)
	}

	for _, bad := range []string{"", "not json", "{}", `{"t":{}}`, `{"":{"product":"x"}}`} {
		if _, err := loadTemplates(bad); err == nil {
			t.Errorf("expected an error for %q", bad)
		}
	}
}
