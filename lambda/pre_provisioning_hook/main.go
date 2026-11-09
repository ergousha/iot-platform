package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// PreProvisioningEvent is the input AWS IoT Fleet Provisioning sends the hook
// (https://docs.aws.amazon.com/iot/latest/developerguide/pre-provisioning-hook.html).
// certificatePem is the certificate being provisioned: for a CSR, the one AWS
// IoT issued for the device's own key. There is no template name field; the
// template comes from templateArn.
type PreProvisioningEvent struct {
	ClaimCertificateID string            `json:"claimCertificateId"`
	CertificateID      string            `json:"certificateId"`
	CertificatePem     string            `json:"certificatePem"`
	TemplateARN        string            `json:"templateArn"`
	ClientID           string            `json:"clientId"`
	Parameters         map[string]string `json:"parameters"`
}

// PreProvisioningResponse represents the output payload expected by AWS IoT Fleet Provisioning.
type PreProvisioningResponse struct {
	AllowProvisioning  bool              `json:"allowProvisioning"`
	ParameterOverrides map[string]string `json:"parameterOverrides,omitempty"`
}

// DeviceItem matches the schema of the DynamoDB Device Registry.
//
// product is the product the device may enrol as; a record written before
// products existed has none and belongs to the legacy product. public_key, when
// set, is the key the device's certificate must carry: the device proves itself
// with the key in its secure element, and the secret is not consulted. It is a
// PEM "PUBLIC KEY" block, or the hex of an uncompressed P-256 point (130 hex
// digits starting 04, or the 128 digits of X||Y as an ATECC608 GenKey returns
// them).
type DeviceItem struct {
	MacAddress  string `dynamodbav:"mac_address"`
	Secret      string `dynamodbav:"secret"`
	Allowed     bool   `dynamodbav:"allowed"`
	Provisioned bool   `dynamodbav:"provisioned"`
	Product     string `dynamodbav:"product"`
	PublicKey   string `dynamodbav:"public_key"`
}

// TemplateProduct is what a provisioning template enrols: a product, and
// whether that product must prove itself with a registered public key.
type TemplateProduct struct {
	Product          string `json:"product"`
	RequirePublicKey bool   `json:"require_public_key"`
}

// DynamoDBAPI defines the DynamoDB operations utilized by this Lambda.
type DynamoDBAPI interface {
	GetItem(ctx context.Context, params *dynamodb.GetItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error)
	UpdateItem(ctx context.Context, params *dynamodb.UpdateItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error)
}

// App encapsulates the application context, facilitating unit testing via client interfaces.
type App struct {
	dbClient  DynamoDBAPI
	tableName string

	// templates maps a provisioning template name to what it enrols.
	templates map[string]TemplateProduct
	// legacyRecordProduct owns registry records without a product ("" = none).
	legacyRecordProduct string
}

var reject = PreProvisioningResponse{AllowProvisioning: false}

// Handler processes the incoming IoT Fleet Provisioning pre-provisioning
// request. Every failure, including an internal one, rejects: the hook fails
// closed.
func (a *App) Handler(ctx context.Context, event PreProvisioningEvent) (PreProvisioningResponse, error) {
	mac := event.Parameters["MacAddress"]
	secret := event.Parameters["Secret"]
	serial := event.Parameters["SerialNumber"]
	templateName := templateNameFromARN(event.TemplateARN)

	slog.Info("Pre-provisioning request received",
		"mac", mac,
		"serial", serial,
		"template", templateName,
		"certificateId", event.CertificateID,
	)

	tmpl, known := a.templates[templateName]
	if !known {
		slog.Warn("REJECTED: unknown provisioning template", "templateArn", event.TemplateARN)
		return reject, nil
	}

	if mac == "" {
		slog.Warn("REJECTED: MacAddress parameter missing")
		return reject, nil
	}

	// The template names the thing after SerialNumber, and the device policy
	// lets a connection act as exactly that thing. Every product names its
	// thing after its MAC, so require that: otherwise a registered device
	// could enrol under another device's thing name, another product's
	// included, and receive its jobs and shadow.
	thingName := thingNameForMAC(mac)
	if serial != thingName {
		slog.Warn("REJECTED: SerialNumber is not the thing name of this MAC",
			"mac", mac, "serial", serial, "expected", thingName)
		return reject, nil
	}

	resp, err := a.dbClient.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(a.tableName),
		Key: map[string]types.AttributeValue{
			"mac_address": &types.AttributeValueMemberS{Value: mac},
		},
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		slog.Error("DynamoDB get_item error", "error", err)
		return reject, nil
	}

	if resp.Item == nil {
		slog.Warn("REJECTED: record does not exist in DynamoDB", "mac", mac)
		return reject, nil
	}

	var item DeviceItem
	err = attributevalue.UnmarshalMap(resp.Item, &item)
	if err != nil {
		slog.Error("Failed to unmarshal DynamoDB item", "error", err)
		return reject, nil
	}

	if !item.Allowed {
		slog.Warn("REJECTED: allowed=false", "mac", mac)
		return reject, nil
	}

	recordProduct := item.Product
	if recordProduct == "" {
		recordProduct = a.legacyRecordProduct
	}
	if recordProduct == "" || recordProduct != tmpl.Product {
		slog.Warn("REJECTED: device is not registered for this template's product",
			"mac", mac, "registeredProduct", recordProduct, "templateProduct", tmpl.Product)
		return reject, nil
	}

	var method string
	switch {
	case item.PublicKey != "" || tmpl.RequirePublicKey:
		// The device holds its key in a secure element: the certificate AWS IoT
		// issued must be for exactly the key registered for this device. A
		// leaked claim credential or shared secret cannot satisfy this.
		if item.PublicKey == "" {
			slog.Warn("REJECTED: product requires a registered public key, record has none",
				"mac", mac, "product", tmpl.Product)
			return reject, nil
		}
		registered, err := parsePublicKey(item.PublicKey)
		if err != nil {
			slog.Error("REJECTED: registry record has an unreadable public_key", "mac", mac, "error", err)
			return reject, nil
		}
		presented, err := certificatePublicKey(event.CertificatePem)
		if err != nil {
			slog.Warn("REJECTED: no usable certificate in the request", "mac", mac, "error", err)
			return reject, nil
		}
		if !publicKeysEqual(registered, presented) {
			slog.Warn("REJECTED: certificate public key does not match the registered key", "mac", mac)
			return reject, nil
		}
		method = "public_key"
	default:
		if secret == "" || !constantTimeEq(item.Secret, secret) {
			slog.Warn("REJECTED: secret missing or mismatched", "mac", mac)
			return reject, nil
		}
		method = "secret"
	}

	// Record the provisioning (best-effort)

	_, err = a.dbClient.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String(a.tableName),
		Key: map[string]types.AttributeValue{
			"mac_address": &types.AttributeValueMemberS{Value: mac},
		},
		UpdateExpression: aws.String("SET provisioned = :t, last_provisioned_serial = :s, last_certificate_id = :c, last_provisioned_via = :m"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":t": &types.AttributeValueMemberBOOL{Value: true},
			":s": &types.AttributeValueMemberS{Value: thingName},
			":c": &types.AttributeValueMemberS{Value: event.CertificateID},
			":m": &types.AttributeValueMemberS{Value: method},
		},
	})
	if err != nil {
		slog.Error("Failed to update provisioned flag (continuing anyway)", "error", err)
	}

	slog.Info("APPROVED: provisioning allowed", "mac", mac, "product", tmpl.Product, "via", method)
	return PreProvisioningResponse{
		AllowProvisioning: true,
		ParameterOverrides: map[string]string{
			"MacAddress":   mac,
			"SerialNumber": thingName,
		},
	}, nil
}

// thingNameForMAC is the thing name every product uses: the MAC as 12
// uppercase hex digits, without separators.
func thingNameForMAC(mac string) string {
	return strings.ToUpper(strings.NewReplacer(":", "", "-", "").Replace(mac))
}

// templateNameFromARN returns <name> from arn:aws:iot:...:provisioningtemplate/<name>.
func templateNameFromARN(templateARN string) string {
	_, name, found := strings.Cut(templateARN, ":provisioningtemplate/")
	if !found {
		return ""
	}
	return name
}

// parsePublicKey reads a registered public key: a PEM PUBLIC KEY block, or the
// hex of an uncompressed P-256 point with or without its 04 prefix. Colons and
// whitespace in the hex are ignored, so a key pasted from a device log works.
func parsePublicKey(s string) (crypto.PublicKey, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "-----BEGIN") {
		block, _ := pem.Decode([]byte(s))
		if block == nil || block.Type != "PUBLIC KEY" {
			return nil, errors.New("not a PEM PUBLIC KEY block")
		}
		return x509.ParsePKIXPublicKey(block.Bytes)
	}

	clean := strings.Map(func(r rune) rune {
		if r == ':' || r == ' ' || r == '\n' || r == '\r' || r == '\t' {
			return -1
		}
		return r
	}, s)
	raw, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("not hex: %w", err)
	}
	if len(raw) == 64 {
		raw = append([]byte{0x04}, raw...)
	}
	if len(raw) != 65 || raw[0] != 0x04 {
		return nil, fmt.Errorf("expected an uncompressed P-256 point (64 or 65 bytes), got %d bytes", len(raw))
	}
	// Rejects a point that is not on the curve.
	return ecdsa.ParseUncompressedPublicKey(elliptic.P256(), raw)
}

// certificatePublicKey returns the public key of a PEM certificate.
func certificatePublicKey(certPEM string) (crypto.PublicKey, error) {
	if certPEM == "" {
		return nil, errors.New("certificatePem is empty")
	}
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("certificatePem is not a PEM CERTIFICATE block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing certificate: %w", err)
	}
	return cert.PublicKey, nil
}

// publicKeysEqual compares two public keys of any type the standard library
// parses (ECDSA, RSA, Ed25519).
func publicKeysEqual(a, b crypto.PublicKey) bool {
	ka, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && b != nil && ka.Equal(b)
}

// constantTimeEq compares two strings in constant time to prevent timing attacks.
func constantTimeEq(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// loadTemplates parses PRODUCTS_BY_TEMPLATE: template name -> TemplateProduct.
func loadTemplates(value string) (map[string]TemplateProduct, error) {
	var templates map[string]TemplateProduct
	if err := json.Unmarshal([]byte(value), &templates); err != nil {
		return nil, fmt.Errorf("PRODUCTS_BY_TEMPLATE is not valid JSON: %w", err)
	}
	if len(templates) == 0 {
		return nil, errors.New("PRODUCTS_BY_TEMPLATE lists no template")
	}
	for name, t := range templates {
		if name == "" || t.Product == "" {
			return nil, fmt.Errorf("PRODUCTS_BY_TEMPLATE: template %q needs a name and a product", name)
		}
	}
	return templates, nil
}

func main() {
	// Configure logging
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	tableName := os.Getenv("DEVICE_TABLE")
	if tableName == "" {
		slog.Error("DEVICE_TABLE environment variable is required")
		panic(errors.New("DEVICE_TABLE environment variable is required"))
	}

	templates, err := loadTemplates(os.Getenv("PRODUCTS_BY_TEMPLATE"))
	if err != nil {
		slog.Error("Invalid configuration", "error", err)
		panic(err)
	}

	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		slog.Error("Unable to load AWS SDK config", "error", err)
		panic(fmt.Sprintf("unable to load SDK config, %v", err))
	}

	app := &App{
		dbClient:            dynamodb.NewFromConfig(cfg),
		tableName:           tableName,
		templates:           templates,
		legacyRecordProduct: os.Getenv("LEGACY_RECORD_PRODUCT"),
	}

	lambda.Start(app.Handler)
}
