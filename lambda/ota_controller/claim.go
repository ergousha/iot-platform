package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iot"
	iottypes "github.com/aws/aws-sdk-go-v2/service/iot/types"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

// staleCertAge: an unattached certificate older than this is deleted (a
// device that never finished RegisterThing, a decommissioned thing).
const staleCertAge = 24 * time.Hour

// ClaimState is the controller's bookkeeping for the claim, in SSM.
type ClaimState struct {
	// RotatePending: the tick armed the claim for a site window; rotate once
	// the window closes, since a board may still hold the claim.
	RotatePending bool   `json:"rotate_pending"`
	RotatedAt     string `json:"rotated_at,omitempty"`
	// Notified is the key of the last one-off claim email.
	Notified string `json:"notified,omitempty"`
}

// certID is the AWS IoT certificate id of a PEM: the SHA-256 of its DER.
func certID(certPEM string) (string, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return "", errors.New("not a certificate PEM")
	}
	sum := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(sum[:]), nil
}

func idFromARN(a string) string { return a[strings.LastIndexByte(a, '/')+1:] }

// claimTargets are the certificate ids the claim policy is attached to:
// normally exactly one, the claim.
func (a *App) claimTargets(ctx context.Context) ([]string, error) {
	var ids []string
	var marker *string
	for {
		out, err := a.iot.ListTargetsForPolicy(ctx, &iot.ListTargetsForPolicyInput{PolicyName: aws.String(a.cfg.ClaimPolicy), Marker: marker})
		if err != nil {
			return nil, fmt.Errorf("listing the targets of %s: %w", a.cfg.ClaimPolicy, err)
		}
		for _, t := range out.Targets {
			if strings.Contains(t, ":cert/") {
				ids = append(ids, idFromARN(t))
			}
		}
		if aws.ToString(out.NextMarker) == "" {
			sort.Strings(ids)
			return ids, nil
		}
		marker = out.NextMarker
	}
}

// currentClaim is the id of the claim certificate in SSM ("" if none).
func (a *App) currentClaim(ctx context.Context) (string, error) {
	out, err := a.ssm.GetParameter(ctx, &ssm.GetParameterInput{Name: aws.String(a.cfg.ClaimCertParameter), WithDecryption: aws.Bool(true)})
	if err != nil {
		var missing *ssmtypes.ParameterNotFound
		if errors.As(err, &missing) {
			return "", nil
		}
		return "", fmt.Errorf("reading %s: %w", a.cfg.ClaimCertParameter, err)
	}
	id, err := certID(aws.ToString(out.Parameter.Value))
	if err != nil {
		return "", fmt.Errorf("%s: %w", a.cfg.ClaimCertParameter, err)
	}
	return id, nil
}

func (a *App) claimState(ctx context.Context) (ClaimState, error) {
	var st ClaimState
	out, err := a.ssm.GetParameter(ctx, &ssm.GetParameterInput{Name: aws.String(a.cfg.ClaimStateParameter)})
	if err != nil {
		var missing *ssmtypes.ParameterNotFound
		if errors.As(err, &missing) {
			return st, nil
		}
		return st, fmt.Errorf("reading %s: %w", a.cfg.ClaimStateParameter, err)
	}
	_ = json.Unmarshal([]byte(aws.ToString(out.Parameter.Value)), &st)
	return st, nil
}

func (a *App) saveClaimState(ctx context.Context, st ClaimState) error {
	b, _ := json.Marshal(st)
	_, err := a.ssm.PutParameter(ctx, &ssm.PutParameterInput{
		Name: aws.String(a.cfg.ClaimStateParameter), Value: aws.String(string(b)),
		Type: ssmtypes.ParameterTypeString, Overwrite: aws.Bool(true),
	})
	if err != nil {
		return fmt.Errorf("writing %s: %w", a.cfg.ClaimStateParameter, err)
	}
	return nil
}

func (a *App) certStatus(ctx context.Context, id string) (iottypes.CertificateStatus, error) {
	out, err := a.iot.DescribeCertificate(ctx, &iot.DescribeCertificateInput{CertificateId: aws.String(id)})
	if err != nil {
		return "", fmt.Errorf("describing certificate %.12s: %w", id, err)
	}
	return out.CertificateDescription.Status, nil
}

func (a *App) setCert(ctx context.Context, id string, status iottypes.CertificateStatus) error {
	_, err := a.iot.UpdateCertificate(ctx, &iot.UpdateCertificateInput{CertificateId: aws.String(id), NewStatus: status})
	if err != nil {
		return fmt.Errorf("setting certificate %.12s %s: %w", id, status, err)
	}
	return nil
}

// claimTick keeps the claim ACTIVE exactly while an enrolment window is open
// (a registry record that may still enrol) and the guard is clear. `ergo
// commission` arms and disarms bench windows itself; the tick covers site
// windows (`ergo register --minutes`, up to a week) and closes anything left
// open. The claim is rotated after a site window and whenever the claim in
// SSM is missing or not the one the policy is attached to.
func (a *App) claimTick(ctx context.Context, records []Record, tripped bool) error {
	targets, err := a.claimTargets(ctx)
	if err != nil {
		return err
	}
	if tripped {
		// The kill switch did this already; re-assert it.
		var errs []error
		for _, id := range targets {
			errs = append(errs, a.setCert(ctx, id, iottypes.CertificateStatusInactive))
		}
		return errors.Join(errs...)
	}

	now := a.now()
	var open []string
	for _, r := range records {
		if r.windowOpen(now) {
			open = append(open, r.Thing)
		}
	}
	current, err := a.currentClaim(ctx)
	if err != nil {
		return err
	}
	st, err := a.claimState(ctx)
	if err != nil {
		return err
	}
	usable := current != "" && contains(targets, current)

	if len(open) > 0 {
		if !usable {
			return a.notifyOnceGlobal(ctx, "no-claim", "no usable claim for an open enrolment window",
				fmt.Sprintf("Enrolment windows are open for %s, but the claim in SSM is missing or not attached to %s. "+
					"The claim is rotated once the windows close.", strings.Join(open, ", "), a.cfg.ClaimPolicy))
		}
		status, err := a.certStatus(ctx, current)
		if err != nil {
			return err
		}
		if status != iottypes.CertificateStatusActive {
			if err := a.setCert(ctx, current, iottypes.CertificateStatusActive); err != nil {
				return err
			}
			slog.Info("Claim armed for open enrolment windows", "things", open)
			st.RotatePending = true
			return a.saveClaimState(ctx, st)
		}
		return nil
	}

	for _, id := range targets {
		status, err := a.certStatus(ctx, id)
		if err != nil {
			return err
		}
		if status == iottypes.CertificateStatusActive {
			if err := a.setCert(ctx, id, iottypes.CertificateStatusInactive); err != nil {
				return err
			}
			slog.Info("Claim disarmed: no enrolment window is open", "certificate", id[:12])
		}
	}
	switch {
	case !usable:
		return a.rotateClaim(ctx, "the claim in SSM is missing or not attached to the claim policy")
	case st.RotatePending:
		return a.rotateClaim(ctx, "a site enrolment window closed")
	case len(targets) > 1:
		return a.rotateClaim(ctx, "the claim policy has more than one target")
	}
	return nil
}

// rotateClaim replaces the claim: a P-256 key generated here and never
// written anywhere but SSM, a certificate from its CSR (INACTIVE), the claim
// policy attached, the SSM parameters overwritten, and only then every other
// target of the claim policy deactivated, detached and deleted. A failure
// part-way leaves the policy with two targets; the next tick finishes it.
// It refuses while a window is open: a board may be enrolling with the
// current claim.
func (a *App) rotateClaim(ctx context.Context, why string) error {
	now := a.now()
	records, err := a.loadRecords(ctx)
	if err != nil {
		return err
	}
	for _, r := range records {
		if r.windowOpen(now) {
			return fmt.Errorf("refusing to rotate the claim: the enrolment window of %s is open until %s", r.Thing, r.EnrolBy.UTC().Format(time.RFC3339))
		}
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "iot-platform-claim"},
	}, key)
	if err != nil {
		return err
	}
	created, err := a.iot.CreateCertificateFromCsr(ctx, &iot.CreateCertificateFromCsrInput{
		CertificateSigningRequest: aws.String(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}))),
		SetAsActive:               false,
	})
	if err != nil {
		return fmt.Errorf("creating the claim certificate: %w", err)
	}
	newID := aws.ToString(created.CertificateId)
	if _, err := a.iot.AttachPolicy(ctx, &iot.AttachPolicyInput{PolicyName: aws.String(a.cfg.ClaimPolicy), Target: created.CertificateArn}); err != nil {
		return fmt.Errorf("attaching %s to the new claim: %w", a.cfg.ClaimPolicy, err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	for _, p := range []struct{ name, value string }{
		{a.cfg.ClaimCertParameter, aws.ToString(created.CertificatePem)},
		{a.cfg.ClaimKeyParameter, string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))},
	} {
		_, err := a.ssm.PutParameter(ctx, &ssm.PutParameterInput{
			Name: aws.String(p.name), Value: aws.String(p.value),
			Type: ssmtypes.ParameterTypeSecureString, Overwrite: aws.Bool(true),
			Description: aws.String("Fleet provisioning claim, rotated by the OTA controller. Read only by ergo."),
		})
		if err != nil {
			return fmt.Errorf("writing %s: %w", p.name, err)
		}
	}

	targets, err := a.claimTargets(ctx)
	if err != nil {
		return err
	}
	var errs []error
	for _, id := range targets {
		if id == newID {
			continue
		}
		errs = append(errs, a.retireCert(ctx, id, true))
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}
	if err := a.saveClaimState(ctx, ClaimState{RotatedAt: now.UTC().Format(time.RFC3339)}); err != nil {
		return err
	}
	slog.Info("Claim rotated", "reason", why, "certificate", newID[:12])
	return a.notify(ctx, "claim rotated", fmt.Sprintf("The provisioning claim was rotated (%s). New certificate %s; "+
		"the previous one is deleted. Boards commissioned but not enrolled before now need `ergo commission` again.", why, newID[:12]))
}

// retireCert deactivates and deletes a certificate. The claim policy is
// detached first when asked; forceDelete covers other policies.
func (a *App) retireCert(ctx context.Context, id string, claim bool) error {
	if err := a.setCert(ctx, id, iottypes.CertificateStatusInactive); err != nil {
		return err
	}
	if claim {
		arn := fmt.Sprintf("arn:aws:iot:%s:%s:cert/%s", a.cfg.Region, a.cfg.Account, id)
		if _, err := a.iot.DetachPolicy(ctx, &iot.DetachPolicyInput{PolicyName: aws.String(a.cfg.ClaimPolicy), Target: aws.String(arn)}); err != nil {
			return fmt.Errorf("detaching %s from %.12s: %w", a.cfg.ClaimPolicy, id, err)
		}
	}
	if _, err := a.iot.DeleteCertificate(ctx, &iot.DeleteCertificateInput{CertificateId: aws.String(id), ForceDelete: true}); err != nil {
		return fmt.Errorf("deleting certificate %.12s: %w", id, err)
	}
	return nil
}

// certHygiene runs hourly:
//
//   - A thing with more than one certificate (re-enrolled at the bench) keeps
//     the newest, once presence shows the device connected with it; the older
//     ones are deactivated and detached.
//   - A certificate attached to no thing, older than a day, and not a claim
//     is deleted.
//
// A device's working certificate is always attached to its thing, so nothing
// here can cut off a device that connects with its newest certificate.
func (a *App) certHygiene(ctx context.Context, presence map[string]*Device) error {
	now := a.now()
	claims, err := a.claimTargets(ctx)
	if err != nil {
		return err
	}
	certs := map[string]iottypes.Certificate{}
	cp := iot.NewListCertificatesPaginator(a.iot, &iot.ListCertificatesInput{PageSize: aws.Int32(250)})
	for cp.HasMorePages() {
		page, err := cp.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("listing certificates: %w", err)
		}
		for _, c := range page.Certificates {
			certs[aws.ToString(c.CertificateId)] = c
		}
	}

	attached := map[string]bool{}
	var actions []string
	tp := iot.NewListThingsPaginator(a.iot, &iot.ListThingsInput{MaxResults: aws.Int32(250)})
	for tp.HasMorePages() {
		page, err := tp.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("listing things: %w", err)
		}
		for _, t := range page.Things {
			thing := aws.ToString(t.ThingName)
			out, err := a.iot.ListThingPrincipals(ctx, &iot.ListThingPrincipalsInput{ThingName: aws.String(thing)})
			if err != nil {
				return fmt.Errorf("listing the principals of %s: %w", thing, err)
			}
			var ids []string
			for _, p := range out.Principals {
				if strings.Contains(p, ":cert/") {
					attached[idFromARN(p)] = true
					ids = append(ids, idFromARN(p))
				}
			}
			if len(ids) < 2 {
				continue
			}
			sort.Slice(ids, func(i, j int) bool {
				return aws.ToTime(certs[ids[i]].CreationDate).After(aws.ToTime(certs[ids[j]].CreationDate))
			})
			newest := ids[0]
			if pr := presence[thing]; pr == nil || pr.Principal != newest {
				continue // not yet seen connecting with the new certificate
			}
			for _, old := range ids[1:] {
				if err := a.setCert(ctx, old, iottypes.CertificateStatusInactive); err != nil {
					return err
				}
				arn := aws.ToString(certs[old].CertificateArn)
				if _, err := a.iot.DetachThingPrincipal(ctx, &iot.DetachThingPrincipalInput{ThingName: aws.String(thing), Principal: aws.String(arn)}); err != nil {
					return fmt.Errorf("detaching %.12s from %s: %w", old, thing, err)
				}
				actions = append(actions, fmt.Sprintf("%s: older certificate %.12s deactivated and detached", thing, old))
			}
		}
	}

	for id, c := range certs {
		if attached[id] || contains(claims, id) || now.Sub(aws.ToTime(c.CreationDate)) < staleCertAge {
			continue
		}
		if c.Status != iottypes.CertificateStatusActive && c.Status != iottypes.CertificateStatusInactive {
			continue
		}
		if err := a.retireCert(ctx, id, false); err != nil {
			return err
		}
		actions = append(actions, fmt.Sprintf("unattached certificate %.12s (created %s) deleted", id, aws.ToTime(c.CreationDate).UTC().Format(time.RFC3339)))
	}
	if len(actions) == 0 {
		return nil
	}
	sort.Strings(actions)
	return a.notify(ctx, "certificate hygiene", strings.Join(actions, "\n"))
}

// notifyOnceGlobal emails once per key, keyed in the claim state parameter.
func (a *App) notifyOnceGlobal(ctx context.Context, key, subject, body string) error {
	st, err := a.claimState(ctx)
	if err != nil {
		return err
	}
	if st.Notified == key {
		return nil
	}
	if err := a.notify(ctx, subject, body); err != nil {
		return err
	}
	st.Notified = key
	return a.saveClaimState(ctx, st)
}
