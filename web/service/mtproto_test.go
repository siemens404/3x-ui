package service

import (
	"strings"
	"testing"

	"github.com/mhsanaei/3x-ui/v2/database/model"
)

func TestNormalizeAndValidateMTProtoSettings(t *testing.T) {
	svc := &InboundService{}

	inbound := &model.Inbound{
		Protocol: model.MTProto,
		Settings: `{"secret":"AABBCCDDEEFF00112233445566778899"}`,
	}
	if err := svc.normalizeAndValidateMTProtoSettings(inbound); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(inbound.Settings, `"users"`) {
		t.Fatalf("normalized settings must contain users array: %s", inbound.Settings)
	}
	if !strings.Contains(inbound.Settings, `"secret": "aabbccddeeff00112233445566778899"`) {
		t.Fatalf("secret must be normalized to lowercase hex: %s", inbound.Settings)
	}
}

func TestNormalizeAndValidateMTProtoSettingsRejectsInvalidSecret(t *testing.T) {
	svc := &InboundService{}

	cases := []string{
		`{"secret":"abc"}`,
		`{"users":[{"secret":"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"}]}`,
		`{"users":[{}]}`,
	}

	for _, settings := range cases {
		inbound := &model.Inbound{
			Protocol: model.MTProto,
			Settings: settings,
		}
		if err := svc.normalizeAndValidateMTProtoSettings(inbound); err == nil {
			t.Fatalf("expected error for settings: %s", settings)
		}
	}
}

func TestMTProtoGenXrayConfigDoesNotAffectOtherInbound(t *testing.T) {
	mtproto := &model.Inbound{
		Listen:   "0.0.0.0",
		Port:     443,
		Protocol: model.MTProto,
		Settings: `{"users":[{"secret":"00112233445566778899aabbccddeeff"}]}`,
		Tag:      "inbound-443",
	}
	vmess := &model.Inbound{
		Listen:   "0.0.0.0",
		Port:     1443,
		Protocol: model.VMESS,
		Settings: `{"clients":[{"id":"7a71395e-b7dd-4cc5-87dd-0dd7f4c7602d","email":"test@example.com"}]}`,
		Tag:      "inbound-1443",
	}

	mtCfg := mtproto.GenXrayInboundConfig()
	vmCfg := vmess.GenXrayInboundConfig()

	if mtCfg.Protocol != string(model.MTProto) {
		t.Fatalf("expected protocol mtproto, got %s", mtCfg.Protocol)
	}
	if !strings.Contains(string(mtCfg.Settings), `"secret":"00112233445566778899aabbccddeeff"`) {
		t.Fatalf("mtproto settings were not generated correctly: %s", string(mtCfg.Settings))
	}
	if vmCfg.Protocol != string(model.VMESS) {
		t.Fatalf("expected vmess protocol to remain unchanged, got %s", vmCfg.Protocol)
	}
	if !strings.Contains(string(vmCfg.Settings), `"clients"`) {
		t.Fatalf("vmess settings unexpectedly changed: %s", string(vmCfg.Settings))
	}
}
