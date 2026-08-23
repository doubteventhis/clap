// cldap.go — CLDAP (Connectionless LDAP) ping for AD account enumeration.
//
// Technique: Windows domain controllers answer anonymous CLDAP SearchRequest packets
// sent via UDP to port 389. The response contains a NETLOGON attribute whose first
// two bytes (little-endian uint16) encode an opcode:
//   23 (0x17) = LOGON_SAM_LOGON_RESPONSE_EX  → account exists
//   25 (0x19) = LOGON_SAM_USER_UNKNOWN_EX     → account not found
//
// The AAC (AllowableAccountControlBits) filter field selects the account type:
//   0x00000010  USER_NORMAL_ACCOUNT                (domain users)
//   0x00000080  USER_WORKSTATION_TRUST_ACCOUNT     (workstations/servers)
//   0x00000100  USER_SERVER_TRUST_ACCOUNT          (domain controllers)
//   0x00000040  USER_INTERDOMAIN_TRUST_ACCOUNT     (domain trusts)
//   0x000001C0  all computer/trust types OR'd       (workstations+DCs+trusts)
//
// No credentials required. Generates no Windows event log entries.
//
// References:
//   https://sensepost.com/blog/2018/a-new-look-at-null-sessions-and-user-enumeration/
//   MS-ADTS §6.3.3  LDAP Ping (CLDAP)
//   MS-SAMR §2.2.1.12 USER_ACCOUNT_CONTROL flags
//   RFC 4511 (LDAP protocol / BER encoding)
package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// BER/LDAP tag constants.
const (
	tagSequence    = 0x30 // UNIVERSAL SEQUENCE (constructed)
	tagInteger     = 0x02 // UNIVERSAL INTEGER
	tagOctetString = 0x04 // UNIVERSAL OCTET STRING
	tagEnumerated  = 0x0a // UNIVERSAL ENUMERATED
	tagBoolean     = 0x01 // UNIVERSAL BOOLEAN
	tagSearchReq   = 0x63 // [APPLICATION 3] constructed — SearchRequest
	tagSearchEntry = 0x64 // [APPLICATION 4] constructed — SearchResultEntry
	tagSearchDone  = 0x65 // [APPLICATION 5] constructed — SearchResultDone
	tagAndFilter   = 0xa0 // [CONTEXT 0] constructed — AND filter
	tagEqMatch     = 0xa3 // [CONTEXT 3] constructed — equalityMatch filter
)

// NETLOGON response opcodes (MS-ADTS §6.3.1.1).
const (
	opcodeUserExists  = 23 // LOGON_SAM_LOGON_RESPONSE_EX
	opcodeUserUnknown = 25 // LOGON_SAM_USER_UNKNOWN_EX
)

// AAC (AllowableAccountControlBits) values for the CLDAP filter.
// These are the USER_ flags from MS-SAMR §2.2.1.12 (not the UF_ flags).
var (
	AACUser     = []byte{0x10, 0x00, 0x00, 0x00} // 0x10 — USER_NORMAL_ACCOUNT
	AACComputer = []byte{0xC0, 0x01, 0x00, 0x00} // 0x1C0 — workstations | DCs | trusts
)

// ── BER helpers ──────────────────────────────────────────────────────────────

// berEncodeLen returns the BER-encoded form of length n.
func berEncodeLen(n int) []byte {
	switch {
	case n < 0x80:
		return []byte{byte(n)}
	case n < 0x100:
		return []byte{0x81, byte(n)}
	default:
		return []byte{0x82, byte(n >> 8), byte(n & 0xff)}
	}
}

// tlv wraps val with a BER tag and length prefix.
func tlv(tag byte, val []byte) []byte {
	out := append([]byte{tag}, berEncodeLen(len(val))...)
	return append(out, val...)
}

// cat concatenates byte slices.
func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// os wraps a string as a BER OCTET STRING (tag 0x04).
func os_(s string) []byte { return tlv(tagOctetString, []byte(s)) }

// osb wraps a byte slice as a BER OCTET STRING (tag 0x04).
func osb(b []byte) []byte { return tlv(tagOctetString, b) }

// ── Packet construction ───────────────────────────────────────────────────────

// buildSearchRequest wraps a filter + attributes into a complete LDAP SearchRequest.
func buildSearchRequest(andFilter, attrs []byte) []byte {
	searchBody := cat(
		tlv(tagOctetString, nil),                   // baseObject = ""
		[]byte{tagEnumerated, 0x01, 0x00},          // scope = baseObject
		[]byte{tagEnumerated, 0x01, 0x00},          // derefAliases = never
		[]byte{tagInteger, 0x01, 0x00},             // sizeLimit = 0
		[]byte{tagInteger, 0x01, 0x00},             // timeLimit = 0
		[]byte{tagBoolean, 0x01, 0x00},             // typesOnly = FALSE
		andFilter,
		attrs,
	)
	searchReq := tlv(tagSearchReq, searchBody)
	msgID := []byte{tagInteger, 0x01, 0x01}
	return tlv(tagSequence, cat(msgID, searchReq))
}

// BuildProbeRequest returns a CLDAP ping that extracts maximum DC information.
// Uses NtVer=0x17 (V1|V5|V5EX|VCS) and no User/AAC filter — the DC always
// responds with opcode 23 and the full NETLOGON_SAM_LOGON_RESPONSE_EX blob.
// If domain is empty, the DC uses its default/primary domain.
func BuildProbeRequest(domain string) []byte {
	// NtVer=0x00000017 LE — V1|V5|V5EX|VCS for maximum response info.
	ntVer := []byte{0x17, 0x00, 0x00, 0x00}

	var filters []byte
	if domain != "" {
		filters = append(filters, tlv(tagEqMatch, cat(os_("DnsDomain"), os_(domain)))...)
	}
	filters = append(filters, tlv(tagEqMatch, cat(os_("NtVer"), osb(ntVer)))...)
	andFilter := tlv(tagAndFilter, filters)
	attrs := tlv(tagSequence, os_("Netlogon"))

	return buildSearchRequest(andFilter, attrs)
}

// BuildRequest returns a CLDAP ping packet (BER-encoded LDAP SearchRequest
// over UDP) that asks the DC to locate an account in domain.
//
// Filter:  (&(DnsDomain=<domain>)(User=<name>)(NtVer=\x06\x00\x00\x00)(AAC=<aac>))
// Attrs:   Netlogon
// Scope:   baseObject (search root DSE only)
//
// Use AACUser for normal domain users, AACComputer for machine/trust accounts.
func BuildRequest(domain, name string, aac []byte) []byte {
	// NtVer=0x00000006 LE — requests LOGON_SAM_LOGON_RESPONSE_EX reply format.
	// See MS-ADTS §6.3.3.2 NETLOGON_NT_VERSION.
	ntVer := []byte{0x06, 0x00, 0x00, 0x00}

	// equalityMatch filters: [CONTEXT 3] IMPLICIT { attributeDesc, assertionValue }
	fDomain := tlv(tagEqMatch, cat(os_("DnsDomain"), os_(domain)))
	fUser   := tlv(tagEqMatch, cat(os_("User"), os_(name)))
	fNtVer  := tlv(tagEqMatch, cat(os_("NtVer"), osb(ntVer)))
	fAAC    := tlv(tagEqMatch, cat(os_("AAC"), osb(aac)))

	// AND filter: [CONTEXT 0] SET OF Filter
	andFilter := tlv(tagAndFilter, cat(fDomain, fUser, fNtVer, fAAC))

	// Attributes to return — only the Netlogon blob.
	attrs := tlv(tagSequence, os_("Netlogon"))

	return buildSearchRequest(andFilter, attrs)
}

// ── Response parsing ──────────────────────────────────────────────────────────

// berNext reads one TLV from data and returns (tag, value, remaining, error).
// For constructed types (SEQUENCE, SET, ...) value is the inner content.
func berNext(data []byte) (tag byte, value []byte, rest []byte, err error) {
	if len(data) < 2 {
		return 0, nil, nil, fmt.Errorf("BER: need ≥2 bytes, have %d", len(data))
	}
	tag = data[0]
	length, n, err := berDecodeLen(data[1:])
	if err != nil {
		return 0, nil, nil, fmt.Errorf("BER length: %w", err)
	}
	offset := 1 + n
	if len(data) < offset+length {
		return 0, nil, nil, fmt.Errorf("BER: value truncated (need %d, have %d)", length, len(data)-offset)
	}
	return tag, data[offset : offset+length], data[offset+length:], nil
}

// berDecodeLen decodes a BER length field. Returns (length, bytes consumed, error).
func berDecodeLen(data []byte) (int, int, error) {
	if len(data) == 0 {
		return 0, 0, fmt.Errorf("empty")
	}
	if data[0] < 0x80 {
		return int(data[0]), 1, nil
	}
	n := int(data[0] & 0x7f)
	if n == 0 || n > 4 || len(data) < 1+n {
		return 0, 0, fmt.Errorf("invalid multibyte length (n=%d, have %d bytes)", n, len(data))
	}
	var l int
	for i := 0; i < n; i++ {
		l = l<<8 | int(data[1+i])
	}
	return l, 1 + n, nil
}

// parseOpcode extracts the NETLOGON opcode from a raw CLDAP response packet.
// Returns opcodeUserExists (23) or opcodeUserUnknown (25), or an error.
func parseOpcode(data []byte) (int, error) {
	blob, err := extractNetlogonBlob(data)
	if err != nil {
		return 0, err
	}
	if len(blob) < 2 {
		return 0, fmt.Errorf("Netlogon blob too short (%d bytes)", len(blob))
	}
	return int(binary.LittleEndian.Uint16(blob[:2])), nil
}

// extractNetlogonBlob extracts the raw Netlogon attribute value from a CLDAP
// response packet. Returns the binary blob for further parsing.
func extractNetlogonBlob(data []byte) ([]byte, error) {
	// Outer SEQUENCE = LDAPMessage
	tag, body, _, err := berNext(data)
	if err != nil {
		return nil, fmt.Errorf("LDAPMessage: %w", err)
	}
	if tag != tagSequence {
		return nil, fmt.Errorf("expected SEQUENCE (0x30), got 0x%02x", tag)
	}

	// Skip messageID
	_, _, body, err = berNext(body)
	if err != nil {
		return nil, fmt.Errorf("messageID: %w", err)
	}

	// protocolOp
	tag, opBody, _, err := berNext(body)
	if err != nil {
		return nil, fmt.Errorf("protocolOp: %w", err)
	}

	if tag != tagSearchEntry {
		if tag == tagSearchDone {
			return nil, fmt.Errorf("received SearchResultDone with no entry")
		}
		return nil, fmt.Errorf("unexpected protocol op 0x%02x", tag)
	}

	// SearchResultEntry: objectName, then partialAttributeList
	_, _, opBody, err = berNext(opBody) // skip objectName
	if err != nil {
		return nil, fmt.Errorf("objectName: %w", err)
	}

	tag, attrList, _, err := berNext(opBody)
	if err != nil {
		return nil, fmt.Errorf("partialAttributeList: %w", err)
	}
	if tag != tagSequence {
		return nil, fmt.Errorf("expected attrList SEQUENCE, got 0x%02x", tag)
	}

	for len(attrList) > 0 {
		var attrBody []byte
		tag, attrBody, attrList, err = berNext(attrList)
		if err != nil {
			return nil, fmt.Errorf("partialAttribute: %w", err)
		}
		if tag != tagSequence {
			continue
		}

		var attrType, rest []byte
		_, attrType, rest, err = berNext(attrBody)
		if err != nil {
			continue
		}
		if string(attrType) != "Netlogon" {
			continue
		}

		// vals SET
		var valsBody []byte
		_, valsBody, _, err = berNext(rest)
		if err != nil {
			return nil, fmt.Errorf("vals SET: %w", err)
		}

		// First OCTET STRING = raw NETLOGON blob
		var val []byte
		_, val, _, err = berNext(valsBody)
		if err != nil {
			return nil, fmt.Errorf("Netlogon value: %w", err)
		}
		return val, nil
	}

	return nil, fmt.Errorf("Netlogon attribute not found")
}

// ── High-level API ────────────────────────────────────────────────────────────

// ProbeDC sends a CLDAP probe (no User/AAC filter) and returns parsed DC info.
func ProbeDC(dc, domain string, timeout time.Duration) (*NetlogonInfo, error) {
	addr, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(dc, "389"))
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", dc, err)
	}

	conn, err := net.DialUDP("udp4", nil, addr)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	if err = conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, fmt.Errorf("deadline: %w", err)
	}

	req := BuildProbeRequest(domain)
	if _, err = conn.Write(req); err != nil {
		return nil, fmt.Errorf("write: %w", err)
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}

	blob, err := extractNetlogonBlob(buf[:n])
	if err != nil {
		return nil, fmt.Errorf("extract blob: %w", err)
	}

	return ParseNetlogonInfo(blob)
}

// CheckAccount sends a CLDAP ping to dc:389 and returns (true, nil) if the
// account exists in domain, (false, nil) if not, or (false, err) on error.
// Use AACUser for domain users, AACComputer for machine/trust accounts.
func CheckAccount(dc, domain, name string, aac []byte, timeout time.Duration) (bool, error) {
	addr, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(dc, "389"))
	if err != nil {
		return false, fmt.Errorf("resolve %s: %w", dc, err)
	}

	conn, err := net.DialUDP("udp4", nil, addr)
	if err != nil {
		return false, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	if err = conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return false, fmt.Errorf("deadline: %w", err)
	}

	req := BuildRequest(domain, name, aac)
	if _, err = conn.Write(req); err != nil {
		return false, fmt.Errorf("write: %w", err)
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return false, fmt.Errorf("read: %w", err)
	}

	opcode, err := parseOpcode(buf[:n])
	if err != nil {
		return false, fmt.Errorf("parse response: %w", err)
	}

	switch opcode {
	case opcodeUserExists:
		return true, nil
	case opcodeUserUnknown:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected NETLOGON opcode %d", opcode)
	}
}
