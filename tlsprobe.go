// tlsprobe.go — TLS certificate probe and RootDSE query for AD domain controllers.
//
// -tls connects to TCP port 636 (LDAPS) and extracts the server's X.509
// certificate from the TLS handshake.
//
// -rootdse reuses the TLS connection to send an anonymous RootDSE search,
// extracting directory metadata (naming contexts, functional levels, etc.).
//
// No credentials required — both the certificate and RootDSE are readable
// anonymously per RFC 4512 §5.1.
//
// References:
//   RFC 4512 §5.1    (RootDSE)
//   MS-ADTS §3.1.1.3 (rootDSE attributes)
package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// ── TLS certificate info ────────────────────────────────────────────────────

// TLSInfo holds information extracted from the LDAPS TLS handshake.
type TLSInfo struct {
	SubjectCN     string
	SANs          []string
	IssuerCN      string
	IssuerOrg     string
	NotBefore     time.Time
	NotAfter      time.Time
	SerialNumber  string
	SignatureAlgo string
	CRLPoints     []string
	AIAURLs       []string
	OCSPServers   []string
	TLSVersion    string
	CipherSuite   string
}

// ProbeTLS connects to dc:636 via TLS, extracts certificate info, and returns
// both the TLSInfo and the live TLS connection. The caller must close the
// connection when done (or pass it to ProbeRootDSE first).
func ProbeTLS(dc string, timeout time.Duration) (*TLSInfo, *tls.Conn, error) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(dc, "636"), timeout)
	if err != nil {
		return nil, nil, fmt.Errorf("connect: %w", err)
	}

	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err := tlsConn.SetDeadline(time.Now().Add(timeout)); err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("deadline: %w", err)
	}
	if err := tlsConn.Handshake(); err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("TLS handshake: %w", err)
	}

	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		tlsConn.Close()
		return nil, nil, fmt.Errorf("no certificates presented")
	}

	cert := state.PeerCertificates[0]

	info := &TLSInfo{
		SubjectCN:     cert.Subject.CommonName,
		SANs:          cert.DNSNames,
		IssuerCN:      cert.Issuer.CommonName,
		NotBefore:     cert.NotBefore,
		NotAfter:      cert.NotAfter,
		SerialNumber:  fmt.Sprintf("%x", cert.SerialNumber),
		SignatureAlgo: cert.SignatureAlgorithm.String(),
		CRLPoints:     cert.CRLDistributionPoints,
		AIAURLs:       cert.IssuingCertificateURL,
		OCSPServers:   cert.OCSPServer,
		TLSVersion:    tlsVersionString(state.Version),
		CipherSuite:   tls.CipherSuiteName(state.CipherSuite),
	}

	if len(cert.Issuer.Organization) > 0 {
		info.IssuerOrg = cert.Issuer.Organization[0]
	}

	return info, tlsConn, nil
}

// Print writes a formatted TLS certificate summary to w.
func (info *TLSInfo) Print(w io.Writer) {
	fmt.Fprintf(w, "┌── TLS Certificate (port 636) ─────────────────────────\n")
	fmt.Fprintf(w, "│  Subject CN      %s\n", info.SubjectCN)
	if len(info.SANs) > 0 {
		fmt.Fprintf(w, "│  SANs            %s\n", strings.Join(info.SANs, ", "))
	}
	fmt.Fprintf(w, "│  Issuer CN       %s\n", info.IssuerCN)
	if info.IssuerOrg != "" {
		fmt.Fprintf(w, "│  Issuer Org      %s\n", info.IssuerOrg)
	}
	fmt.Fprintf(w, "│  Valid From      %s\n", info.NotBefore.UTC().Format("2006-01-02 15:04:05 UTC"))
	fmt.Fprintf(w, "│  Valid Until     %s\n", info.NotAfter.UTC().Format("2006-01-02 15:04:05 UTC"))
	fmt.Fprintf(w, "│  Serial          %s\n", info.SerialNumber)
	fmt.Fprintf(w, "│  Signature       %s\n", info.SignatureAlgo)
	fmt.Fprintf(w, "│  TLS Version     %s\n", info.TLSVersion)
	fmt.Fprintf(w, "│  Cipher Suite    %s\n", info.CipherSuite)

	if len(info.CRLPoints) > 0 {
		fmt.Fprintf(w, "│\n")
		fmt.Fprintf(w, "│  CRL Distribution Points\n")
		for _, url := range info.CRLPoints {
			fmt.Fprintf(w, "│    %s\n", url)
		}
	}
	if len(info.AIAURLs) > 0 {
		fmt.Fprintf(w, "│  AIA URLs\n")
		for _, url := range info.AIAURLs {
			fmt.Fprintf(w, "│    %s\n", url)
		}
	}
	if len(info.OCSPServers) > 0 {
		fmt.Fprintf(w, "│  OCSP Servers\n")
		for _, url := range info.OCSPServers {
			fmt.Fprintf(w, "│    %s\n", url)
		}
	}

	fmt.Fprintf(w, "└───────────────────────────────────────────────────────\n")
}

// ── RootDSE info ────────────────────────────────────────────────────────────

// RootDSEInfo holds attributes extracted from an anonymous RootDSE query.
type RootDSEInfo struct {
	Attrs map[string][]string
}

// ProbeRootDSE sends an anonymous RootDSE search over an existing connection
// (typically the TLS connection from ProbeTLS) and returns parsed attributes.
func ProbeRootDSE(conn net.Conn, timeout time.Duration) (*RootDSEInfo, error) {
	attrs, err := queryRootDSE(conn, timeout)
	if err != nil {
		return nil, err
	}
	return &RootDSEInfo{Attrs: attrs}, nil
}

// Print writes a formatted RootDSE summary to w.
func (info *RootDSEInfo) Print(w io.Writer) {
	if len(info.Attrs) == 0 {
		fmt.Fprintf(w, "┌── RootDSE ────────────────────────────────────────────\n")
		fmt.Fprintf(w, "│  (no attributes returned)\n")
		fmt.Fprintf(w, "└───────────────────────────────────────────────────────\n")
		return
	}

	fmt.Fprintf(w, "┌── RootDSE ────────────────────────────────────────────\n")

	dseField := func(label, attr string) {
		if vals, ok := info.Attrs[attr]; ok && len(vals) > 0 {
			fmt.Fprintf(w, "│  %-19s%s\n", label, vals[0])
		}
	}
	dseFuncLevel := func(label, attr string) {
		if vals, ok := info.Attrs[attr]; ok && len(vals) > 0 {
			fmt.Fprintf(w, "│  %-19s%s\n", label, functionalLevelString(vals[0]))
		}
	}

	dseField("DNS Hostname", "dnsHostName")
	dseField("Server Name", "serverName")
	dseField("Default NC", "defaultNamingContext")
	dseField("Root Domain NC", "rootDomainNamingContext")
	dseField("Config NC", "configurationNamingContext")
	dseField("Schema NC", "schemaNamingContext")
	dseField("DS Service Name", "dsServiceName")
	dseField("Current Time", "currentTime")
	dseField("Highest USN", "highestCommittedUSN")
	dseField("Is GC Ready", "isGlobalCatalogReady")
	dseField("Is Synchronized", "isSynchronized")
	dseField("LDAP Service", "ldapServiceName")
	dseFuncLevel("Domain Level", "domainFunctionality")
	dseFuncLevel("Forest Level", "forestFunctionality")
	dseFuncLevel("DC Level", "domainControllerFunctionality")

	// Naming contexts (may be multi-valued on GC)
	if ncs, ok := info.Attrs["namingContexts"]; ok && len(ncs) > 1 {
		fmt.Fprintf(w, "│\n")
		fmt.Fprintf(w, "│  Naming Contexts (%d)\n", len(ncs))
		for _, nc := range ncs {
			fmt.Fprintf(w, "│    %s\n", nc)
		}
	}

	// SASL mechanisms
	if mechs, ok := info.Attrs["supportedSASLMechanisms"]; ok && len(mechs) > 0 {
		fmt.Fprintf(w, "│\n")
		fmt.Fprintf(w, "│  SASL Mechanisms  %s\n", strings.Join(mechs, ", "))
	}

	// Supported LDAP controls — show total count + notable ones
	if ctrls, ok := info.Attrs["supportedControl"]; ok && len(ctrls) > 0 {
		fmt.Fprintf(w, "│\n")
		fmt.Fprintf(w, "│  LDAP Controls (%d total)\n", len(ctrls))

		ctrlSet := make(map[string]bool, len(ctrls))
		for _, oid := range ctrls {
			ctrlSet[oid] = true
		}
		for _, kc := range knownControls {
			if ctrlSet[kc.oid] {
				fmt.Fprintf(w, "│    %-42s %s\n", kc.oid, kc.desc)
			}
		}
	}

	fmt.Fprintf(w, "└───────────────────────────────────────────────────────\n")
}

// ── RootDSE query ───────────────────────────────────────────────────────────

const tagPresent = 0x87 // [CONTEXT 7] IMPLICIT — present filter

// buildRootDSESearch returns an LDAP SearchRequest for the RootDSE:
// base="", scope=base, filter=(objectClass=*), attrs=*
func buildRootDSESearch() []byte {
	filter := tlv(tagPresent, []byte("objectClass"))

	// Request all user attributes with "*"
	attrs := tlv(tagSequence, os_("*"))

	searchBody := cat(
		tlv(tagOctetString, nil),          // baseObject = ""
		[]byte{tagEnumerated, 0x01, 0x00}, // scope = baseObject
		[]byte{tagEnumerated, 0x01, 0x00}, // derefAliases = never
		[]byte{tagInteger, 0x01, 0x00},    // sizeLimit = 0
		[]byte{tagInteger, 0x01, 0x00},    // timeLimit = 0
		[]byte{tagBoolean, 0x01, 0x00},    // typesOnly = FALSE
		filter,
		attrs,
	)
	searchReq := tlv(tagSearchReq, searchBody)
	msgID := []byte{tagInteger, 0x01, 0x02} // messageID = 2
	return tlv(tagSequence, cat(msgID, searchReq))
}

// queryRootDSE sends a RootDSE search and parses the response attributes.
func queryRootDSE(conn net.Conn, timeout time.Duration) (map[string][]string, error) {
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}

	req := buildRootDSESearch()
	if _, err := conn.Write(req); err != nil {
		return nil, fmt.Errorf("write: %w", err)
	}

	attrs := make(map[string][]string)

	// Read LDAP messages until we get a SearchResultDone.
	for {
		msg, err := recvLDAPMsg(conn)
		if err != nil {
			return attrs, fmt.Errorf("read: %w", err)
		}

		tag, body, _, err := berNext(msg)
		if err != nil || tag != tagSequence {
			return attrs, fmt.Errorf("parse LDAPMessage: tag=0x%02x err=%v", tag, err)
		}

		// Skip messageID
		_, _, body, err = berNext(body)
		if err != nil {
			return attrs, err
		}

		// protocolOp
		opTag, opBody, _, err := berNext(body)
		if err != nil {
			return attrs, err
		}

		switch opTag {
		case tagSearchEntry:
			parseSearchEntry(opBody, attrs)
		case tagSearchDone:
			return attrs, nil
		}
	}
}

// recvLDAPMsg reads a single BER-encoded LDAP message from a TCP connection.
func recvLDAPMsg(conn net.Conn) ([]byte, error) {
	// Read tag byte.
	tagBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, tagBuf); err != nil {
		return nil, err
	}

	// Read length.
	lenByte := make([]byte, 1)
	if _, err := io.ReadFull(conn, lenByte); err != nil {
		return nil, err
	}

	var bodyLen int
	var header []byte

	if lenByte[0] < 0x80 {
		bodyLen = int(lenByte[0])
		header = append(tagBuf, lenByte...)
	} else {
		nExtra := int(lenByte[0] & 0x7f)
		if nExtra == 0 || nExtra > 4 {
			return nil, fmt.Errorf("invalid BER length (n=%d)", nExtra)
		}
		extra := make([]byte, nExtra)
		if _, err := io.ReadFull(conn, extra); err != nil {
			return nil, err
		}
		for _, b := range extra {
			bodyLen = bodyLen<<8 | int(b)
		}
		header = append(tagBuf, lenByte...)
		header = append(header, extra...)
	}

	if bodyLen > 65536 {
		return nil, fmt.Errorf("message too large (%d bytes)", bodyLen)
	}

	body := make([]byte, bodyLen)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, err
	}

	return append(header, body...), nil
}

// parseSearchEntry extracts attribute name→values from a SearchResultEntry body.
func parseSearchEntry(body []byte, attrs map[string][]string) {
	// Skip objectName
	_, _, body, err := berNext(body)
	if err != nil {
		return
	}

	// partialAttributeList SEQUENCE
	tag, attrList, _, err := berNext(body)
	if err != nil || tag != tagSequence {
		return
	}

	for len(attrList) > 0 {
		var attrBody []byte
		tag, attrBody, attrList, err = berNext(attrList)
		if err != nil || tag != tagSequence {
			continue
		}

		// attribute type
		_, attrType, rest, err := berNext(attrBody)
		if err != nil {
			continue
		}
		name := string(attrType)

		// vals SET
		_, valsBody, _, err := berNext(rest)
		if err != nil {
			continue
		}

		// Walk OCTET STRING values
		for len(valsBody) > 0 {
			var val []byte
			_, val, valsBody, err = berNext(valsBody)
			if err != nil {
				break
			}
			attrs[name] = append(attrs[name], string(val))
		}
	}
}

// ── Display helpers ─────────────────────────────────────────────────────────

func tlsVersionString(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("unknown (0x%04x)", v)
	}
}

// functionalLevelString maps AD functional level integers to OS versions.
func functionalLevelString(val string) string {
	switch val {
	case "0":
		return "0 (Windows 2000)"
	case "1":
		return "1 (Windows Server 2003 Mixed)"
	case "2":
		return "2 (Windows Server 2003)"
	case "3":
		return "3 (Windows Server 2008)"
	case "4":
		return "4 (Windows Server 2008 R2)"
	case "5":
		return "5 (Windows Server 2012)"
	case "6":
		return "6 (Windows Server 2012 R2)"
	case "7":
		return "7 (Windows Server 2016)"
	default:
		return val
	}
}

// knownControls lists LDAP control OIDs worth highlighting when advertised.
// Reference: MS-ADTS §3.1.1.3.4.6, IETF RFCs.
type knownControl struct {
	oid  string
	desc string
}

var knownControls = []knownControl{
	// Replication / DCSync surface
	{"1.2.840.113556.1.4.841", "DIRSYNC — AD replication via LDAP (DCSync surface)"},
	{"1.2.840.113556.1.4.528", "SERVER_NOTIFICATION — persistent search / change notifications"},

	// Security descriptor access
	{"1.2.840.113556.1.4.801", "SD_FLAGS — request specific DACL/SACL portions"},

	// Password policy
	{"1.2.840.113556.1.4.2066", "POLICY_HINTS — enforce password policy on resets"},
	{"1.2.840.113556.1.4.2239", "POLICY_HINTS_DEPRECATED — legacy password policy hints"},

	// Cross-domain operations
	{"1.2.840.113556.1.4.521", "CROSSDOM_MOVE — cross-domain object moves"},

	// Tombstone / deleted object recovery
	{"1.2.840.113556.1.4.417", "SHOW_DELETED — include tombstoned objects in results"},
	{"1.2.840.113556.1.4.2064", "SHOW_RECYCLED — include recycled objects (AD Recycle Bin)"},
	{"1.2.840.113556.1.4.2065", "SHOW_DEACTIVATED_LINK — show deactivated linked values"},

	// Query controls
	{"1.2.840.113556.1.4.319", "PAGED_RESULTS — paged search results (RFC 2696)"},
	{"1.2.840.113556.1.4.473", "SORT_REQUEST — server-side sort (RFC 2891)"},
	{"1.2.840.113556.1.4.1339", "DOMAIN_SCOPE — restrict search to single NC"},
	{"1.2.840.113556.1.4.1340", "SEARCH_OPTIONS — phantom root / domain scope search"},
	{"1.2.840.113556.1.4.529", "EXTENDED_DN — return extended DNs with GUID/SID"},
	{"1.2.840.113556.1.4.1781", "FAST_BIND — skip group membership / token computation"},
	{"1.2.840.113556.1.4.1852", "QUOTA_CONTROL — query per-object quota usage"},
	{"1.2.840.113556.1.4.802", "RANGE_OPTION — incremental retrieval of multi-valued attrs"},

	// Lazy commit / transaction
	{"1.2.840.113556.1.4.619", "LAZY_COMMIT — relaxed write durability"},
	{"1.2.840.113556.1.4.1670", "TREE_DELETE — recursive subtree deletion"},

	// Access control / permissions
	{"1.2.840.113556.1.4.1504", "PERMISSIVE_MODIFY — ignore duplicate add/remove errors"},
	{"1.2.840.113556.1.4.2237", "SET_OWNER — set SD owner on creation"},

	// Authentication / credential
	{"1.2.840.113556.1.4.1338", "VERIFY_NAME — validate name against GC"},
	{"1.2.840.113556.1.4.1413", "PERMISSIVE_MODIFY_V2 — input/output validation control"},

	// Operational
	{"1.2.840.113556.1.4.970", "RODC_DCPROMO — RODC promotion operations"},
	{"1.2.840.113556.1.4.2204", "BATCH_REQUEST — batch multiple operations"},
}
