// netlogon.go — Parser for NETLOGON_SAM_LOGON_RESPONSE_EX structures.
//
// The Netlogon attribute returned in a CLDAP ping response contains a binary
// blob with DC identity, domain/forest info, capability flags, and AD site
// topology. String fields use RFC 1035 DNS name compression.
//
// Reference: MS-ADTS §6.3.1.9 NETLOGON_SAM_LOGON_RESPONSE_EX
package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"
)

// NetlogonInfo holds all fields parsed from a NETLOGON_SAM_LOGON_RESPONSE_EX.
type NetlogonInfo struct {
	Opcode              uint16
	Flags               uint32
	DomainGuid          [16]byte
	DnsForestName       string
	DnsDomainName       string
	DnsHostName         string
	NetbiosDomainName   string
	NetbiosComputerName string
	UserName            string
	DcSiteName          string
	ClientSiteName      string
	NextClosestSiteName string // present if NtVer included VCS (0x10)
	NtVersion           uint32
}

// ── DS_FLAG constants (MS-ADTS §6.3.1.2) ─────────────────────────────────────

const (
	flagPDC           = 0x00000001 // PDC Emulator FSMO role holder
	flagGC            = 0x00000004 // Global Catalog server
	flagLDAP          = 0x00000008 // LDAP server (always set)
	flagDS            = 0x00000010 // Domain Controller (always set)
	flagKDC           = 0x00000020 // Kerberos KDC
	flagTimeserv      = 0x00000040 // W32Time service
	flagClosest       = 0x00000080 // DC is in client's AD site
	flagWritable      = 0x00000100 // Writable DC (not RODC)
	flagGoodTimeserv  = 0x00000200 // Reliable time source
	flagNDNC          = 0x00000400 // NC is an Application NC
	flagRODC          = 0x00000800 // Read-Only Domain Controller
	flagWS2008        = 0x00001000 // Writable DC running WS2008+
	flagADWS          = 0x00002000 // Active Directory Web Services
	flagWS2012        = 0x00004000 // Windows Server 2012+
	flagWS2012R2      = 0x00008000 // Windows Server 2012 R2+
	flagDNSController = 0x20000000 // DC has a DNS name
	flagDNSDomain     = 0x40000000 // NC is a domain NC
	flagForestRoot    = 0x80000000 // NC is the forest root
)

// ── RFC 1035 DNS name decompression ──────────────────────────────────────────

// decompressName reads an RFC 1035 compressed DNS name starting at offset
// within data. Returns (name, bytes consumed from offset, error).
// Pointers reference positions within the same data buffer.
func decompressName(data []byte, offset int) (string, int, error) {
	var labels []string
	consumed := 0
	followed := false
	pos := offset
	seen := make(map[int]bool) // cycle detection

	for {
		if pos >= len(data) {
			return "", 0, fmt.Errorf("offset %d beyond data length %d", pos, len(data))
		}
		b := data[pos]

		if b == 0 {
			if !followed {
				consumed = pos - offset + 1
			}
			break
		}

		if b&0xC0 == 0xC0 {
			// Pointer — 2 bytes: offset = ((b & 0x3F) << 8) | next_byte
			if pos+1 >= len(data) {
				return "", 0, fmt.Errorf("pointer at %d extends beyond data", pos)
			}
			if !followed {
				consumed = pos - offset + 2
				followed = true
			}
			ptr := int(b&0x3F)<<8 | int(data[pos+1])
			if seen[ptr] {
				return "", 0, fmt.Errorf("pointer loop at offset %d", ptr)
			}
			seen[ptr] = true
			pos = ptr
			continue
		}

		// Label: length byte + label bytes
		labelLen := int(b)
		pos++
		if pos+labelLen > len(data) {
			return "", 0, fmt.Errorf("label at %d (len %d) extends beyond data", pos, labelLen)
		}
		labels = append(labels, string(data[pos:pos+labelLen]))
		pos += labelLen
	}

	return strings.Join(labels, "."), consumed, nil
}

// ── NETLOGON response parsing ────────────────────────────────────────────────

// ParseNetlogonInfo parses the raw Netlogon attribute value into a NetlogonInfo.
func ParseNetlogonInfo(data []byte) (*NetlogonInfo, error) {
	// Minimum: Opcode(2) + Sbz(2) + Flags(4) + GUID(16) = 24 bytes
	// Plus at least a few name terminators + trailing 8 bytes
	if len(data) < 32 {
		return nil, fmt.Errorf("netlogon blob too short (%d bytes, need ≥32)", len(data))
	}

	info := &NetlogonInfo{
		Opcode: binary.LittleEndian.Uint16(data[0:2]),
		// Sbz at [2:4] — skip
		Flags: binary.LittleEndian.Uint32(data[4:8]),
	}
	copy(info.DomainGuid[:], data[8:24])

	offset := 24
	readName := func(field string) (string, error) {
		name, n, err := decompressName(data, offset)
		if err != nil {
			return "", fmt.Errorf("%s at offset %d: %w", field, offset, err)
		}
		offset += n
		return name, nil
	}

	var err error
	if info.DnsForestName, err = readName("DnsForestName"); err != nil {
		return nil, err
	}
	if info.DnsDomainName, err = readName("DnsDomainName"); err != nil {
		return nil, err
	}
	if info.DnsHostName, err = readName("DnsHostName"); err != nil {
		return nil, err
	}
	if info.NetbiosDomainName, err = readName("NetbiosDomainName"); err != nil {
		return nil, err
	}
	if info.NetbiosComputerName, err = readName("NetbiosComputerName"); err != nil {
		return nil, err
	}
	if info.UserName, err = readName("UserName"); err != nil {
		return nil, err
	}
	if info.DcSiteName, err = readName("DcSiteName"); err != nil {
		return nil, err
	}
	if info.ClientSiteName, err = readName("ClientSiteName"); err != nil {
		return nil, err
	}

	// Trailing 8 bytes: NtVersion(4) + LmNtToken(2) + Lm20Token(2)
	// Anything between ClientSiteName and the trailing 8 is NextClosestSiteName.
	remaining := len(data) - offset
	if remaining > 8 {
		if info.NextClosestSiteName, err = readName("NextClosestSiteName"); err != nil {
			// Non-fatal — might just be missing
			info.NextClosestSiteName = ""
		}
	}

	// Read NtVersion from the end-8 position (or current offset)
	if offset+8 <= len(data) {
		info.NtVersion = binary.LittleEndian.Uint32(data[offset : offset+4])
	}

	return info, nil
}

// ── Display ──────────────────────────────────────────────────────────────────

type flagDef struct {
	bit  uint32
	tag  string // short label
	desc string // longer description
}

var flagDefs = []flagDef{
	{flagPDC, "PDC", "PDC Emulator FSMO role holder"},
	{flagGC, "GC", "Global Catalog server"},
	{flagLDAP, "LDAP", "LDAP server"},
	{flagDS, "DS", "Domain Controller"},
	{flagKDC, "KDC", "Kerberos Key Distribution Center"},
	{flagTimeserv, "TIMESERV", "Running Windows Time Service"},
	{flagClosest, "CLOSEST", "DC is in the client's AD site"},
	{flagWritable, "WRITABLE", "Writable DC (not a read-only replica)"},
	{flagGoodTimeserv, "GOOD_TIMESERV", "Reliable time source (PDC or external NTP)"},
	{flagNDNC, "NDNC", "Hosts an Application partition"},
	{flagRODC, "RODC", "Read-Only Domain Controller"},
	{flagWS2008, "WS2008+", "Running Windows Server 2008 or later"},
	{flagADWS, "ADWS", "Active Directory Web Services available"},
	{flagWS2012, "WS2012+", "Running Windows Server 2012 or later"},
	{flagWS2012R2, "WS2012R2+", "Running Windows Server 2012 R2 or later"},
	{flagDNSController, "DNS_CONTROLLER", "DC has a DNS name"},
	{flagDNSDomain, "DNS_DOMAIN", "Domain name is a DNS name"},
	{flagForestRoot, "FOREST_ROOT", "Domain is the forest root"},
}

// FlagNames returns short labels for all set DS_FLAG bits.
func (info *NetlogonInfo) FlagNames() []string {
	var names []string
	for _, d := range flagDefs {
		if info.Flags&d.bit != 0 {
			names = append(names, d.tag)
		}
	}
	return names
}

// FlagDetails returns "TAG — description" strings for all set DS_FLAG bits.
func (info *NetlogonInfo) FlagDetails() []string {
	var lines []string
	for _, d := range flagDefs {
		if info.Flags&d.bit != 0 {
			lines = append(lines, fmt.Sprintf("%-16s %s", d.tag, d.desc))
		}
	}
	return lines
}

// OSHint returns the best guess at the DC's Windows Server version.
func (info *NetlogonInfo) OSHint() string {
	f := info.Flags
	switch {
	case f&flagWS2012R2 != 0:
		return "Windows Server 2012 R2 or later"
	case f&flagWS2012 != 0:
		return "Windows Server 2012"
	case f&flagWS2008 != 0:
		return "Windows Server 2008/2008 R2"
	default:
		return "Windows Server 2003 or earlier"
	}
}

// OpcodeString returns a human-readable description of the response opcode.
func (info *NetlogonInfo) OpcodeString() string {
	switch info.Opcode {
	case 19:
		return "LOGON_SAM_LOGON_RESPONSE (success, V5)"
	case 20:
		return "LOGON_SAM_PAUSE_RESPONSE (netlogon paused/not synced)"
	case 21:
		return "LOGON_SAM_USER_UNKNOWN (user not found, V5)"
	case 23:
		return "LOGON_SAM_LOGON_RESPONSE_EX (success)"
	case 24:
		return "LOGON_SAM_PAUSE_RESPONSE_EX (netlogon paused/not synced)"
	case 25:
		return "LOGON_SAM_USER_UNKNOWN_EX (user not found)"
	default:
		return fmt.Sprintf("unknown (%d)", info.Opcode)
	}
}

// formatGUID formats a 16-byte Windows GUID (mixed-endian) as a string.
func formatGUID(g [16]byte) string {
	return fmt.Sprintf("%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		binary.LittleEndian.Uint32(g[0:4]),
		binary.LittleEndian.Uint16(g[4:6]),
		binary.LittleEndian.Uint16(g[6:8]),
		g[8], g[9], g[10], g[11], g[12], g[13], g[14], g[15])
}

// Print writes a formatted DC information summary to w.
func (info *NetlogonInfo) Print(w io.Writer) {
	fmt.Fprintf(w, "┌── DC Information ──────────────────────────────────────\n")
	fmt.Fprintf(w, "│  DC Hostname     %s\n", info.DnsHostName)
	fmt.Fprintf(w, "│  DC NetBIOS      %s\n", info.NetbiosComputerName)
	fmt.Fprintf(w, "│  DC Site         %s\n", info.DcSiteName)
	fmt.Fprintf(w, "│  Domain DNS      %s\n", info.DnsDomainName)
	fmt.Fprintf(w, "│  Domain NetBIOS  %s\n", info.NetbiosDomainName)
	fmt.Fprintf(w, "│  Forest DNS      %s\n", info.DnsForestName)
	fmt.Fprintf(w, "│  Domain GUID     %s\n", formatGUID(info.DomainGuid))

	if info.ClientSiteName != "" {
		fmt.Fprintf(w, "│  Client Site     %s\n", info.ClientSiteName)
	}
	if info.NextClosestSiteName != "" {
		fmt.Fprintf(w, "│  Next Site       %s\n", info.NextClosestSiteName)
	}

	isForestRoot := info.DnsForestName == info.DnsDomainName
	if !isForestRoot {
		fmt.Fprintf(w, "│  Child Domain    YES (forest root: %s)\n", info.DnsForestName)
	}

	fmt.Fprintf(w, "│  Opcode          %s\n", info.OpcodeString())
	fmt.Fprintf(w, "│  OS Hint         %s\n", info.OSHint())
	fmt.Fprintf(w, "│\n")
	fmt.Fprintf(w, "│  Flags           0x%08x\n", info.Flags)
	for _, line := range info.FlagDetails() {
		fmt.Fprintf(w, "│    %s\n", line)
	}

	fmt.Fprintf(w, "└───────────────────────────────────────────────────────\n")
}
