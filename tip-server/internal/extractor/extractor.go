package extractor

import (
	"net"
	"regexp"
	"strings"
	"sync"

	"tip-server/internal/models"
)

// Extractor holds pre-compiled regex patterns for IOC extraction
type Extractor struct {
	patterns map[models.IOCType]*regexp.Regexp
	mu       sync.RWMutex
}

// Pre-compiled regex patterns for each IOC type
var (
	// IPv4 pattern - matches standard dotted decimal notation
	ipv4Pattern = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`)

	// IPv6 patterns - full form and compressed forms
	ipv6FullPattern = regexp.MustCompile(`\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b`)
	ipv6CompressedPattern = regexp.MustCompile(`\b(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}|:(?::[0-9a-fA-F]{1,4}){1,7}|::(?:[fF]{4}:)?(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`)

	// MD5 - 32 hex characters
	md5Pattern = regexp.MustCompile(`\b[a-fA-F0-9]{32}\b`)

	// SHA1 - 40 hex characters
	sha1Pattern = regexp.MustCompile(`\b[a-fA-F0-9]{40}\b`)

	// SHA256 - 64 hex characters
	sha256Pattern = regexp.MustCompile(`\b[a-fA-F0-9]{64}\b`)

	// Domain - matches domain names with TLDs
	domainPattern = regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|edu|gov|mil|int|info|biz|name|pro|aero|coop|museum|[a-z]{2})\b`)

	// URL - HTTP/HTTPS URLs
	urlPattern = regexp.MustCompile(`(?i)\bhttps?://[^\s<>"'\x60{}\[\]|\\^]+`)

	// Email - standard email format
	emailPattern = regexp.MustCompile(`(?i)\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b`)
)

// Common false positives to filter out
var (
	// Private/reserved IP ranges to potentially filter
	privateIPv4Ranges = []string{
		"10.",
		"172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
		"172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
		"192.168.",
		"127.",
		"0.",
	}

	// Common false positive domains
	falsePositiveDomains = map[string]bool{
		"example.com":     true,
		"example.org":     true,
		"example.net":     true,
		"localhost.local": true,
		"test.com":        true,
		"domain.com":      true,
	}

	// File extension patterns that might be false positives for hashes
	hashFalsePositivePatterns = []string{
		"ffffffffffffffffffffffffffffffff", // All f's
		"00000000000000000000000000000000", // All 0's
	}
)

// NewExtractor creates a new IOC extractor with pre-compiled patterns
func NewExtractor() *Extractor {
	return &Extractor{
		patterns: map[models.IOCType]*regexp.Regexp{
			models.IOCTypeIPv4:   ipv4Pattern,
			models.IOCTypeMD5:    md5Pattern,
			models.IOCTypeSHA1:   sha1Pattern,
			models.IOCTypeSHA256: sha256Pattern,
			models.IOCTypeDomain: domainPattern,
			models.IOCTypeURL:    urlPattern,
			models.IOCTypeEmail:  emailPattern,
		},
	}
}

// Scan extracts all IOCs from content
// Returns a map where key is IOC type and value is a deduplicated list of matches
func (e *Extractor) Scan(content []byte) (map[models.IOCType][]string, error) {
	results := make(map[models.IOCType][]string)
	contentStr := string(content)

	// Extract each IOC type
	results[models.IOCTypeIPv4] = e.extractIPv4(contentStr)
	results[models.IOCTypeIPv6] = e.extractIPv6(contentStr)
	results[models.IOCTypeMD5] = e.extractMD5(contentStr)
	results[models.IOCTypeSHA1] = e.extractSHA1(contentStr)
	results[models.IOCTypeSHA256] = e.extractSHA256(contentStr)
	results[models.IOCTypeDomain] = e.extractDomains(contentStr)
	results[models.IOCTypeURL] = e.extractURLs(contentStr)
	results[models.IOCTypeEmail] = e.extractEmails(contentStr)

	// Remove empty results
	for k, v := range results {
		if len(v) == 0 {
			delete(results, k)
		}
	}

	return results, nil
}

// ScanWithOptions extracts IOCs with filtering options
func (e *Extractor) ScanWithOptions(content []byte, opts ExtractOptions) (map[models.IOCType][]string, error) {
	results, err := e.Scan(content)
	if err != nil {
		return nil, err
	}

	// Apply filters based on options
	if opts.ExcludePrivateIPs {
		results[models.IOCTypeIPv4] = filterPrivateIPs(results[models.IOCTypeIPv4])
	}

	if opts.ExcludeFalsePositiveDomains {
		results[models.IOCTypeDomain] = filterFalsePositiveDomains(results[models.IOCTypeDomain])
	}

	return results, nil
}

// ExtractOptions allows customization of extraction behavior
type ExtractOptions struct {
	ExcludePrivateIPs           bool
	ExcludeFalsePositiveDomains bool
	Types                       []models.IOCType // If set, only extract these types
}

// ========== Individual Extractors ==========

func (e *Extractor) extractIPv4(content string) []string {
	matches := ipv4Pattern.FindAllString(content, -1)
	return deduplicate(validateIPv4s(matches))
}

func (e *Extractor) extractIPv6(content string) []string {
	var matches []string

	// Extract full form IPv6
	fullMatches := ipv6FullPattern.FindAllString(content, -1)
	matches = append(matches, fullMatches...)

	// Extract compressed form IPv6
	compressedMatches := ipv6CompressedPattern.FindAllString(content, -1)
	matches = append(matches, compressedMatches...)

	return deduplicate(validateIPv6s(matches))
}

func (e *Extractor) extractMD5(content string) []string {
	matches := md5Pattern.FindAllString(content, -1)
	// Filter out matches that are actually SHA1 or SHA256 substrings
	// Also filter false positives
	filtered := filterHashFalsePositives(matches)
	return deduplicate(toLower(filtered))
}

func (e *Extractor) extractSHA1(content string) []string {
	matches := sha1Pattern.FindAllString(content, -1)
	// Filter out matches that are actually SHA256 substrings
	filtered := filterHashFalsePositives(matches)
	return deduplicate(toLower(filtered))
}

func (e *Extractor) extractSHA256(content string) []string {
	matches := sha256Pattern.FindAllString(content, -1)
	filtered := filterHashFalsePositives(matches)
	return deduplicate(toLower(filtered))
}

func (e *Extractor) extractDomains(content string) []string {
	matches := domainPattern.FindAllString(content, -1)
	return deduplicate(toLower(matches))
}

func (e *Extractor) extractURLs(content string) []string {
	matches := urlPattern.FindAllString(content, -1)
	// Clean up URLs (remove trailing punctuation)
	cleaned := make([]string, 0, len(matches))
	for _, u := range matches {
		u = strings.TrimRight(u, ".,;:!?)")
		cleaned = append(cleaned, u)
	}
	return deduplicate(cleaned)
}

func (e *Extractor) extractEmails(content string) []string {
	matches := emailPattern.FindAllString(content, -1)
	return deduplicate(toLower(matches))
}

// ========== Helper Functions ==========

// deduplicate removes duplicate strings from a slice
func deduplicate(items []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(items))

	for _, item := range items {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}

	return result
}

// toLower converts all strings to lowercase
func toLower(items []string) []string {
	result := make([]string, len(items))
	for i, item := range items {
		result[i] = strings.ToLower(item)
	}
	return result
}

// validateIPv4s filters out invalid IPv4 addresses
func validateIPv4s(ips []string) []string {
	valid := make([]string, 0, len(ips))
	for _, ip := range ips {
		if net.ParseIP(ip) != nil {
			valid = append(valid, ip)
		}
	}
	return valid
}

// validateIPv6s filters out invalid IPv6 addresses
func validateIPv6s(ips []string) []string {
	valid := make([]string, 0, len(ips))
	for _, ip := range ips {
		parsed := net.ParseIP(ip)
		if parsed != nil && parsed.To4() == nil { // Ensure it's actually IPv6, not IPv4
			valid = append(valid, ip)
		}
	}
	return valid
}

// filterPrivateIPs removes private/reserved IPv4 addresses
func filterPrivateIPs(ips []string) []string {
	public := make([]string, 0, len(ips))
	for _, ip := range ips {
		isPrivate := false
		for _, prefix := range privateIPv4Ranges {
			if strings.HasPrefix(ip, prefix) {
				isPrivate = true
				break
			}
		}
		if !isPrivate {
			public = append(public, ip)
		}
	}
	return public
}

// filterFalsePositiveDomains removes known false positive domains
func filterFalsePositiveDomains(domains []string) []string {
	filtered := make([]string, 0, len(domains))
	for _, d := range domains {
		if !falsePositiveDomains[strings.ToLower(d)] {
			filtered = append(filtered, d)
		}
	}
	return filtered
}

// filterHashFalsePositives removes known false positive hash patterns
func filterHashFalsePositives(hashes []string) []string {
	filtered := make([]string, 0, len(hashes))
	for _, h := range hashes {
		lower := strings.ToLower(h)
		isFalsePositive := false
		for _, fp := range hashFalsePositivePatterns {
			if strings.HasPrefix(lower, fp[:len(lower)]) || lower == fp[:len(lower)] {
				isFalsePositive = true
				break
			}
		}
		if !isFalsePositive {
			filtered = append(filtered, h)
		}
	}
	return filtered
}

// CountIOCs counts total IOCs from a scan result
func CountIOCs(results map[models.IOCType][]string) int {
	count := 0
	for _, iocs := range results {
		count += len(iocs)
	}
	return count
}

// FlattenIOCs converts scan results to a flat list of IOC structs
func FlattenIOCs(results map[models.IOCType][]string, sourceFileID string) []models.IOC {
	var iocs []models.IOC

	for iocType, values := range results {
		for _, value := range values {
			iocs = append(iocs, models.IOC{
				Value:        value,
				Type:         iocType,
				SourceFileID: sourceFileID,
			})
		}
	}

	return iocs
}
