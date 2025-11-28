package domain

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"domain-scanner/internal/types"
	"github.com/likexian/whois"
)

var (
	// Pre-initialized maps for O(1) lookup
	availableIndicatorsMap   map[string]bool
	unavailableIndicatorsMap map[string]bool
	indicatorsOnce           sync.Once

	// Global config reference
	globalConfig *types.Config

	// Special status tracking
	specialStatusDomains []types.SpecialStatusDomain
	specialStatusMutex   sync.Mutex

	// Global WHOIS rate limiter - limits concurrent WHOIS queries to avoid overwhelming the server
	whoisSemaphore chan struct{}
	whoisOnce      sync.Once

	// WHOIS indicators for domain status detection
	registeredIndicators = []string{
		"registrar:",
		"registrant:",
		"creation date:",
		"created:",
		"updated date:",
		"updated:",
		"expiration date:",
		"expires:",
		"name server:",
		"nserver:",
		"nameserver:",
		"status: active",
		"status: client",
		"status: ok",
		"status: locked",
		"status: connect",  // Connect status indicates registered domain
		"status:connect",   // Version without space
		"domain name:",
		"domain:",
		"nsentry:",         // DENIC specific field
		"changed:",         // DENIC specific field
	}

	reservedIndicators = []string{
		"status: reserved",
		"status: restricted",
		"status: blocked",
		"status: prohibited",
		"status: reserved for registry",
		"status: reserved for registrar",
		"status: reserved for registry operator",
		"status: reserved for future use",
		"status: not available for registration",
		"status: not available for general registration",
		"status: reserved for special purposes",
		"status: reserved for government use",
		"status: reserved for educational institutions",
		"status: reserved for non-profit organizations",
		"domain reserved",
		"this domain is reserved",
		"reserved domain",
	}

	// WHOIS indicators for domain availability detection
	availableIndicators = []string{
		"no match for", "not found", "no data found", "no entries found",
		"domain not found", "no object found", "no matching record",
		"status: free", "status: available", "available for registration",
		"this domain is available", "domain is available", "domain available",
	}

	unavailableIndicators = []string{
		"registrar:", "registrant:", "creation date:", "updated date:",
		"expiration date:", "name server:", "nserver:", "status: registered",
		"status: active", "status: ok", "status: connect", "status:connect",
		"domain name:", "domain:", "nsentry:", "changed:",
	}
)

// SetConfig sets the global configuration for the domain checker
func SetConfig(config *types.Config) {
	globalConfig = config
	initWhoisSemaphore()
}

// initWhoisSemaphore initializes the global WHOIS semaphore for rate limiting
func initWhoisSemaphore() {
	whoisOnce.Do(func() {
		// Limit to 3 concurrent WHOIS queries to avoid overwhelming servers
		// Especially important for strict registries like .eu (EURid)
		maxConcurrentWhois := 3
		whoisSemaphore = make(chan struct{}, maxConcurrentWhois)
		fmt.Printf("[WHOIS] Initialized with max %d concurrent queries\n", maxConcurrentWhois)
	})
}

// initIndicatorMaps initializes the indicator maps for fast lookup
func initIndicatorMaps() {
	indicatorsOnce.Do(func() {
		// Initialize available indicators map
		availableIndicatorsMap = make(map[string]bool, len(availableIndicators))
		for _, indicator := range availableIndicators {
			availableIndicatorsMap[indicator] = true
		}

		// Initialize unavailable indicators map
		unavailableIndicatorsMap = make(map[string]bool, len(unavailableIndicators))
		for _, indicator := range unavailableIndicators {
			unavailableIndicatorsMap[indicator] = true
		}
	})
}

// CheckDomainSignatures checks various signatures to determine domain status
// This function now only checks DNS and SSL, WHOIS is handled by CheckDomainAvailability
func CheckDomainSignatures(domain string) ([]string, error) {
    var signatures []string

	// 1. Check DNS records (if enabled)
	if globalConfig == nil || globalConfig.Scanner.Methods.DNSCheck {
		dnsSignatures, err := checkDNSRecords(domain)
		if err == nil {
			signatures = append(signatures, dnsSignatures...)
		}
	}

	// 2. Check SSL certificate with timeout (if enabled)
	if globalConfig == nil || globalConfig.Scanner.Methods.SSLCheck {
		conn, err := tls.DialWithDialer(&net.Dialer{
			Timeout: 5 * time.Second,
		}, "tcp", domain+":443", &tls.Config{
			InsecureSkipVerify: true,
		})
		if err == nil {
			defer func() {
				_ = conn.Close()
			}()
			state := conn.ConnectionState()
			if len(state.PeerCertificates) > 0 {
				signatures = append(signatures, "SSL")
			}
		}
	}

	// Note: WHOIS checking is now only done in CheckDomainAvailability to avoid duplicate queries
	return signatures, nil
}

// min returns the smaller of two integers
func min(a, b int) int {
    if a < b {
        return a
    }
    return b
}

// whoisQueryWithTimeout executes a WHOIS lookup with a hard timeout to avoid rare hangs
// Uses context for proper goroutine cancellation to prevent goroutine leaks
func whoisQueryWithTimeout(domain string, timeout time.Duration) (string, error) {
	// Ensure semaphore is initialized
	if whoisSemaphore == nil {
		initWhoisSemaphore()
	}

	// Acquire semaphore to limit concurrent WHOIS queries
	select {
	case whoisSemaphore <- struct{}{}:
		// Got the semaphore
		defer func() { <-whoisSemaphore }() // Release when done
	case <-time.After(5 * time.Second):
		// Waited too long for semaphore, likely a deadlock or resource exhaustion
		return "", fmt.Errorf("whois semaphore timeout")
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	type resp struct {
		data string
		err  error
	}
	ch := make(chan resp, 1)

	go func() {
		result, err := whois.Whois(domain)
		select {
		case ch <- resp{data: result, err: err}:
		case <-ctx.Done():
			// Context cancelled, clean up and exit
			return
		}
	}()

	select {
	case r := <-ch:
		return r.data, r.err
	case <-ctx.Done():
		// Timeout occurred - the goroutine will exit when it completes
		return "", fmt.Errorf("whois timeout after %v", timeout)
	}
}

// checkDNSRecords checks various DNS records for the domain
func checkDNSRecords(domain string) ([]string, error) {
	var signatures []string

	// 1. Check DNS NS records
	nsRecords, err := net.LookupNS(domain)
	if err == nil && len(nsRecords) > 0 {
		signatures = append(signatures, "DNS_NS")
	}

	// 2. Check DNS A records
	ipRecords, err := net.LookupIP(domain)
	if err == nil && len(ipRecords) > 0 {
		signatures = append(signatures, "DNS_A")
	}

	// 3. Check DNS MX records
	mxRecords, err := net.LookupMX(domain)
	if err == nil && len(mxRecords) > 0 {
		signatures = append(signatures, "DNS_MX")
	}

	// 4. Check DNS TXT records
	txtRecords, err := net.LookupTXT(domain)
	if err == nil && len(txtRecords) > 0 {
		signatures = append(signatures, "DNS_TXT")
	}

	// 5. Check DNS CNAME records
	cnameRecord, err := net.LookupCNAME(domain)
	if err == nil && cnameRecord != "" && cnameRecord != domain+"." {
		signatures = append(signatures, "DNS_CNAME")
	}

	return signatures, nil
}

// CheckDomainAvailability checks if a domain is available for registration
func CheckDomainAvailability(domain string) (bool, error) {
	signatures, err := CheckDomainSignatures(domain)
	if err != nil {
		return false, err
	}

	// Check if we have any registration signatures
	hasRegistrationSignatures := false
	hasDNSSignatures := false

	for _, sig := range signatures {
		if sig == "DNS_NS" || sig == "DNS_A" || sig == "DNS_MX" || sig == "DNS_TXT" || sig == "DNS_CNAME" {
			hasDNSSignatures = true
			hasRegistrationSignatures = true
		} else if sig == "SSL" {
			hasRegistrationSignatures = true
		}
	}

	// If we have clear registration signatures, domain is registered
	if hasRegistrationSignatures {
		return false, nil
	}

	// Now perform WHOIS check as final verification
	// Skip WHOIS if explicitly disabled in config
	if globalConfig != nil && !globalConfig.Scanner.Methods.WHOISCheck {
		// No signatures and WHOIS disabled - assume available
		return true, nil
	}

	// WHOIS check with retry logic
	maxRetries := 3  // Reduced from 5 to avoid excessive retries
	baseDelay := 2 * time.Second
	perAttemptTimeout := 10 * time.Second

	for i := 0; i < maxRetries; i++ {
		result, err := whoisQueryWithTimeout(domain, perAttemptTimeout)
		if err == nil {
			// Convert WHOIS response to lowercase for case-insensitive matching
			result = strings.ToLower(result)

			// Check for access control errors in WHOIS response
			isRateLimitResponse := strings.Contains(result, "connection refused") ||
								   strings.Contains(result, "access control") ||
								   strings.Contains(result, "limit exceeded") ||
								   strings.Contains(result, "rate limit") ||
								   strings.Contains(result, "too many requests")

			if isRateLimitResponse {
				// If this is not the last attempt, wait and retry
				if i < maxRetries-1 {
					waitTime := baseDelay * time.Duration(1<<uint(i+1)) // Exponential backoff: 4s, 8s
					time.Sleep(waitTime)
					continue // Retry the WHOIS query
				} else {
					// Last attempt failed, handle specially
					return handleRateLimitedDomain(domain, hasDNSSignatures)
				}
			}

			// First, check for special cases that should NOT be treated as generally available
			// Identity Digital Dropzone: special application phase, not general reg
			if strings.Contains(result, "dropzone") ||
			   strings.Contains(result, "available for application via the identity digital dropzone service") {
				addToSpecialStatus(domain, "DROPZONE_AVAILABLE")
				return false, nil
			}
			// Premium names (various registries)
			if strings.Contains(result, "premium name") ||
			   strings.Contains(result, "premium domain") ||
			   strings.Contains(result, "premium") {
				addToSpecialStatus(domain, "PREMIUM")
				return false, nil
			}

			// Check for indicators that domain is definitely available
			for _, indicator := range availableIndicators {
				if strings.Contains(result, indicator) {
					return true, nil
				}
			}

			// Check for registration indicators
			enhancedRegisteredIndicators := []string{
				"registrar:",
				"registrant:",
				"creation date:",
				"created:",
				"updated date:",
				"updated:",
				"expiration date:",
				"expires:",
				"name server:",
				"nserver:",
				"nameserver:",
				"status: active",
				"status: client",
				"status: ok",
				"status: locked",
				"status: connect",  // Connect status indicates registered domain
				"status:connect",   // Version without space
				"domain name:",
				"domain:",
				"Status: connect",  // Uppercase version
				"nsentry:",         // DENIC specific field
				"changed:",         // DENIC specific field
			}

			for _, indicator := range enhancedRegisteredIndicators {
				if strings.Contains(result, indicator) {
					return false, nil
				}
			}

			// Check for special status indicators
			specialStatusIndicators := []string{
				"status: redemptionperiod",
				"status: redemption period",
				"status: redemption",
				"redemptionperiod",
				"redemption period",
				"status: pendingdelete",
				"status: pending delete",
				"status: hold",
				"status: inactive",
				"status: suspended",
				"status: reserved",
				"status: quarantined",
				"status: pending",
				"status: transfer",
				"status: grace",
				"status: autorenewperiod",
				"status: auto renew period",
				"status: expire",
				"status: expired",
				"status: clienthold",
				"status: client hold",
				"status: serverhold",
				"status: server hold",
			}

			for _, indicator := range specialStatusIndicators {
				if strings.Contains(result, indicator) {
					// Extract the status type for better tracking
					statusType := strings.TrimPrefix(indicator, "status: ")
					addToSpecialStatus(domain, strings.ToUpper(statusType))
					return false, nil
				}
			}

			// Successfully got WHOIS result, no need to retry
			break
		} else {
			// WHOIS query error
			errorStr := strings.ToLower(err.Error())
			isRateLimit := strings.Contains(errorStr, "connection refused") ||
						  strings.Contains(errorStr, "access control") ||
						  strings.Contains(errorStr, "limit exceeded") ||
						  strings.Contains(errorStr, "rate limit") ||
						  strings.Contains(errorStr, "too many requests") ||
						  strings.Contains(errorStr, "whois timeout") ||
						  strings.Contains(errorStr, "semaphore timeout")

			if isRateLimit {
				// If this is the last attempt, handle specially
				if i == maxRetries-1 {
					// Mark domain for special handling
					return handleRateLimitedDomain(domain, hasDNSSignatures)
				}

				// Use exponential backoff for rate limits: 4s, 8s
				waitTime := baseDelay * time.Duration(1<<uint(i+1))
				time.Sleep(waitTime)
			} else {
				// For other errors, use shorter delay
				if i < maxRetries-1 {
					waitTime := time.Duration(1+i) * time.Second
					time.Sleep(waitTime)
				}
			}
		}
	}

	// If we can't determine the status, assume available but with caution
	// This happens when WHOIS is inconclusive
	return true, nil
}

// handleRateLimitedDomain handles domains that couldn't be checked due to WHOIS rate limiting
func handleRateLimitedDomain(domain string, hasDNSSignatures bool) (bool, error) {
	// If we have DNS signatures, it's likely registered
	if hasDNSSignatures {
		return false, nil // Domain is registered
	}

	// No DNS signatures and WHOIS unavailable - this is uncertain
	// We'll add it to special status for manual review and NOT mark as available
	if globalConfig != nil {
		// Add to special status list for manual review
		addToSpecialStatus(domain, "WHOIS_RATE_LIMITED")
	}

	// Return as NOT available since we can't determine the status
	// The domain will be tracked in special status instead
	return false, nil
}

// addToSpecialStatus adds a domain to the special status tracking
func addToSpecialStatus(domain, reason string) {
    specialStatusMutex.Lock()
    defer specialStatusMutex.Unlock()

    // Deduplicate by domain+status to avoid duplicates from multiple detectors
    for _, existing := range specialStatusDomains {
        if existing.Domain == domain && strings.EqualFold(existing.Status, reason) {
            // Already recorded
            return
        }
    }

    specialStatusDomains = append(specialStatusDomains, types.SpecialStatusDomain{
        Domain: domain,
        Status: reason,
        Reason: fmt.Sprintf("WHOIS status: %s", reason),
    })

	// Also log for immediate visibility
	fmt.Printf("SPECIAL STATUS: %s - %s\n", domain, reason)
}

// GetSpecialStatusDomains returns all domains with special status
func GetSpecialStatusDomains() []types.SpecialStatusDomain {
	specialStatusMutex.Lock()
	defer specialStatusMutex.Unlock()

	// Return a copy to avoid race conditions
	result := make([]types.SpecialStatusDomain, len(specialStatusDomains))
	copy(result, specialStatusDomains)
	return result
}

// ClearSpecialStatusDomains clears the special status domains list
func ClearSpecialStatusDomains() {
    specialStatusMutex.Lock()
    defer specialStatusMutex.Unlock()
    specialStatusDomains = nil
}

// ReportSpecialStatus allows external packages to record a special status
func ReportSpecialStatus(domainName, reason string) {
    addToSpecialStatus(domainName, reason)
}
