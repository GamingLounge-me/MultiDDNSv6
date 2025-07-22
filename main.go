package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

// Service represents a DNS update service provider
type Service struct {
	Name      string `json:"name"`
	UpdateURL string `json:"update_url"`
	AuthType  string `json:"auth_type,omitempty"`
	Username  string `json:"username"`
	Password  string `json:"password"`
}

// Domain represents a domain that needs DNS updates
type Domain struct {
	FQDN       string      `json:"fqdn"`
	IPv6Suffix string      `json:"ipv6suffix"`
	Services   interface{} `json:"services"` // Can be string, []string, or "all"
}

// Config represents the application configuration
type Config struct {
	Period   string    `json:"period"`
	Services []Service `json:"services"`
	Domains  []Domain  `json:"domain"`
}

// setupLogging configures standard logging
func setupLogging() error {
	// Use standard logging to stdout/stderr
	log.SetFlags(log.LstdFlags)
	log.Printf("MultiDDNSv6 logging initialized")
	return nil
}

// DynDNSClient manages DNS updates for multiple domains
type DynDNSClient struct {
	config        Config
	currentPrefix string
	httpClient    *http.Client
	checkInterval time.Duration
}

// NewDynDNSClient creates a new DynDNS client
func NewDynDNSClient(configPath string) (*DynDNSClient, error) {
	config, err := loadConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	// Parse check interval
	checkInterval, err := time.ParseDuration(config.Period)
	if err != nil {
		return nil, fmt.Errorf("invalid period format: %w", err)
	}

	// Setup logging
	err = setupLogging()
	if err != nil {
		return nil, fmt.Errorf("failed to setup logging: %w", err)
	}

	client := &DynDNSClient{
		config: config,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		checkInterval: checkInterval,
	}

	log.Printf("MultiDDNSv6 client initialized with config: %s", configPath)
	return client, nil
}

// loadConfig loads configuration from JSON file
func loadConfig(path string) (Config, error) {
	var config Config

	data, err := os.ReadFile(path)
	if err != nil {
		return config, err
	}

	err = json.Unmarshal(data, &config)
	if err != nil {
		return config, err
	}

	// Set default period if not specified
	if config.Period == "" {
		config.Period = "5m"
	}

	// Set default auth_type for services that don't have it
	for i := range config.Services {
		if config.Services[i].AuthType == "" {
			config.Services[i].AuthType = "http_basic"
		}
	}

	return config, nil
} // getIPv6Prefix detects the current IPv6 prefix
func (c *DynDNSClient) getIPv6Prefix() (string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("failed to get interfaces: %w", err)
	}

	for _, iface := range interfaces {
		// Skip loopback and down interfaces
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				ip := ipnet.IP
				// Look for global unicast IPv6 addresses
				if ip.To4() == nil && ip.IsGlobalUnicast() && !ip.IsLinkLocalUnicast() {
					// Extract the /64 prefix
					prefix := ip.Mask(net.CIDRMask(64, 128))
					return prefix.String(), nil
				}
			}
		}
	}

	return "", fmt.Errorf("no suitable IPv6 address found")
}

// buildIPv6Address combines prefix and suffix to create full IPv6 address
func (c *DynDNSClient) buildIPv6Address(prefix, suffix string) (string, error) {
	prefixIP := net.ParseIP(prefix)
	if prefixIP == nil {
		return "", fmt.Errorf("invalid prefix: %s", prefix)
	}

	suffixIP := net.ParseIP(suffix)
	if suffixIP == nil {
		return "", fmt.Errorf("invalid suffix: %s", suffix)
	}

	// Combine prefix (first 64 bits) with suffix (last 64 bits)
	result := make(net.IP, 16)
	copy(result[:8], prefixIP[:8])
	copy(result[8:], suffixIP[8:])

	return result.String(), nil
}

// getServicesForDomain returns the list of service names for a domain
func (c *DynDNSClient) getServicesForDomain(domain Domain) []string {
	switch services := domain.Services.(type) {
	case string:
		if services == "all" {
			var allServices []string
			for _, service := range c.config.Services {
				allServices = append(allServices, service.Name)
			}
			return allServices
		}
		return []string{services}
	case []interface{}:
		var serviceNames []string
		for _, service := range services {
			if serviceName, ok := service.(string); ok {
				serviceNames = append(serviceNames, serviceName)
			}
		}
		return serviceNames
	default:
		return []string{}
	}
}

// findServiceByName finds a service by name
func (c *DynDNSClient) findServiceByName(name string) *Service {
	for i := range c.config.Services {
		if c.config.Services[i].Name == name {
			return &c.config.Services[i]
		}
	}
	return nil
}

// updateDNS sends DNS update request for a domain using a specific service
func (c *DynDNSClient) updateDNS(domain Domain, service Service, ipv6 string) error {
	// Replace placeholders in update URL
	url := strings.ReplaceAll(service.UpdateURL, "<fqdn>", domain.FQDN)
	url = strings.ReplaceAll(url, "<ipv6>", ipv6)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Add basic authentication (default and only supported type)
	if service.AuthType == "http_basic" || service.AuthType == "" {
		auth := base64.StdEncoding.EncodeToString([]byte(service.Username + ":" + service.Password))
		req.Header.Add("Authorization", "Basic "+auth)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("DNS update failed with status %d: %s", resp.StatusCode, string(body))
	}

	log.Printf("Successfully updated DNS for %s via %s -> %s", domain.FQDN, service.Name, ipv6)
	return nil
}

// checkAndUpdate checks for IP changes and updates DNS if necessary
func (c *DynDNSClient) checkAndUpdate() error {
	prefix, err := c.getIPv6Prefix()
	if err != nil {
		return fmt.Errorf("failed to get IPv6 prefix: %w", err)
	}

	// Check if prefix has changed
	if prefix == c.currentPrefix {
		log.Printf("IPv6 prefix unchanged: %s", prefix)
		return nil
	}

	// Log prefix change (avoid logging on first run when currentPrefix is empty)
	if c.currentPrefix == "" {
		log.Printf("Initial IPv6 prefix detected: %s", prefix)
	} else {
		log.Printf("IPv6 prefix changed from %s to %s", c.currentPrefix, prefix)
	}
	c.currentPrefix = prefix

	// Update DNS for all domains
	for _, domain := range c.config.Domains {
		ipv6, err := c.buildIPv6Address(prefix, domain.IPv6Suffix)
		if err != nil {
			log.Printf("Failed to build IPv6 for domain %s: %v", domain.FQDN, err)
			continue
		}

		// Get services for this domain
		serviceNames := c.getServicesForDomain(domain)

		// Update DNS for each service
		for _, serviceName := range serviceNames {
			service := c.findServiceByName(serviceName)
			if service == nil {
				log.Printf("Service '%s' not found for domain %s", serviceName, domain.FQDN)
				continue
			}

			err = c.updateDNS(domain, *service, ipv6)
			if err != nil {
				log.Printf("DNS update failed for %s via %s: %v", domain.FQDN, serviceName, err)
			}
		}
	}

	return nil
}

// Run starts the MultiDDNSv6 client monitoring loop
func (c *DynDNSClient) Run() {
	log.Printf("Starting MultiDDNSv6 client with %d domains and %d services", len(c.config.Domains), len(c.config.Services))
	log.Printf("Check interval: %v", c.checkInterval)

	// Initial check
	err := c.checkAndUpdate()
	if err != nil {
		log.Printf("Initial check failed: %v", err)
	}

	// Set up periodic checks
	ticker := time.NewTicker(c.checkInterval)
	defer ticker.Stop()

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	for {
		select {
		case <-ticker.C:
			err := c.checkAndUpdate()
			if err != nil {
				log.Printf("Check failed: %v", err)
			}
		case sig := <-sigChan:
			log.Printf("Received signal %v, shutting down gracefully...", sig)
			return
		}
	}
}

func main() {
	configPath := "config.json"
	if len(os.Args) > 1 {
		configPath = os.Args[1]
	}

	client, err := NewDynDNSClient(configPath)
	if err != nil {
		log.Fatalf("Failed to create DynDNS client: %v", err)
	}

	client.Run()
}
