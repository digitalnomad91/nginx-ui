package namecheap

import (
	"context"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"

	"github.com/0xJacky/Nginx-UI/internal/dns"
)

const (
	commandGetHosts = "namecheap.domains.dns.getHosts"
	commandSetHosts = "namecheap.domains.dns.setHosts"

	defaultBaseURL     = "https://api.namecheap.com/xml.response"
	sandboxBaseURL     = "https://api.sandbox.namecheap.com/xml.response"
	defaultHTTPTimeout = 60 * time.Second
)

type provider struct {
	apiUser    string
	apiKey     string
	userName   string
	clientIP   string
	baseURL    string
	httpClient *http.Client
}

func init() {
	dns.RegisterProvider("namecheap", newProvider)
}

func newProvider(cred *dns.Credential) (dns.Provider, error) {
	apiUser := firstNonEmpty(
		cred.Values["NAMECHEAP_API_USER"],
		cred.Values["NAMECHEAP_USERNAME"],
	)
	apiKey := strings.TrimSpace(cred.Values["NAMECHEAP_API_KEY"])
	clientIP := firstNonEmpty(
		cred.Values["NAMECHEAP_CLIENT_IP"],
		cred.Additional["NAMECHEAP_CLIENT_IP"],
	)

	if apiUser == "" || apiKey == "" {
		return nil, fmt.Errorf("namecheap: missing API user or API key")
	}
	if clientIP == "" {
		return nil, fmt.Errorf("namecheap: missing client ip")
	}

	userName := firstNonEmpty(
		cred.Values["NAMECHEAP_USERNAME"],
		cred.Additional["NAMECHEAP_USERNAME"],
		apiUser,
	)

	baseURL := defaultBaseURL
	if strings.EqualFold(strings.TrimSpace(cred.Additional["NAMECHEAP_SANDBOX"]), "true") {
		baseURL = sandboxBaseURL
	}
	if endpoint := strings.TrimSpace(cred.Additional["NAMECHEAP_API_ENDPOINT"]); endpoint != "" {
		baseURL = endpoint
	}

	timeout := parseTimeout(cred.Additional["NAMECHEAP_HTTP_TIMEOUT"])

	return &provider{
		apiUser:  apiUser,
		apiKey:   apiKey,
		userName: userName,
		clientIP: clientIP,
		baseURL:  baseURL,
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}, nil
}

func (p *provider) ListRecords(ctx context.Context, domain string, filter dns.RecordFilter) ([]dns.Record, error) {
	hosts, err := p.getHosts(ctx, domain)
	if err != nil {
		return nil, err
	}

	filterType := strings.ToUpper(strings.TrimSpace(filter.Type))
	filterName := strings.TrimSpace(filter.Name)
	if filterName != "" {
		filterName = normalizeHostName(filterName)
	}

	records := make([]dns.Record, 0, len(hosts))
	for _, host := range hosts {
		record := host.toRecord()
		if filterType != "" && !strings.EqualFold(record.Type, filterType) {
			continue
		}
		if filterName != "" && !strings.EqualFold(record.Name, filterName) {
			continue
		}
		records = append(records, record)
	}

	return records, nil
}

func (p *provider) CreateRecord(ctx context.Context, domain string, input dns.RecordInput) (dns.Record, error) {
	hosts, err := p.getHosts(ctx, domain)
	if err != nil {
		return dns.Record{}, err
	}

	hosts = append(hosts, newHostFromInput(input))

	if err := p.setHosts(ctx, domain, hosts); err != nil {
		return dns.Record{}, err
	}

	return p.findRecord(ctx, domain, "", input)
}

func (p *provider) UpdateRecord(ctx context.Context, domain string, recordID string, input dns.RecordInput) (dns.Record, error) {
	hosts, err := p.getHosts(ctx, domain)
	if err != nil {
		return dns.Record{}, err
	}

	updated := false
	for i, host := range hosts {
		if host.identifier() == recordID {
			hosts[i] = host.updateFromInput(input)
			updated = true
			break
		}
	}
	if !updated {
		return dns.Record{}, fmt.Errorf("namecheap: record %s not found", recordID)
	}

	if err := p.setHosts(ctx, domain, hosts); err != nil {
		return dns.Record{}, err
	}

	return p.findRecord(ctx, domain, recordID, input)
}

func (p *provider) DeleteRecord(ctx context.Context, domain string, recordID string) error {
	hosts, err := p.getHosts(ctx, domain)
	if err != nil {
		return err
	}

	filtered := hosts[:0]
	removed := false
	for _, host := range hosts {
		if host.identifier() == recordID {
			removed = true
			continue
		}
		filtered = append(filtered, host)
	}

	if !removed {
		return fmt.Errorf("namecheap: record %s not found", recordID)
	}

	return p.setHosts(ctx, domain, filtered)
}

func (p *provider) findRecord(ctx context.Context, domain string, recordID string, input dns.RecordInput) (dns.Record, error) {
	hosts, err := p.getHosts(ctx, domain)
	if err != nil {
		return dns.Record{}, err
	}

	if recordID != "" {
		if host, ok := findHostByID(hosts, recordID); ok {
			return host.toRecord(), nil
		}
	}

	name := normalizeHostName(input.Name)
	recordType := strings.ToUpper(strings.TrimSpace(input.Type))
	content := strings.TrimSpace(input.Content)

	for _, host := range hosts {
		if strings.EqualFold(host.Name, name) &&
			strings.EqualFold(host.Type, recordType) &&
			strings.EqualFold(host.Address, content) {
			return host.toRecord(), nil
		}
	}

	return dns.Record{}, fmt.Errorf("namecheap: record not found after update")
}

func (p *provider) getHosts(ctx context.Context, domain string) ([]hostRecord, error) {
	sld, tld, err := splitDomain(domain)
	if err != nil {
		return nil, err
	}

	params := url.Values{}
	params.Set("SLD", sld)
	params.Set("TLD", tld)

	var resp getHostsResponse
	if err := p.do(ctx, commandGetHosts, params, &resp); err != nil {
		return nil, err
	}

	return resp.CommandResponse.Result.Hosts, nil
}

func (p *provider) setHosts(ctx context.Context, domain string, hosts []hostRecord) error {
	sld, tld, err := splitDomain(domain)
	if err != nil {
		return err
	}

	params := url.Values{}
	params.Set("SLD", sld)
	params.Set("TLD", tld)

	for i, host := range hosts {
		index := strconv.Itoa(i + 1)
		params.Set("HostName"+index, normalizeHostName(host.Name))
		params.Set("RecordType"+index, strings.ToUpper(strings.TrimSpace(host.Type)))
		params.Set("Address"+index, strings.TrimSpace(host.Address))
		if host.TTL > 0 {
			params.Set("TTL"+index, strconv.Itoa(host.TTL))
		}
		if host.MXPref > 0 {
			params.Set("MXPref"+index, strconv.Itoa(host.MXPref))
		} else if host.Priority > 0 {
			params.Set("MXPref"+index, strconv.Itoa(host.Priority))
		}
		if host.Weight > 0 {
			params.Set("Weight"+index, strconv.Itoa(host.Weight))
		}
		if host.Port > 0 {
			params.Set("Port"+index, strconv.Itoa(host.Port))
		}
	}

	var resp setHostsResponse
	if err := p.do(ctx, commandSetHosts, params, &resp); err != nil {
		return err
	}

	if !resp.CommandResponse.Result.IsSuccess {
		return fmt.Errorf("namecheap: failed to update records")
	}

	return nil
}

func (p *provider) do(ctx context.Context, command string, params url.Values, out responseValidator) error {
	values := url.Values{
		"ApiUser":  {p.apiUser},
		"ApiKey":   {p.apiKey},
		"UserName": {p.userName},
		"ClientIp": {p.clientIP},
		"Command":  {command},
	}

	for k, v := range params {
		for _, item := range v {
			values.Add(k, item)
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.baseURL, nil)
	if err != nil {
		return fmt.Errorf("namecheap: build request: %w", err)
	}
	req.URL.RawQuery = values.Encode()

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("namecheap: request %s: %w", command, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= http.StatusBadRequest {
		return fmt.Errorf("namecheap: request %s failed with status %d", command, resp.StatusCode)
	}

	decoder := xml.NewDecoder(resp.Body)
	if err := decoder.Decode(out); err != nil {
		return fmt.Errorf("namecheap: parse response: %w", err)
	}

	return out.validate()
}

type responseValidator interface {
	validate() error
}

type baseResponse struct {
	Status string     `xml:"Status,attr"`
	Errors []apiError `xml:"Errors>Error"`
}

func (r baseResponse) validate() error {
	if len(r.Errors) > 0 {
		return fmt.Errorf("namecheap: %s", strings.Join(r.errorMessages(), "; "))
	}
	if strings.EqualFold(r.Status, "OK") {
		return nil
	}
	return fmt.Errorf("namecheap: unexpected status %s", r.Status)
}

func (r baseResponse) errorMessages() []string {
	msgs := make([]string, 0, len(r.Errors))
	for _, err := range r.Errors {
		msg := strings.TrimSpace(err.Message)
		if err.Number != "" {
			msg = fmt.Sprintf("%s: %s", err.Number, msg)
		}
		msgs = append(msgs, msg)
	}
	return msgs
}

type apiError struct {
	Number  string `xml:"Number,attr"`
	Message string `xml:",chardata"`
}

type getHostsResponse struct {
	XMLName xml.Name `xml:"ApiResponse"`
	baseResponse
	CommandResponse struct {
		Result hostsResult `xml:"DomainDNSGetHostsResult"`
	} `xml:"CommandResponse"`
}

func (r getHostsResponse) validate() error {
	return r.baseResponse.validate()
}

type setHostsResponse struct {
	XMLName xml.Name `xml:"ApiResponse"`
	baseResponse
	CommandResponse struct {
		Result setHostsResult `xml:"DomainDNSSetHostsResult"`
	} `xml:"CommandResponse"`
}

func (r setHostsResponse) validate() error {
	if err := r.baseResponse.validate(); err != nil {
		return err
	}
	if !r.CommandResponse.Result.IsSuccess {
		return fmt.Errorf("namecheap: failed to apply DNS changes")
	}
	return nil
}

type setHostsResult struct {
	IsSuccess bool `xml:"IsSuccess,attr"`
}

type hostsResult struct {
	Hosts []hostRecord `xml:"host"`
}

type hostRecord struct {
	RecordID string `xml:"RecordId,attr"`
	HostID   string `xml:"HostId,attr"`
	Name     string `xml:"Name,attr"`
	Type     string `xml:"Type,attr"`
	Address  string `xml:"Address,attr"`
	MXPref   int    `xml:"MXPref,attr"`
	TTL      int    `xml:"TTL,attr"`
	Priority int    `xml:"Priority,attr"`
	Weight   int    `xml:"Weight,attr"`
	Port     int    `xml:"Port,attr"`
}

func (h hostRecord) identifier() string {
	if h.RecordID != "" {
		return h.RecordID
	}
	return h.HostID
}

func (h hostRecord) toRecord() dns.Record {
	record := dns.Record{
		ID:      h.identifier(),
		Type:    strings.ToUpper(strings.TrimSpace(h.Type)),
		Name:    normalizeHostName(h.Name),
		Content: strings.TrimSpace(h.Address),
		TTL:     h.TTL,
	}
	if h.MXPref > 0 {
		value := h.MXPref
		record.Priority = &value
	}
	if h.Priority > 0 {
		value := h.Priority
		record.Priority = &value
	}
	if h.Weight > 0 {
		value := h.Weight
		record.Weight = &value
	}
	return record
}

func (h hostRecord) updateFromInput(input dns.RecordInput) hostRecord {
	h.Name = normalizeHostName(input.Name)
	h.Type = strings.ToUpper(strings.TrimSpace(input.Type))
	h.Address = strings.TrimSpace(input.Content)
	h.TTL = normalizeTTL(input.TTL)
	if input.Priority != nil {
		h.MXPref = max(*input.Priority, 0)
		h.Priority = max(*input.Priority, 0)
	}
	if input.Weight != nil {
		h.Weight = max(*input.Weight, 0)
	}
	return h
}

func newHostFromInput(input dns.RecordInput) hostRecord {
	host := hostRecord{
		Name:    normalizeHostName(input.Name),
		Type:    strings.ToUpper(strings.TrimSpace(input.Type)),
		Address: strings.TrimSpace(input.Content),
		TTL:     normalizeTTL(input.TTL),
	}
	if input.Priority != nil {
		host.MXPref = max(*input.Priority, 0)
		host.Priority = max(*input.Priority, 0)
	}
	if input.Weight != nil {
		host.Weight = max(*input.Weight, 0)
	}
	return host
}

func findHostByID(hosts []hostRecord, id string) (hostRecord, bool) {
	for _, host := range hosts {
		if host.identifier() == id {
			return host, true
		}
	}
	return hostRecord{}, false
}

func normalizeHostName(name string) string {
	name = strings.TrimSuffix(strings.TrimSpace(name), ".")
	if name == "" || name == "@" {
		return "@"
	}
	return name
}

func splitDomain(domain string) (string, string, error) {
	normalized := strings.Trim(strings.ToLower(domain), ".")
	if normalized == "" {
		return "", "", fmt.Errorf("namecheap: invalid domain")
	}

	etld1, err := publicsuffix.EffectiveTLDPlusOne(normalized)
	if err != nil {
		return "", "", fmt.Errorf("namecheap: parse domain %s: %w", normalized, err)
	}
	if !strings.EqualFold(etld1, normalized) {
		return "", "", fmt.Errorf("namecheap: domain must be apex, got %s", domain)
	}

	suffix, _ := publicsuffix.PublicSuffix(normalized)
	if suffix == "" || suffix == normalized {
		parts := strings.SplitN(normalized, ".", 2)
		if len(parts) != 2 {
			return "", "", fmt.Errorf("namecheap: invalid domain %s", domain)
		}
		return parts[0], parts[1], nil
	}

	sld := strings.TrimSuffix(etld1, "."+suffix)
	if sld == "" {
		return "", "", fmt.Errorf("namecheap: invalid domain %s", domain)
	}
	return sld, suffix, nil
}

func parseTimeout(value string) time.Duration {
	if strings.TrimSpace(value) == "" {
		return defaultHTTPTimeout
	}
	seconds, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || seconds <= 0 {
		return defaultHTTPTimeout
	}
	return time.Duration(seconds) * time.Second
}

func normalizeTTL(ttl int) int {
	if ttl <= 0 {
		return 60
	}
	return ttl
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
