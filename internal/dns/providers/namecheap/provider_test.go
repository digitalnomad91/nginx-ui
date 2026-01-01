package namecheap

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	dnsSvc "github.com/0xJacky/Nginx-UI/internal/dns"
	"github.com/stretchr/testify/require"
)

func TestSplitDomain(t *testing.T) {
	sld, tld, err := splitDomain("example.co.uk")
	require.NoError(t, err)
	require.Equal(t, "example", sld)
	require.Equal(t, "co.uk", tld)

	_, _, err = splitDomain("sub.example.com")
	require.Error(t, err)
}

func TestListRecords(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, commandGetHosts, r.URL.Query().Get("Command"))
		require.Equal(t, "example", r.URL.Query().Get("SLD"))
		require.Equal(t, "com", r.URL.Query().Get("TLD"))
		fmt.Fprint(w, `<ApiResponse Status="OK"><CommandResponse><DomainDNSGetHostsResult Domain="example.com"><host HostId="123" Name="@" Type="A" Address="1.1.1.1" TTL="60"/></DomainDNSGetHostsResult></CommandResponse></ApiResponse>`)
	}))
	t.Cleanup(server.Close)

	prov, err := newProvider(&dnsSvc.Credential{
		Values: map[string]string{
			"NAMECHEAP_API_USER":  "user",
			"NAMECHEAP_API_KEY":   "key",
			"NAMECHEAP_CLIENT_IP": "127.0.0.1",
			"NAMECHEAP_USERNAME":  "user",
		},
		Additional: map[string]string{
			"NAMECHEAP_API_ENDPOINT": server.URL,
		},
	})
	require.NoError(t, err)

	records, err := prov.ListRecords(context.Background(), "example.com", dnsSvc.RecordFilter{})
	require.NoError(t, err)
	require.Len(t, records, 1)
	require.Equal(t, "A", records[0].Type)
	require.Equal(t, "@", records[0].Name)
}

func TestCreateRecord(t *testing.T) {
	var setHostsCalled int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		command := r.URL.Query().Get("Command")
		switch command {
		case commandGetHosts:
			if setHostsCalled == 0 {
				fmt.Fprint(w, `<ApiResponse Status="OK"><CommandResponse><DomainDNSGetHostsResult Domain="example.com"></DomainDNSGetHostsResult></CommandResponse></ApiResponse>`)
			} else {
				fmt.Fprint(w, `<ApiResponse Status="OK"><CommandResponse><DomainDNSGetHostsResult Domain="example.com"><host HostId="456" Name="www" Type="A" Address="2.2.2.2" TTL="120"/></DomainDNSGetHostsResult></CommandResponse></ApiResponse>`)
			}
		case commandSetHosts:
			setHostsCalled++
			require.Equal(t, "example", r.URL.Query().Get("SLD"))
			require.Equal(t, "com", r.URL.Query().Get("TLD"))
			require.Equal(t, "www", r.URL.Query().Get("HostName1"))
			require.Equal(t, "A", r.URL.Query().Get("RecordType1"))
			require.Equal(t, "2.2.2.2", r.URL.Query().Get("Address1"))
			require.Equal(t, "120", r.URL.Query().Get("TTL1"))
			fmt.Fprint(w, `<ApiResponse Status="OK"><CommandResponse><DomainDNSSetHostsResult IsSuccess="true"/></CommandResponse></ApiResponse>`)
		default:
			t.Fatalf("unexpected command %s", command)
		}
	}))
	t.Cleanup(server.Close)

	prov, err := newProvider(&dnsSvc.Credential{
		Values: map[string]string{
			"NAMECHEAP_API_USER":  "user",
			"NAMECHEAP_API_KEY":   "key",
			"NAMECHEAP_CLIENT_IP": "127.0.0.1",
			"NAMECHEAP_USERNAME":  "user",
		},
		Additional: map[string]string{
			"NAMECHEAP_API_ENDPOINT": server.URL,
		},
	})
	require.NoError(t, err)

	record, err := prov.CreateRecord(context.Background(), "example.com", dnsSvc.RecordInput{
		Type:    "A",
		Name:    "www",
		Content: "2.2.2.2",
		TTL:     120,
	})
	require.NoError(t, err)
	require.Equal(t, "456", record.ID)
	require.Equal(t, "www", record.Name)
	require.Equal(t, "A", record.Type)
}
