package shield_policy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/coredns/coredns/plugin"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/request"
	"go.uber.org/zap"

	"github.com/miekg/dns"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin/shield_policy/logs"
	ratelimit "github.com/coredns/coredns/plugin/shield_policy/ratelimit"
)

type DohModeKey struct{}

// Define log to be a logger with the plugin name in it. This way we can just use log.Info etc.
var log = clog.NewWithPlugin("shield_policy")

type ShieldPolicyPlugin struct {
	Next plugin.Handler
}

var BLOCK_IP, REDIRECTOR_IP net.IP

var logger = logs.New()

// init registers this plugin.
func init() {
	plugin.Register("shield_policy", setup)

	blockAddr := getEnv("BLOCKADDRESS", "129.159.157.83") // TODO get from consul, move this to settings.go
	BLOCK_IP = net.ParseIP(blockAddr).To4()               // TODO might fail?
	redirectAddr := getEnv("REDIRECTORADDRESS", "")
	REDIRECTOR_IP = net.ParseIP(redirectAddr)

}

func setup(c *caddy.Controller) error {
	c.Next() // Ignore "example" and give us the next token.
	if c.NextArg() {
		// If there was another token, return an error, because we don't have any configuration.
		// Any errors returned from this setup function should be wrapped with plugin.Error, so we
		// can present a slightly nicer error message to the user.
		return plugin.Error("shield_policy", c.ArgErr())
	}

	WaitConfigReady()

	rateLimits := ratelimit.NewGroup()

	// Add the Plugin to CoreDNS, so Servers can use it in their plugin chain.
	config := dnsserver.GetConfig(c)

	config.HTTPRequestValidateFunc = func(req *http.Request) bool {
		if !(req.URL.Path == "/" || req.URL.Path == "/dns-query") {
			return false
		}
		tenantID := getReqTenantId(req)
		token := getReqBearerToken(req)

		mode := getDoHMode(tenantID, token)

		ctx := context.WithValue(req.Context(), DohModeKey{}, mode)
		*req = *req.WithContext(ctx)

		if mode == "None" {
			return false
		}

		rateLimitSettings := getRateLimit(tenantID)

		if rateLimitSettings.enabled {
			rateLimit := rateLimits.GetLimiterWithSettings(
				tenantID,
				float64(rateLimitSettings.requestsPerInterval)/float64(rateLimitSettings.intervalSeconds),
				rateLimitSettings.requestsPerInterval)

			return rateLimit.Allow()
		}

		return true

	}

	config.AddPlugin(func(next plugin.Handler) plugin.Handler {
		return ShieldPolicyPlugin{Next: next}
	})

	// All OK, return a nil error.
	return nil
}

// implements plugin.Handler
func (e ShieldPolicyPlugin) ServeDNS(ctx context.Context, writer dns.ResponseWriter, query *dns.Msg) (int, error) {
	state := request.Request{W: writer, Req: query}
	interceptingWriter := &ResponseWriter{writer, nil}

	continueRequest := func() (int, error) {
		return plugin.NextOrFailure(e.Name(), e.Next, ctx, interceptingWriter, query)
	}

	qType := state.QType()
	domain := strings.Trim(state.Name(), ".")

	reportData := &ReportData{
		Domain: domain,
		Query:  fmt.Sprintf("%s %s %s", state.Name(), state.Class(), state.Type()),
		DoH:    true,
	}

	if qType != dns.TypeA && qType != dns.TypeAAAA {
		return continueRequest()
	}

	req := ctx.Value(dnsserver.HTTPRequestKey{}).(*http.Request)
	if req == nil { // this request is not over HTTP, do not handle
		return continueRequest()
	}

	tenantId := getReqTenantId(req)
	reportData.TenantID = tenantId
	reportData.UserAgent = req.Header.Get("user-agent")

	defer logReport(reportData)
	defer addReportDnsResponse(reportData, interceptingWriter)

	policy, err := queryPolicy(logger, domain, tenantId)
	if err != nil {
		reportData.Errors = err.Error()
		return continueRequest() // TODO what should we do if policy fails?
	}

	reportData.Category = policy.CategoryGroupName
	reportData.SubCategory = policy.CategoryPrimaryName
	reportData.RuleHits = policy.MatchedOn

	accessPolicy := policy.Access

	switch accessPolicy {
	case 0: // shield
		if (req.Context().Value(DohModeKey{}) == "FilteringAndIsolation" && REDIRECTOR_IP != nil) {
			reportData.Policy = "Isolate"
			m := makeDnsResponse(state, REDIRECTOR_IP)
			interceptingWriter.WriteMsg(m)
			return 0, nil
		} else {
			reportData.Policy = "Allow"
			return continueRequest()
		}
	case 2: // deny
		reportData.Policy = "Deny"
		m := makeDnsResponse(state, BLOCK_IP)
		err := interceptingWriter.WriteMsg(m)
		if err != nil {
			logger.Error("error writing response", zap.Error(err))
			return 1, err // TODO what to return?
		}
		return 0, nil
	}

	reportData.Policy = "Allow"
	// any other case we just allow
	return continueRequest()
}

// Name implements the Handler interface.
func (e ShieldPolicyPlugin) Name() string { return "shield_policy" }

func getReqTenantId(req *http.Request) string {
	before, _, _ := strings.Cut(req.Host, ".")
	return before
}

func getReqBearerToken(req *http.Request) string {
	authorization := req.Header.Get("authorization")
	token, found := strings.CutPrefix(authorization, "Bearer ")
	if !found {
		return ""
	}
	return token
}

func makeDnsResponse(state request.Request, address net.IP) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(state.Req)
	switch state.QType() {
	case dns.TypeA:
		hdr := dns.RR_Header{Name: state.QName(), Ttl: 10, Class: dns.ClassINET, Rrtype: dns.TypeA}
		m.Answer = []dns.RR{&dns.A{Hdr: hdr, A: address}}
	case dns.TypeAAAA:
		hdr := dns.RR_Header{Name: state.QName(), Ttl: 0, Class: dns.ClassINET, Rrtype: dns.TypeAAAA}
		m.Answer = []dns.RR{&dns.AAAA{Hdr: hdr, AAAA: address.To16()}}
	}
	return m
}

func logReport(data *ReportData) {
	logger.ReportObject("", data)
}

func addReportDnsResponse(data *ReportData, writer *ResponseWriter) {
	res := writer.response

	if res == nil || len(res.Answer) == 0 || dns.NumField(res.Answer[0]) == 0 {
		return
	}
	data.Response = dns.Field(res.Answer[0], 1)
}
