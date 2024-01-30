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

	"github.com/miekg/dns"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
)

// TODO lower TTL on all requests, becaus allowed request gets TTL from upstream ?
// TODO only handle A
// TODO add TLS certs??
// TODO IPV6 ? AAAA queries?
// TODO use env vars

// Define log to be a logger with the plugin name in it. This way we can just use log.Info etc.
var log = clog.NewWithPlugin("shield_policy")

type ShieldPolicyPlugin struct {
	Next plugin.Handler
}

var BLOCK_IP net.IP

// init registers this plugin.
func init() {
	plugin.Register("shield_policy", setup)
	block_address := getEnv("BLOCKADDRESS", "129.159.157.83")
	BLOCK_IP = net.ParseIP(block_address).To4()
}

// setup is the function that gets called when the config parser see the token "shield_policy". Setup is responsible
// for parsing any extra options the example plugin may have. The first token this function sees is "example".
func setup(c *caddy.Controller) error {
	c.Next() // Ignore "example" and give us the next token.
	if c.NextArg() {
		// If there was another token, return an error, because we don't have any configuration.
		// Any errors returned from this setup function should be wrapped with plugin.Error, so we
		// can present a slightly nicer error message to the user.
		return plugin.Error("shield_policy", c.ArgErr())
	}

	// Add the Plugin to CoreDNS, so Servers can use it in their plugin chain.
	config := dnsserver.GetConfig(c)
	config.HTTPRequestValidateFunc = func(r *http.Request) bool {
		return r.URL.Path == "/" || r.URL.Path == "/dns-query"
	}

	config.AddPlugin(func(next plugin.Handler) plugin.Handler {
		return ShieldPolicyPlugin{Next: next}
	})

	// All OK, return a nil error.
	return nil
}

// ServeDNS implements the plugin.Handler interface
func (e ShieldPolicyPlugin) ServeDNS(ctx context.Context, writer dns.ResponseWriter, query *dns.Msg) (int, error) {
	// Debug log that we've have seen the query. This will only be shown when the debug plugin is loaded.
	// log.Debug("Received query\n")

	state := request.Request{W: writer, Req: query}

	if state.QType() != dns.TypeA {
		return plugin.NextOrFailure(e.Name(), e.Next, ctx, writer, query)
	}

	// TODO how to get tenant id?
	// TODO req policy manager

	domain := strings.Trim(query.Question[0].Name, ".") // TODO might panic if nil
	source := state.IP()
	request := ctx.Value(dnsserver.HTTPRequestKey{}).(*http.Request)

	if request == nil { // TODO this request is not over HTTP, what do?
		return plugin.NextOrFailure(e.Name(), e.Next, ctx, writer, query)
	}

	// TODO also try :authority header ? I think go deals with it by itself
	tenantId := strings.Split(strings.Split(request.Host, ":")[0], ".")[0]

	accessPolicy := queryPolicy(domain, tenantId)
	// accessPolicy := queryPolicyGRPC(domain, tenantId)
	// accessPolicy := 1

	// TODO don't use %v everywhere ?
	log.Info(fmt.Sprintf("domain: %v source: %v tenantId: %v policy: %v  \n", domain, source, tenantId, accessPolicy))

	switch accessPolicy {
	case 0: // shield  // TODO use redirector
		return plugin.NextOrFailure(e.Name(), e.Next, ctx, writer, query)
	case 2: // deny
		m := new(dns.Msg)
		m.SetReply(state.Req)
		switch state.QType() {
		case dns.TypeA:
			hdr := dns.RR_Header{Name: state.QName(), Ttl: 10, Class: dns.ClassINET, Rrtype: dns.TypeA}
			m.Answer = []dns.RR{&dns.A{Hdr: hdr, A: BLOCK_IP}} // TODO get block address from env var
			// case dns.TypeAAAA:
			// 	hdr := dns.RR_Header{Name: state.QName(), Ttl: 0, Class: dns.ClassINET, Rrtype: dns.TypeAAAA}
			// 	m.Answer = []dns.RR{&dns.AAAA{Hdr: hdr, AAAA: net.ParseIP("::1")}}
			// default:
			// 	// nodata
			// 	m.Ns = soaFromOrigin(state.QName())
		}
		writer.WriteMsg(m)
		return 0, nil
	}
	// any other case we just allow

	// Call next plugin (if any).
	return plugin.NextOrFailure(e.Name(), e.Next, ctx, writer, query)
}

// Name implements the Handler interface.
func (e ShieldPolicyPlugin) Name() string { return "shield_policy" }
