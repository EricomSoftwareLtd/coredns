package shield_policy

import (
	"github.com/miekg/dns"
)

type ResponseWriter struct {
	dns.ResponseWriter
	response *dns.Msg
}

// WriteMsg implements the dns.ResponseWriter interface.
func (writer *ResponseWriter) WriteMsg(res *dns.Msg) error {
	writer.response = res
	return writer.ResponseWriter.WriteMsg(res)
}

// Write implements the dns.ResponseWriter interface.
func (writer *ResponseWriter) Write(buf []byte) (int, error) {
	return writer.ResponseWriter.Write(buf)
}
