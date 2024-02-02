package shield_policy

import "go.uber.org/zap"

// make sure to also change the log fn call when changing fields
type ReportData struct {
	TenantID    string `json:"logSystemID"`
	Errors      string `json:"Errors"`
	Domain      string `json:"Domain"`
	Policy      string `json:"Policy"`
	Query       string `json:"DNS Request Query"`
	Response    string `json:"DNS Response"`
	UserAgent   string `json:"User-Agent"`
	Category    string `json:"Category"`
	SubCategory string `json:"Sub Category"`
	RuleHits    string `json:"Rule hits"`
	DoH         bool   `json:"DoH"`
}

// implements Loggable
func (r *ReportData) LogFields() []zap.Field {
	return []zap.Field{
		zap.String("logSystemID", r.TenantID),
		zap.String("Errors", r.Errors),
		zap.String("Domain", r.Domain),
		zap.String("Policy", r.Policy),
		zap.String("DNS Request Query", r.Query),
		zap.String("DNS Response", r.Response),
		zap.String("User-Agent", r.UserAgent),
		zap.String("Category", r.Category),
		zap.String("Sub Category", r.SubCategory),
		zap.String("Rule hits", r.RuleHits),
		zap.Bool("DoH", r.DoH),
	}
}
