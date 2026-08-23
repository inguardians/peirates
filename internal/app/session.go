package app

import "github.com/inguardians/peirates/internal/model"

// Session contains mutable state for one Peirates run. Capability packages
// receive only the fields or callbacks they need rather than depending on it.
type Session struct {
	Connection         model.ServerInfo
	ServiceAccounts    []model.ServiceAccount
	ClientCertificates []model.ClientCertificateKeyPair
	Pods               model.PodDetails
	Cloud              string
	Interactive        bool
	FullMenu           bool
	LogToFile          bool
	OutputFileName     string
	Verbose            bool
	AWSCredentials     AWSCredentials
	AssumedAWSRole     AWSCredentials
}

// NewSession returns the historical interactive defaults.
func NewSession(connection model.ServerInfo) *Session {
	connection.UseAuthCanI = true
	return &Session{
		Connection:  connection,
		Interactive: true,
		FullMenu:    true,
	}
}
