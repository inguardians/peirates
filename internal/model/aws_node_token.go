package model

import "time"

// AWSNodeTokenKey separates clusters, signing regions, and instance roles.
type AWSNodeTokenKey struct{ ClusterName, Region, RoleIdentity string }

// AWSNodeToken is a retained EKS credential, not a service-account JWT.
type AWSNodeToken struct {
	Token, ClusterName, Region, RoleIdentity                                     string
	RegionSource, ClusterSource, InstanceID, AccountID, RoleName, PrivateDNSName string
	AcquiredAt, ExpiresAt                                                        time.Time
	Corroborated, Verified, InstanceMatched                                      bool
	Username                                                                     string
	Groups                                                                       []string
	VerificationError                                                            string
}
