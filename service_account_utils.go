package peirates

import "time"
import "gopkg.in/square/go-jose.v2/jwt"
import "github.com/trung/jwt-tools/display"


// SERVICE ACCOUNT MANAGEMENT functions

// ServiceAccount stores service account information.
type ServiceAccount struct {
	Name            string    // Service account name
	Token           string    // Service account token
	DiscoveryTime   time.Time // Time the service account was discovered
	DiscoveryMethod string    // How the service account was discovered (file on disk, secrets, user input, etc.)
}

// MakeNewServiceAccount creates a new service account with the provided name,
// token, and discovery method, while setting the DiscoveryTime to time.Now()
func MakeNewServiceAccount(name, token, discoveryMethod string) ServiceAccount {
	return ServiceAccount{
		Name:            name,
		Token:           token,
		DiscoveryTime:   time.Now(),
		DiscoveryMethod: discoveryMethod,
	}
}

func acceptServiceAccountFromUser() ServiceAccount {
	println("\nPlease paste in a new service account token or hit ENTER to maintain current token.")
	serviceAccount := ServiceAccount{
		Name:            "",
		Token:           "",
		DiscoveryTime:   time.Now(),
		DiscoveryMethod: "User Input",
	}
	println("\nWhat do you want to name this service account?")
	serviceAccount.Name, _ = ReadLineStripWhitespace()
	println("\nPaste the service account token and hit ENTER:")
	serviceAccount.Token, _ = ReadLineStripWhitespace()

	return serviceAccount
}

func assignServiceAccountToConnection(account ServiceAccount, info *ServerInfo) {
	info.TokenName = account.Name
	info.Token = account.Token
}


func printJWT(tokenString string) {

    var claims map[string]interface{} 
    
    token, _ := jwt.ParseSigned(tokenString)
    _ = token.UnsafeClaimsWithoutVerification(&claims)
    
    display.PrintJSON(claims)
}
        
