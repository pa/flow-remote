package mailbox

import (
	"testing"

	"go.mongodb.org/mongo-driver/v2/x/mongo/driver/connstring"
)

func TestConnStringDatabase(t *testing.T) {
	cs, err := connstring.Parse("mongodb://u.asia-south1.firestore.goog:443/mailbox-abc-dev?loadBalanced=true&tls=true&retryWrites=false&authMechanism=MONGODB-OIDC&authMechanismProperties=ENVIRONMENT:gcp,TOKEN_RESOURCE:FIRESTORE")
	if err != nil || cs.Database != "mailbox-abc-dev" {
		t.Fatalf("%q %v", cs.Database, err)
	}
}
