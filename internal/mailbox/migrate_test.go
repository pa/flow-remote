package mailbox

import (
	"context"
	"os"
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/pa/flow-remote/internal/envelope"
)

// Records written before tenancy: a Mac with no admin flag, a device with
// no owner. After migrate, the Mac is an admin and owns the device.
func TestMigratePreTenancyData(t *testing.T) {
	uri := os.Getenv("FLOW_REMOTE_MONGO_URI")
	if uri == "" {
		t.Skip("set FLOW_REMOTE_MONGO_URI to test the Mongo migration")
	}
	ctx := context.Background()
	db := "flow_remote_mig_" + envelope.NewID()[:8]
	m, err := OpenMongo(ctx, uri, db)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.envs.Database().Drop(ctx) })
	m.macs.InsertOne(ctx, bson.M{"_id": "mac-old", "sign_pub": "k"})
	m.devices.InsertOne(ctx, bson.M{"_id": "dev-old", "sign_pub": "d", "revoked": false})

	for i := 0; i < 2; i++ { // twice: it must be idempotent
		if err := m.migrate(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if mac, _ := m.GetMac(ctx, "mac-old"); !mac.Admin {
		t.Fatal("old Mac not made admin")
	}
	if d, err := m.GetDevice(ctx, "dev-old"); err != nil || d.Owner != "mac-old" {
		t.Fatalf("old device owner = %q, %v", d.Owner, err)
	}
}
