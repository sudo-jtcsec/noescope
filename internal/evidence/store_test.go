package evidence

import (
	"testing"

	"github.com/sudo-jtcsec/noescope/internal/tools"
)

func TestOpenStoreLoadsExistingEvidenceForResume(t *testing.T) {
	runRoot := t.TempDir()
	store := NewStore(runRoot)
	records, err := store.AddDrafts("surface.api.group_1", []tools.EvidenceDraft{{
		Kind: "source", Path: "jsonrpc.php", Summary: "JSON-RPC entrypoint",
	}})
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenStore(runRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || !reopened.Exists(records[0].ID) {
		t.Fatalf("reopened evidence store omitted %q", records[0].ID)
	}
}
