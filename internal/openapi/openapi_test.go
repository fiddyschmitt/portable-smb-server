package openapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSpecIsValidJSON(t *testing.T) {
	var doc map[string]any
	if err := json.Unmarshal(Spec(), &doc); err != nil {
		t.Fatalf("embedded spec is not valid JSON: %v", err)
	}
	if doc["openapi"] == nil || doc["paths"] == nil {
		t.Error("spec missing openapi/paths")
	}
}

func TestHandlerServesSpec(t *testing.T) {
	srv := httptest.NewServer(Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("status %d, content-type %q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}

	root, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer root.Body.Close()
	if root.StatusCode != 200 {
		t.Errorf("root status %d", root.StatusCode)
	}
}
