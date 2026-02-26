package canonicaljson

import "testing"

func TestCanonicalizeAndHashVector(t *testing.T) {
	input := []byte(`{"b":1,"a":"x","c":[true,2]}`)
	canonical, err := Canonicalize(input)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	expectedCanonical := `{"a":"x","b":1,"c":[true,2]}`
	if string(canonical) != expectedCanonical {
		t.Fatalf("expected %s, got %s", expectedCanonical, string(canonical))
	}
	hash := HashSHA256(canonical)
	expectedHash := "04ceb95b6eab660e1db5b4cf9e1d8ad320a4772a2a22775bb679d53daabd84f2"
	if hash != expectedHash {
		t.Fatalf("expected hash %s, got %s", expectedHash, hash)
	}
}

func TestCanonicalizeFloatAsString(t *testing.T) {
	input := []byte(`{"value":1.25}`)
	canonical, err := Canonicalize(input)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	if string(canonical) != `{"value":"1.25"}` {
		t.Fatalf("expected float as string, got %s", string(canonical))
	}
}
