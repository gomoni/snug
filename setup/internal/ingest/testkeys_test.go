package ingest

import "encoding/base64"

// BlobForTest is a base64 ed25519 key blob that differs per seed.
func BlobForTest(seed byte) string { return base64.StdEncoding.EncodeToString(keyBlob(seed)) }
