package artx

import "sync/atomic"

// RuntimeStats contains process-lifetime, privacy-safe ArtX client transport
// counters. The values have no node, user, address, or payload dimensions.
type RuntimeStats struct {
	UnexpectedDisconnects uint64 `json:"unexpected_disconnects"`
}

var unexpectedDisconnects atomic.Uint64

// RuntimeStatsSnapshot returns a lock-free snapshot for the embedding client.
func RuntimeStatsSnapshot() RuntimeStats {
	return RuntimeStats{
		UnexpectedDisconnects: unexpectedDisconnects.Load(),
	}
}

func recordUnexpectedDisconnect() {
	unexpectedDisconnects.Add(1)
}
