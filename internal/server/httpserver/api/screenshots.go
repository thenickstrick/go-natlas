package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/thenickstrick/go-natlas/internal/protocol"
	"github.com/thenickstrick/go-natlas/internal/server/objectstore"
)

// MaxScreenshotBytes caps a single screenshot upload. Real PNGs from a
// 1280x800 viewport sit comfortably under 1 MiB; this cap is purely a
// runaway-payload guard.
const MaxScreenshotBytes = 8 << 20 // 8 MiB

// screenshotKey is the canonical object-store key for a screenshot keyed by
// the SHA-256 of its bytes. Storing by hash gives us automatic dedup across
// scans (identical screen → identical bytes → same key).
func screenshotKey(hash string) string { return "screenshots/" + hash + ".png" }

// PostScreenshots accepts a multipart upload of screenshots tied to a
// specific scan_id. Each part carries:
//
//   - body: the PNG bytes (image/png)
//   - X-Natlas-Port:    the source port number
//   - X-Natlas-Service: "HTTP" | "HTTPS" | "VNC"
//   - X-Natlas-Hash:    optional client-computed sha256 hex (verified)
//
// On success returns a JSON envelope listing what was stored, with the
// server-computed hash for each. The agent uses this to populate the
// Screenshots field on the subsequent /api/v1/results submission.
func (h *Handlers) PostScreenshots(w http.ResponseWriter, r *http.Request) {
	if h.Objects == nil {
		writeErr(w, http.StatusServiceUnavailable, "object store not configured", true)
		return
	}
	scanID := chi.URLParam(r, "scan_id")
	if scanID == "" {
		writeErr(w, http.StatusBadRequest, "scan_id required", false)
		return
	}

	mr, err := r.MultipartReader()
	if err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("multipart: %v", err), false)
		return
	}

	saved := make([]protocol.Screenshot, 0, 4)
	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("multipart next: %v", err), false)
			return
		}

		port, _ := strconv.Atoi(part.Header.Get("X-Natlas-Port"))
		service := part.Header.Get("X-Natlas-Service")
		clientHash := part.Header.Get("X-Natlas-Hash")

		// Hash on the fly while buffering. Capping at MaxScreenshotBytes+1
		// lets us detect oversized parts without slurping unbounded memory.
		hasher := sha256.New()
		buf := &bytes.Buffer{}
		n, err := io.Copy(io.MultiWriter(buf, hasher), io.LimitReader(part, MaxScreenshotBytes+1))
		_ = part.Close()
		if err != nil {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("read part: %v", err), false)
			return
		}
		if n > MaxScreenshotBytes {
			writeErr(w, http.StatusRequestEntityTooLarge,
				fmt.Sprintf("screenshot exceeds %d bytes", MaxScreenshotBytes), false)
			return
		}
		if n == 0 {
			// Empty part — skip silently rather than write a useless object.
			continue
		}

		actualHash := hex.EncodeToString(hasher.Sum(nil))
		if clientHash != "" && clientHash != actualHash {
			writeErr(w, http.StatusBadRequest,
				fmt.Sprintf("hash mismatch: client=%s server=%s", clientHash, actualHash), false)
			return
		}

		key := screenshotKey(actualHash)
		// Skip the upload when the bytes already exist — content-addressed
		// storage gives us free dedup on identical screenshots across hosts
		// (think: blank "default page" landings).
		exists, err := h.Objects.Exists(r.Context(), key)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, fmt.Sprintf("object exists: %v", err), true)
			return
		}
		if !exists {
			if err := h.Objects.Put(r.Context(), key, bytes.NewReader(buf.Bytes()), "image/png", int64(buf.Len())); err != nil {
				writeErr(w, http.StatusInternalServerError, fmt.Sprintf("object put: %v", err), true)
				return
			}
		}

		saved = append(saved, protocol.Screenshot{
			Port:    port,
			Service: service,
			Hash:    actualHash,
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"scan_id": scanID,
		"saved":   saved,
	})
}

// Compile-time guard against silent decoupling: the Handlers struct must
// keep an Objects field for this handler to work.
var _ objectstore.Client = (*objectstore.MinIO)(nil)
