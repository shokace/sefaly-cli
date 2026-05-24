package tui

import (
	"context"
	"errors"
	"fmt"
	"mime"
	"os"
	"path/filepath"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/shokace/sefaly-cli/internal/api"
	"github.com/shokace/sefaly-cli/internal/cryptox"
)

// transferState tracks the one currently-running transfer. Phase
// B v1 deliberately allows only one at a time — pressing `c` again
// while a transfer is in flight is a no-op. The status bar shows
// which one is running so this isn't a surprise.
//
// A future queue / parallel-upload story would replace `*transferState`
// on the model with a slice + a per-row spinner. Not yet.
type transferState struct {
	label  string // shown in the status bar
	source Pane   // which pane initiated; destination is the other
}

// Bubble Tea messages for the transfer lifecycle. The Cmd that
// actually does the work returns one of completed / failed when
// it finishes; "started" is set synchronously in the key handler
// (because we already know the label by then).

type transferCompletedMsg struct {
	source Pane
}

type transferFailedMsg struct {
	err error
}

// startCopy is the entry point — dispatched from the key handler
// when the user hits `c` / F5. Inspects the focused pane's
// selection, sets m.transfer + clears any previous status error,
// returns a tea.Cmd that performs the work asynchronously.
//
// Returns nil if there's nothing to do (no selection, ".." row,
// folder selected with no recursive-copy support yet). In the
// folder case it ALSO sets m.statusErr so the user sees why
// nothing happened.
func (m *Model) startCopy() tea.Cmd {
	// Always clear the previous error on a fresh action — fail
	// messages from a previous transfer shouldn't stick around
	// past the next attempt.
	m.statusErr = nil

	if !m.ready {
		// Remote tree not loaded yet. Either direction needs it
		// (upload needs the destination folder ID; download needs
		// the source tree). Ignore the keypress.
		return nil
	}
	switch m.focused {
	case PaneLocal:
		return m.startUpload()
	case PaneRemote:
		return m.startDownload()
	}
	return nil
}

func (m *Model) startUpload() tea.Cmd {
	if m.local.cursor < 0 || m.local.cursor >= len(m.local.entries) {
		return nil
	}
	sel := m.local.entries[m.local.cursor]
	if sel.IsParent {
		return nil
	}
	if sel.IsDir {
		m.statusErr = errors.New("folder copy isn't implemented yet — select a file")
		return nil
	}

	sourcePath := filepath.Join(m.local.cwd, sel.Name)
	destFolderID := ""
	if cp := m.remote.currentParent(); cp != nil {
		destFolderID = *cp
	}

	m.transfer = &transferState{
		label:  fmt.Sprintf("Uploading %s → %s", sel.Name, m.remote.breadcrumb(m.privKey)),
		source: PaneLocal,
	}

	// Capture the fields we need into the closure. We don't pass
	// `m` directly because the goroutine running the Cmd shouldn't
	// reach into model state — that's Bubble Tea's threading model.
	// Everything we need is immutable for the duration of the
	// transfer.
	client := m.client
	publicKeyB64 := m.publicKeyB64

	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()
		if err := doUpload(ctx, client, sourcePath, destFolderID, publicKeyB64); err != nil {
			return transferFailedMsg{err: err}
		}
		return transferCompletedMsg{source: PaneLocal}
	}
}

func (m *Model) startDownload() tea.Cmd {
	if m.remote.cursor < 0 || m.remote.cursor >= len(m.remote.entries) {
		return nil
	}
	sel := m.remote.entries[m.remote.cursor]
	if sel.IsParent {
		return nil
	}
	if sel.IsDir {
		m.statusErr = errors.New("folder copy isn't implemented yet — select a file")
		return nil
	}

	fileID := sel.FileID
	decryptedName := sel.DisplayName
	destDir := m.local.cwd

	m.transfer = &transferState{
		label:  fmt.Sprintf("Downloading %s → %s", decryptedName, destDir),
		source: PaneRemote,
	}

	client := m.client
	// We rely on the model staying alive for the transfer's
	// duration (it does — Bubble Tea holds the only reference and
	// only releases on tea.Quit). Capturing privKey by reference
	// is fine; we just must NOT call quit() during a transfer or
	// the zero loop will mid-flight-zero the key while the upload
	// is mid-decrypt. Phase B v1 doesn't even try to handle that;
	// `q` during a transfer cancels the program, the OS reaps the
	// goroutine.
	privKey := m.privKey

	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()
		if err := doDownload(ctx, client, fileID, decryptedName, destDir, privKey); err != nil {
			return transferFailedMsg{err: err}
		}
		return transferCompletedMsg{source: PaneRemote}
	}
}

// doUpload is the inline copy of `sef upload`'s pipeline, minus
// the fmt.Printf progress chatter. Kept here rather than refactored
// into a shared helper because (a) the existing upload command has
// its own well-tested UX (progress prefixes, error formatting) and
// (b) the TUI doesn't want any of that. They're cleanly separate
// rather than coupled.
func doUpload(ctx context.Context, client *api.Client, sourcePath, destFolderID, publicKeyB64 string) error {
	plaintext, err := os.ReadFile(sourcePath)
	if err != nil {
		return fmt.Errorf("reading file: %w", err)
	}

	info, err := os.Stat(sourcePath)
	if err != nil {
		return fmt.Errorf("stat: %w", err)
	}
	if info.IsDir() {
		return errors.New("is a directory (folder uploads aren't implemented yet)")
	}

	basename := filepath.Base(sourcePath)
	mimeType := mime.TypeByExtension(filepath.Ext(basename))
	if mt, _, err := mime.ParseMediaType(mimeType); err == nil {
		mimeType = mt
	}

	enc, err := cryptox.EncryptFileForUpload(plaintext, basename, publicKeyB64)
	if err != nil {
		return fmt.Errorf("encrypting: %w", err)
	}

	init, err := client.UploadInit(ctx, &api.UploadInitRequest{
		SizeBytes: len(enc.Ciphertext),
		FolderID:  destFolderID,
	})
	if err != nil {
		return fmt.Errorf("init: %w", err)
	}

	if err := client.UploadPut(ctx, init.UploadURL, enc.Ciphertext); err != nil {
		return fmt.Errorf("storage PUT: %w", err)
	}

	var mimePtr *string
	if mimeType != "" {
		mimePtr = &mimeType
	}
	var folderIDPtr *string
	if destFolderID != "" {
		fid := destFolderID
		folderIDPtr = &fid
	}

	_, err = client.UploadComplete(ctx, &api.UploadCompleteRequest{
		FileID:            init.FileID,
		StoragePath:       init.StoragePath,
		EncryptedFilename: enc.EncryptedFilenameB64,
		FilenameNonce:     enc.FilenameNonceB64,
		MimeType:          mimePtr,
		FolderID:          folderIDPtr,
		EncapsulatedKey:   enc.EncapsulatedKeyB64,
		WrappedFileKey:    enc.WrappedFileKeyB64,
		Nonce:             enc.NonceB64,
		KeyWrapNonce:      enc.KeyWrapNonceB64,
		EncryptionMetadata: map[string]interface{}{
			"algorithm": "AES-256-GCM",
			"kemType":   "ML-KEM-768",
			"version":   "1.2",
		},
	})
	if err != nil {
		return fmt.Errorf("complete: %w", err)
	}
	return nil
}

// doDownload is the inline copy of `sef download`'s pipeline for
// owner downloads. Share-recipient downloads (no ownerWrap) get a
// clear error rather than mysterious failure — Phase B will need
// a "this file is shared with you" branch when we wire up share
// support.
func doDownload(
	ctx context.Context,
	client *api.Client,
	fileID, decryptedName, destDir string,
	privKey []byte,
) error {
	info, err := client.FileURL(ctx, fileID)
	if err != nil {
		return fmt.Errorf("requesting download URL: %w", err)
	}
	if info.OwnerWrap == nil {
		return errors.New("server didn't return wrap material — shared-file download not implemented in the TUI yet")
	}
	wrap := info.OwnerWrap

	ciphertext, err := client.FetchCiphertext(ctx, info.DownloadURL)
	if err != nil {
		return fmt.Errorf("downloading ciphertext: %w", err)
	}

	fileKey, err := cryptox.UnwrapFileKey(
		privKey,
		wrap.EncapsulatedKey,
		wrap.WrappedFileKey,
		wrap.KeyWrapNonce,
	)
	if err != nil {
		return fmt.Errorf("unwrapping file key: %w", err)
	}
	defer zeroBytes(fileKey)

	plaintext, err := cryptox.DecryptFileContent(
		fileKey,
		wrap.Nonce,
		wrap.EncryptionVersion,
		ciphertext,
	)
	if err != nil {
		return fmt.Errorf("decrypting: %w", err)
	}

	// Pick a non-clobbering output path so two presses of `c` on
	// the same file don't silently overwrite — "(1)", "(2)", etc.
	// suffixes, mirroring how desktop file managers handle the
	// "file already exists" case.
	outPath := pickNonClobberPath(filepath.Join(destDir, decryptedName))
	return atomicWriteFileTUI(outPath, plaintext)
}

// pickNonClobberPath returns `path` unchanged if nothing exists
// there, otherwise tries "path (1)", "path (2)", … up to 999. We
// don't loop forever because if 1000 same-named files are landing
// in one directory, something is wrong upstream.
func pickNonClobberPath(path string) string {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return path
	}
	ext := filepath.Ext(path)
	base := path[:len(path)-len(ext)]
	for i := 1; i < 1000; i++ {
		candidate := fmt.Sprintf("%s (%d)%s", base, i, ext)
		if _, err := os.Stat(candidate); os.IsNotExist(err) {
			return candidate
		}
	}
	return path
}

// atomicWriteFileTUI is a copy of download.go's atomic-write
// helper, lifted into this package so the TUI doesn't import
// cli/. Same pattern: write to a tempfile in the destination dir,
// chmod, rename.
func atomicWriteFileTUI(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".sef-tui-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		cleanup()
		return err
	}
	return nil
}
