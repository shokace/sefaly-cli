package cli

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"mime"
	"os"
	"path/filepath"
	"time"

	"github.com/shokace/sefaly-cli/internal/api"
	"github.com/shokace/sefaly-cli/internal/creds"
	"github.com/shokace/sefaly-cli/internal/cryptox"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(uploadCmd)
	uploadCmd.Flags().StringVarP(&uploadTo, "to", "t", "",
		"Folder to upload into, as a slash-separated path (default: root). "+
			"Example: --to Photos/2026/Trip")
	uploadCmd.Flags().BoolVar(&uploadOverwrite, "overwrite", false,
		"Replace an existing file with the same name instead of keeping both (auto-suffixed).")
	uploadCmd.Flags().BoolVarP(&uploadRecursive, "recursive", "r", false,
		"Upload a directory and its contents, recreating the folder structure.")
}

var (
	uploadTo        string
	uploadOverwrite bool
	uploadRecursive bool
)

var uploadCmd = &cobra.Command{
	Use:     "upload <file>...",
	Aliases: []string{"up", "put"},
	Short:   "Encrypt and upload one or more files",
	Long: `Upload one or more local files to your Sefaly account. Each
file is encrypted in this shell (ML-KEM-768 key wrap + AES-256-GCM
content + AES-GCM filename), the ciphertext is PUT directly to your
storage backend via a presigned URL, and a File row is written on
the server. The server never sees the plaintext content, the
plaintext filename, or the file's symmetric key.

  sef upload report.pdf
  sef upload photo.jpg --to Photos/2026
  sef upload *.pdf --to Documents          # shell-expanded
  sef upload a.txt b.txt c.txt --to MyDocs # multi-file`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		stored, err := creds.Load()
		if err != nil {
			if errors.Is(err, creds.ErrNotFound) {
				return errors.New("not signed in — run `sef login`")
			}
			return fmt.Errorf("reading credentials: %w", err)
		}

		// Decrypt the user's private key once, derive the public key
		// out of it (no /api/auth/me round-trip needed — ML-KEM-768's
		// expanded private key has the public key embedded as a
		// substring). Plaintext private key gets zeroed at function
		// end; the public key copy stays alive for the loop below.
		privKey, _, err := cryptox.DecryptPrivateKey(
			stored.AccessToken,
			stored.UserID,
			stored.EncryptedPrivateKey,
		)
		if err != nil {
			return fmt.Errorf("decrypting private key (re-login may help): %w", err)
		}
		defer zero(privKey)

		publicKey, err := cryptox.PublicKeyFromPrivate(privKey)
		if err != nil {
			return fmt.Errorf("extracting public key: %w", err)
		}
		publicKeyB64 := base64StdString(publicKey)

		baseURL, err := resolveBaseURL(stored.APIBaseURL)
		if err != nil {
			return err
		}
		client := api.New(baseURL, stored.AccessToken)

		// Fetch the tree once: needed both to resolve --to AND to detect
		// name collisions in the target folder. The server can't dedupe
		// names (they're encrypted), so we do it here.
		ctxTree, cancelTree := context.WithTimeout(cmd.Context(), 30*time.Second)
		tree, treeErr := client.Tree(ctxTree)
		cancelTree()
		if treeErr != nil {
			if api.IsStatus(treeErr, 401) {
				return errors.New("server rejected your token — run `sef login` to re-authorize")
			}
			return fmt.Errorf("fetching file tree: %w", treeErr)
		}
		var folderID *string
		if uploadTo != "" {
			id, err := resolvePath(uploadTo, tree.Folders, privKey)
			if err != nil {
				return err
			}
			folderID = id
		}

		// Names already taken in the destination folder → file ids, so a
		// collision can either auto-suffix "(N)" (default) or, with
		// --overwrite, replace the existing file after the new one lands.
		existing := folderFileNames(tree, folderID, privKey)

		// Upload each file sequentially. Could parallelize, but the
		// quota check happens at /complete with serializable isolation
		// anyway — concurrent uploads would just race and one would
		// 413. Serial is simpler + has predictable progress output.
		var hadError bool
		for i, arg := range args {
			if len(args) > 1 {
				fmt.Printf("[%d/%d] ", i+1, len(args))
			}

			// Directories: recurse (with -r) by recreating the structure
			// and uploading every file; otherwise refuse with a hint.
			if info, statErr := os.Stat(arg); statErr == nil && info.IsDir() {
				if !uploadRecursive {
					fmt.Fprintf(os.Stderr, "  %s is a directory — pass -r to upload it recursively\n", arg)
					hadError = true
					continue
				}
				n, derr := uploadDir(cmd.Context(), client, privKey, publicKeyB64, arg, folderID, tree)
				fmt.Printf("  ✓ Uploaded %d file(s) from %s\n", n, filepath.Base(arg))
				if derr != nil {
					fmt.Fprintf(os.Stderr, "  Error uploading %s: %v\n", arg, derr)
					hadError = true
				}
				continue
			}

			desired := filepath.Base(arg)
			finalName := desired
			overwriteID := ""
			if oldID, clash := existing[desired]; clash {
				if uploadOverwrite {
					overwriteID = oldID
				} else {
					finalName = uniqueFileName(desired, existing)
					fmt.Printf("  %q already exists here — saving as %q (use --overwrite to replace)\n", desired, finalName)
				}
			}
			// Reserve the chosen name so a later file in the same batch
			// can't pick it too.
			existing[finalName] = "pending"

			if err := uploadOne(cmd.Context(), client, arg, folderID, publicKeyB64, finalName); err != nil {
				fmt.Fprintf(os.Stderr, "  Error uploading %s: %v\n", filepath.Base(arg), err)
				hadError = true
				continue
			}
			if overwriteID != "" {
				delCtx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
				if derr := client.DeleteFile(delCtx, overwriteID); derr != nil {
					fmt.Fprintf(os.Stderr, "  Uploaded, but couldn't remove the previous %q (it's in Trash-able state): %v\n", desired, derr)
				}
				cancel()
			}
		}
		if hadError {
			return errors.New("one or more uploads failed")
		}
		return nil
	},
}

// uploadDir recursively uploads a local directory: it recreates the
// folder structure under baseFolderID (reusing any existing cloud folder
// of the same name, so re-uploads merge) and uploads every regular file,
// resolving filename collisions per destination folder. Returns the
// number of files uploaded. Symlinks, devices, and sockets are skipped.
func uploadDir(
	parentCtx context.Context,
	client *api.Client,
	privKey []byte,
	publicKeyB64 string,
	localDir string,
	baseFolderID *string,
	tree *api.TreeResponse,
) (int, error) {
	localDir = filepath.Clean(localDir)

	findOrCreate := func(parent *string, name string) (*string, error) {
		if id := findChildFolderID(tree, parent, name, privKey); id != nil {
			return id, nil
		}
		id, err := createOneFolder(parentCtx, client, tree, parent, name, publicKeyB64)
		if err != nil {
			return nil, err
		}
		return &id, nil
	}

	rootID, err := findOrCreate(baseFolderID, filepath.Base(localDir))
	if err != nil {
		return 0, fmt.Errorf("creating %q: %w", filepath.Base(localDir), err)
	}

	cloudIDFor := map[string]*string{localDir: rootID}
	// Cache the taken-name set per destination folder, populated lazily +
	// reserved as we go so two local files with the same name still land
	// uniquely.
	taken := map[string]map[string]string{}
	takenFor := func(id *string) map[string]string {
		k := strPtrKey(id)
		if taken[k] == nil {
			taken[k] = folderFileNames(tree, id, privKey)
		}
		return taken[k]
	}

	uploaded := 0
	walkErr := filepath.WalkDir(localDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&fs.ModeSymlink != 0 {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if path == localDir {
				return nil // root already created
			}
			id, cerr := findOrCreate(cloudIDFor[filepath.Dir(path)], d.Name())
			if cerr != nil {
				return cerr
			}
			cloudIDFor[path] = id
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		parentID := cloudIDFor[filepath.Dir(path)]
		t := takenFor(parentID)
		finalName := d.Name()
		overwriteID := ""
		if oldID, clash := t[d.Name()]; clash {
			if uploadOverwrite {
				overwriteID = oldID
			} else {
				finalName = uniqueFileName(d.Name(), t)
			}
		}
		t[finalName] = "pending"
		if uerr := uploadOne(parentCtx, client, path, parentID, publicKeyB64, finalName); uerr != nil {
			fmt.Fprintf(os.Stderr, "  Error uploading %s: %v\n", path, uerr)
			return nil // keep going with the rest of the tree
		}
		if overwriteID != "" {
			dctx, cancel := context.WithTimeout(parentCtx, 30*time.Second)
			_ = client.DeleteFile(dctx, overwriteID)
			cancel()
		}
		uploaded++
		return nil
	})
	return uploaded, walkErr
}

// uploadOne handles a single file: read → encrypt → init → PUT →
// complete. Errors at any stage abort that file but the caller
// continues with the next one (so a bad path in a batch upload
// doesn't kill the rest).
func uploadOne(
	parentCtx context.Context,
	client *api.Client,
	localPath string,
	folderID *string,
	publicKeyB64 string,
	displayName string,
) error {
	// Read once into memory. Streaming AES-GCM seal exists but the
	// AEAD interface here doesn't expose it, and the upload PUT
	// needs a known Content-Length anyway — that's set when we
	// sign the presigned URL.
	plaintext, err := os.ReadFile(localPath)
	if err != nil {
		return fmt.Errorf("reading file: %w", err)
	}

	info, err := os.Stat(localPath)
	if err != nil {
		return fmt.Errorf("stat: %w", err)
	}
	if info.IsDir() {
		return errors.New("is a directory (folder uploads aren't implemented yet)")
	}

	// The stored (encrypted) name is the collision-resolved displayName,
	// which may differ from the local basename (e.g. "report (1).pdf").
	// It keeps the original extension, so MIME detection is unaffected.
	basename := displayName
	// Strip any parameters from the detected media type. Go's
	// `mime.TypeByExtension(".txt")` returns "text/plain; charset=utf-8",
	// but the server's MIME_TYPE_REGEX rejects anything with a
	// semicolon. Browser uploads also send the bare `File.type`
	// (e.g. just "text/plain"), so doing the same keeps the wire
	// format identical. Empty result → leave it null.
	mimeType := mime.TypeByExtension(filepath.Ext(basename))
	if mt, _, err := mime.ParseMediaType(mimeType); err == nil {
		mimeType = mt
	}

	fmt.Printf("  Encrypting %s (%s)…\n", basename, prettySize(int64(len(plaintext))))
	enc, err := cryptox.EncryptFileForUpload(plaintext, basename, publicKeyB64)
	if err != nil {
		return fmt.Errorf("encrypting: %w", err)
	}

	// /init pre-flights quota + signs a presigned PUT against the
	// ciphertext size. Browser uploads include the +16 byte GCM tag
	// in this count — we already include it because the ciphertext
	// returned by aesGCMSeal has the tag appended.
	initCtx, initCancel := context.WithTimeout(parentCtx, 30*time.Second)
	init, err := client.UploadInit(initCtx, &api.UploadInitRequest{
		SizeBytes: len(enc.Ciphertext),
		FolderID:  derefOr(folderID, ""),
	})
	initCancel()
	if err != nil {
		// 413 = quota / size limit; 401 = bad token; 402 = billing
		// blocked. Surface the server's message verbatim — they're
		// already user-friendly.
		return fmt.Errorf("init: %w", err)
	}

	fmt.Printf("  Uploading %s…\n", prettySize(int64(len(enc.Ciphertext))))
	putCtx, putCancel := context.WithTimeout(parentCtx, 10*time.Minute)
	if err := client.UploadPut(putCtx, init.UploadURL, enc.Ciphertext); err != nil {
		putCancel()
		return fmt.Errorf("storage PUT: %w", err)
	}
	putCancel()

	// /complete writes the File row + the quota increment + share
	// rows (if any) in a serializable transaction. If THIS step
	// fails, the orphan R2 blob gets cleaned up by the server's
	// rejection handler; if it succeeds, the file is live.
	completeCtx, completeCancel := context.WithTimeout(parentCtx, 30*time.Second)
	defer completeCancel()
	resp, err := client.UploadComplete(completeCtx, &api.UploadCompleteRequest{
		FileID:            init.FileID,
		StoragePath:       init.StoragePath,
		OriginalFilename:  nil, // client-side encrypted name; server never sees plaintext
		EncryptedFilename: enc.EncryptedFilenameB64,
		FilenameNonce:     enc.FilenameNonceB64,
		MimeType:          stringPtrOrNil(mimeType),
		FolderID:          folderID,
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

	fmt.Printf("  ✓ Uploaded %s (id=%s)\n", basename, resp.File.ID)
	return nil
}

// ---- small helpers ----

func base64StdString(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func stringPtrOrNil(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func derefOr[T any](p *T, fallback T) T {
	if p == nil {
		return fallback
	}
	return *p
}

// prettySize is upload's compact-byte-size formatter. ls.go has a
// similar helper (`humanSize`) but it's right-padded for column
// layout; this one is plain.
func prettySize(n int64) string {
	const k = 1024
	switch {
	case n < k:
		return fmt.Sprintf("%d B", n)
	case n < k*k:
		return fmt.Sprintf("%.1f KB", float64(n)/k)
	case n < k*k*k:
		return fmt.Sprintf("%.1f MB", float64(n)/(k*k))
	default:
		return fmt.Sprintf("%.1f GB", float64(n)/(k*k*k))
	}
}
