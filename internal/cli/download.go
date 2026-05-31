package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/shokace/sefaly-cli/internal/api"
	"github.com/shokace/sefaly-cli/internal/creds"
	"github.com/shokace/sefaly-cli/internal/cryptox"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(downloadCmd)
	downloadCmd.Flags().StringVarP(&downloadOut, "out", "o", "",
		"Where to save the decrypted file. May be a directory (file saved with its original name) or a full output path. Defaults to the current directory.")
	downloadCmd.Flags().BoolVarP(&downloadForce, "force", "f", false,
		"Overwrite the output file if it already exists.")
}

var (
	downloadOut   string
	downloadForce bool
)

var downloadCmd = &cobra.Command{
	Use:     "download <path>",
	Aliases: []string{"dl", "get"},
	Short:   "Download and decrypt a file",
	Long: `Download a file from your account, decrypt it locally, and
save the plaintext to disk.

  sef download report.pdf
  sef download Photos/2026/Trip/IMG_1234.jpg --out ~/Downloads
  sef download Photos/IMG.jpg --out /tmp/renamed.jpg --force

Path is slash-separated, mirroring the folder hierarchy in your
account. The server only ever sees the ciphertext + the wrapped key —
the file key is recovered locally via ML-KEM decapsulation against
your private key.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		stored, err := creds.Load()
		if err != nil {
			if errors.Is(err, creds.ErrNotFound) {
				return errors.New("not signed in — run `sef login`")
			}
			return fmt.Errorf("reading credentials: %w", err)
		}

		privKey, _, err := cryptox.DecryptPrivateKey(
			stored.AccessToken,
			stored.UserID,
			stored.EncryptedPrivateKey,
		)
		if err != nil {
			return fmt.Errorf("decrypting private key (re-login may help): %w", err)
		}
		defer zero(privKey)

		baseURL, err := resolveBaseURL(stored.APIBaseURL)
		if err != nil {
			return err
		}
		client := api.New(baseURL, stored.AccessToken)

		// 1. Pull the tree once and resolve the path locally. Costs
		// one round-trip up front but keeps subsequent operations
		// (filename decrypt, file metadata) purely local.
		ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
		defer cancel()
		tree, err := client.Tree(ctx)
		if err != nil {
			if api.IsStatus(err, 401) {
				return errors.New("server rejected your token — run `sef login` to re-authorize")
			}
			return fmt.Errorf("fetching file tree: %w", err)
		}

		file, decryptedName, err := resolveFile(args[0], tree, privKey)
		if err != nil {
			return err
		}

		// 2. Decide where to write before doing any expensive work
		// (download, decrypt). Catches "directory doesn't exist" or
		// "would overwrite" before the user has paid for a multi-MB
		// download.
		outPath, err := pickOutputPath(downloadOut, decryptedName)
		if err != nil {
			return err
		}
		if !downloadForce {
			if _, err := os.Stat(outPath); err == nil {
				return fmt.Errorf("%s already exists (re-run with --force to overwrite)", outPath)
			} else if !os.IsNotExist(err) {
				return fmt.Errorf("checking %s: %w", outPath, err)
			}
		}

		// 3. Get the presigned download URL + the wrap material.
		// /api/files/[id]/url returns ownerWrap for files we own;
		// share recipients get only the URL (file-share table holds
		// their wrap material separately, not implemented here yet).
		urlCtx, urlCancel := context.WithTimeout(cmd.Context(), 30*time.Second)
		defer urlCancel()
		info, err := client.FileURL(urlCtx, file.ID)
		if err != nil {
			return fmt.Errorf("requesting download URL: %w", err)
		}
		if info.OwnerWrap == nil {
			// We hit /api/files/[id]/url for a file we don't own —
			// shouldn't happen for a tree resolution that only walks
			// our own folders, but handle defensively. Once share
			// support lands this branch becomes the "use recipient
			// wrap" path.
			return errors.New("server didn't return wrap material — share-recipient downloads not implemented yet")
		}
		wrap := info.OwnerWrap

		// 4. Download the ciphertext from wherever the server pointed
		// us. In prod that's a presigned R2 URL (off-host); in dev
		// it's a same-origin streaming endpoint. Either way the
		// FetchCiphertext helper does the right thing.
		fmt.Printf("  Downloading %s…\n", decryptedName)
		dlCtx, dlCancel := context.WithTimeout(cmd.Context(), 10*time.Minute)
		defer dlCancel()
		ciphertext, err := client.FetchCiphertext(dlCtx, info.DownloadURL)
		if err != nil {
			return fmt.Errorf("downloading ciphertext: %w", err)
		}

		// 5. Unwrap the per-file symmetric key.
		fileKey, err := cryptox.UnwrapFileKey(
			privKey,
			wrap.EncapsulatedKey,
			wrap.WrappedFileKey,
			wrap.KeyWrapNonce,
		)
		if err != nil {
			return fmt.Errorf("unwrapping file key: %w", err)
		}
		defer zero(fileKey)

		// 6. Decrypt the file content. v1.2 binds AAD to the
		// canonical metadata; cryptox.DecryptFileContent rebuilds
		// the same AAD the browser used at upload time, so a
		// server-side metadata tweak fails GCM auth instead of
		// quietly producing wrong bytes.
		plaintext, err := cryptox.DecryptFileContent(
			fileKey,
			wrap.Nonce,
			wrap.EncryptionVersion,
			ciphertext,
		)
		if err != nil {
			return fmt.Errorf("decrypting file: %w", err)
		}
		// Scrub the plaintext-buffer slice header once we've written
		// out; the bytes themselves get GC'd whenever they're done.

		// 7. Write to disk atomically — write to a tempfile in the
		// destination directory and rename. A crash mid-write
		// otherwise leaves a half-written file with the real name
		// that an `--force=false` rerun would refuse to clobber.
		if err := atomicWriteFile(outPath, plaintext); err != nil {
			return fmt.Errorf("writing %s: %w", outPath, err)
		}

		abs, _ := filepath.Abs(outPath)
		fmt.Printf("  Saved %d bytes to %s\n", len(plaintext), abs)
		return nil
	},
}

// resolveFile walks a slash-separated path (folders…/filename),
// resolves each folder segment by its DECRYPTED display name, then
// finds the file in the leaf folder by its decrypted name. Returns
// the api.File row + the decrypted filename so the caller doesn't
// have to redo the decrypt.
func resolveFile(path string, tree *api.TreeResponse, privKey []byte) (*api.File, string, error) {
	path = strings.Trim(path, "/")
	if path == "" {
		return nil, "", errors.New("a file path is required, e.g. `sef download report.pdf`")
	}

	// Split into (folder-segments…, filename). If only one segment,
	// folder is root.
	parts := strings.Split(path, "/")
	filename := parts[len(parts)-1]
	folderPath := strings.Join(parts[:len(parts)-1], "/")

	parentID, err := resolvePath(folderPath, tree.Folders, privKey)
	if err != nil {
		return nil, "", err
	}

	// Find the file by decrypted name in the resolved folder.
	filesByParent := indexFilesByParent(tree.Files)
	candidates := filesByParent[strPtrKey(parentID)]
	var match *api.File
	for i := range candidates {
		name, err := fileDisplayName(candidates[i], privKey)
		if err != nil {
			continue
		}
		if name == filename {
			if match != nil {
				return nil, "", fmt.Errorf("multiple files named %q in this folder — disambiguate via the web UI", filename)
			}
			m := candidates[i]
			match = &m
		}
	}
	if match == nil {
		return nil, "", fmt.Errorf("no such file: %q", path)
	}
	return match, filename, nil
}

// pickOutputPath resolves --out + the decrypted filename into a
// concrete output path. Rules:
//
//   - --out empty  → write to ./<filename>
//   - --out is an existing directory  → write to <out>/<filename>
//   - otherwise  → use --out verbatim as the output path (creating
//     the parent dir if missing? No — refuse, to match `cp`'s
//     behavior. Avoids accidentally creating deep trees the user
//     didn't intend.)
func pickOutputPath(out, decryptedName string) (string, error) {
	if decryptedName == "" {
		return "", errors.New("file has no usable filename — refusing to save without one")
	}
	if out == "" {
		return filepath.Join(".", decryptedName), nil
	}
	// Expand ~ since we set this via a flag, not a shell, so the
	// user's shell didn't get a chance to.
	if strings.HasPrefix(out, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			out = filepath.Join(home, out[2:])
		}
	}
	if info, err := os.Stat(out); err == nil && info.IsDir() {
		return filepath.Join(out, decryptedName), nil
	}
	// Treat as a full path. Validate the parent exists so we fail
	// fast rather than after the download.
	parent := filepath.Dir(out)
	if parent != "" && parent != "." {
		if _, err := os.Stat(parent); err != nil {
			return "", fmt.Errorf("output directory %s does not exist", parent)
		}
	}
	return out, nil
}

// atomicWriteFile writes bytes to a tempfile in the same directory
// as `path` and renames over the destination. Avoids leaving a
// half-written file when the process is killed mid-write.
func atomicWriteFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".sef-download-*")
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
