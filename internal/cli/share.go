package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/shokace/sefaly-cli/internal/api"
	"github.com/shokace/sefaly-cli/internal/cryptox"
	"github.com/shokace/sefaly-cli/internal/ui"
	"github.com/spf13/cobra"
)

var (
	shareTo       string
	shareExpires  int
	shareMaxDowns int
	shareSlug     string
)

func init() {
	rootCmd.AddCommand(shareCmd)
	shareCmd.AddCommand(shareLsCmd, shareRevokeCmd)
	shareCmd.Flags().StringVar(&shareTo, "to", "",
		"Share directly with a Sefaly user by email (end-to-end, not a public link).")
	shareCmd.Flags().IntVar(&shareExpires, "expires", 0,
		"Public link: days until it expires (0 = your tier's default).")
	shareCmd.Flags().IntVar(&shareMaxDowns, "max-downloads", 0,
		"Public link: stop working after N downloads (0 = unlimited).")
	shareCmd.Flags().StringVar(&shareSlug, "slug", "",
		"Public link: a custom URL slug (Pro feature).")
}

var shareCmd = &cobra.Command{
	Use:   "share <path>",
	Short: "Share a file via a public link or directly with a user",
	Long: `Create a share for a file. Two kinds:

  • Public link (default) — anyone with the link can download. The
    decryption key lives in the URL fragment (after '#'); the server
    never sees it, so it can't read your file.

      sef share report.pdf
      sef share report.pdf --expires 7 --max-downloads 5
      sef share report.pdf --slug q3-report        (Pro)

  • Direct share (--to) — end-to-end share with a registered Sefaly
    user. The file key is re-wrapped to their post-quantum public key;
    only they can open it.

      sef share report.pdf --to alex@example.com

Manage shares with ` + "`sef share ls`" + ` and ` + "`sef share revoke <id>`" + `.
(Folder sharing from the CLI is coming; use the web app for now.)`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		_, privKey, client, baseURL, err := authedClientURL()
		if err != nil {
			return err
		}
		defer zero(privKey)

		ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
		defer cancel()
		tree, err := client.Tree(ctx)
		if err != nil {
			if api.IsStatus(err, 401) {
				return errors.New("server rejected your token — run `sef login` to re-authorize")
			}
			return fmt.Errorf("fetching file tree: %w", err)
		}

		fileID, folderID, err := resolveDeleteTarget(args[0], tree, privKey)
		if err != nil {
			return err
		}
		if folderID != "" {
			return errors.New("folder sharing from the CLI isn't supported yet — use the web app, or share individual files")
		}

		// Find the file row + unwrap its key (we need it for either path).
		var f *api.File
		for i := range tree.Files {
			if tree.Files[i].ID == fileID {
				f = &tree.Files[i]
				break
			}
		}
		if f == nil {
			return errors.New("file not found")
		}
		fileKey, err := cryptox.UnwrapFileKey(privKey, f.EncapsulatedKey, f.EncryptedFileKey, f.KeyWrapNonce())
		if err != nil {
			return fmt.Errorf("unwrapping file key: %w", err)
		}
		defer zero(fileKey)

		// --- Direct user share ---
		if shareTo != "" {
			recipientID, recipientPK, err := client.LookupPublicKey(ctx, shareTo)
			if err != nil {
				if api.IsStatus(err, 404) {
					return fmt.Errorf("no Sefaly account is registered with %q", shareTo)
				}
				return fmt.Errorf("looking up recipient: %w", err)
			}
			wrap, err := cryptox.WrapFileKeyForRecipient(fileKey, recipientPK)
			if err != nil {
				return fmt.Errorf("wrapping key for recipient: %w", err)
			}
			if err := client.ShareFileWithUser(ctx, fileID, recipientID, wrap.EncapsulatedKeyB64, wrap.WrappedKeyB64, wrap.KeyWrapNonceB64); err != nil {
				return fmt.Errorf("creating share: %w", err)
			}
			if jsonOutput {
				return emitJSON(map[string]any{"type": "direct", "file": args[0], "recipient": shareTo})
			}
			fmt.Println(ui.Success_(fmt.Sprintf("Shared %s with %s (end-to-end).", args[0], ui.Boldf(shareTo))))
			return nil
		}

		// --- Public link ---
		linkKey, err := cryptox.GenerateLinkKey()
		if err != nil {
			return err
		}
		defer zero(linkKey)
		payload, nonce, err := cryptox.EncryptForPublicLink(fileKey, linkKey)
		if err != nil {
			return err
		}

		opt := api.PublicLinkOptions{CustomSlug: shareSlug}
		if cmd.Flags().Changed("expires") {
			d := shareExpires
			opt.ExpiresInDays = &d
		}
		if cmd.Flags().Changed("max-downloads") {
			n := shareMaxDowns
			opt.MaxDownloads = &n
		}

		token, slug, err := client.CreateFilePublicLink(ctx, fileID, payload, nonce, opt)
		if err != nil {
			if api.IsStatus(err, 403) {
				return fmt.Errorf("%w (custom slugs + longer expiries are Pro features)", err)
			}
			return fmt.Errorf("creating public link: %w", err)
		}
		ref := token
		if slug != "" {
			ref = slug
		}
		url := strings.TrimRight(baseURL, "/") + "/s/" + ref + "#" + cryptox.LinkKeyToFragment(linkKey)

		if jsonOutput {
			res := map[string]any{"type": "public-link", "file": args[0], "url": url, "token": token}
			if slug != "" {
				res["slug"] = slug
			}
			if opt.ExpiresInDays != nil {
				res["expiresInDays"] = *opt.ExpiresInDays
			}
			if opt.MaxDownloads != nil {
				res["maxDownloads"] = *opt.MaxDownloads
			}
			return emitJSON(res)
		}

		fmt.Println()
		fmt.Println(ui.Success_("Public link created."))
		fmt.Println("  " + ui.Accentf(url))
		fmt.Println("  " + ui.Faintf("The part after # is the decryption key — anyone with the full link can open the file."))
		if opt.ExpiresInDays != nil || opt.MaxDownloads != nil {
			var notes []string
			if opt.ExpiresInDays != nil {
				notes = append(notes, fmt.Sprintf("expires in %d day(s)", *opt.ExpiresInDays))
			}
			if opt.MaxDownloads != nil {
				notes = append(notes, fmt.Sprintf("max %d download(s)", *opt.MaxDownloads))
			}
			fmt.Println("  " + ui.Faintf(strings.Join(notes, " · ")))
		}
		fmt.Println()
		return nil
	},
}

var shareLsCmd = &cobra.Command{
	Use:   "ls",
	Short: "List the shares you've created",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		_, privKey, client, err := authedClient()
		if err != nil {
			return err
		}
		defer zero(privKey)
		ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
		defer cancel()
		out, err := client.ListOutgoingShares(ctx)
		if err != nil {
			if api.IsStatus(err, 401) {
				return errors.New("server rejected your token — run `sef login` to re-authorize")
			}
			return fmt.Errorf("listing shares: %w", err)
		}
		if jsonOutput {
			return emitJSON(out)
		}
		total := len(out.PublicLinks) + len(out.Files) + len(out.Folders)
		if total == 0 {
			fmt.Println(ui.Mutedf("  You haven't shared anything yet."))
			return nil
		}
		fmt.Println()
		if len(out.PublicLinks) > 0 {
			fmt.Println(ui.Heading("  Public links"))
			for _, l := range out.PublicLinks {
				ref := l.Token
				if l.CustomSlug != nil && *l.CustomSlug != "" {
					ref = *l.CustomSlug
				}
				fmt.Printf("  %s  %s\n", ui.Accentf("/s/"+ref), ui.Faintf("revoke id: "+l.ID))
			}
			fmt.Println("  " + ui.Faintf("(the decryption key was only shown when you created the link)"))
			fmt.Println()
		}
		if len(out.Files) > 0 {
			fmt.Println(ui.Heading("  Direct file shares"))
			for _, s := range out.Files {
				fmt.Printf("  %s  %s\n", ui.Fg(s.RecipientEmail), ui.Faintf("id: "+s.ID))
			}
			fmt.Println()
		}
		if len(out.Folders) > 0 {
			fmt.Println(ui.Heading("  Shared folders"))
			for _, s := range out.Folders {
				fmt.Printf("  %s  %s  %s\n", ui.Fg(s.RecipientEmail), ui.Faintf(fmt.Sprintf("%d file(s)", s.FileCount)), ui.Faintf("id: "+s.ID))
			}
			fmt.Println()
		}
		return nil
	},
}

var shareRevokeCmd = &cobra.Command{
	Use:   "revoke <link-id>...",
	Short: "Revoke a public link (by its id from `sef share ls`)",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		_, privKey, client, err := authedClient()
		if err != nil {
			return err
		}
		defer zero(privKey)
		ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
		defer cancel()
		n := 0
		for _, id := range args {
			if err := client.RevokePublicLink(ctx, id); err != nil {
				fmt.Println(ui.Error_(fmt.Sprintf("%s: %v", id, err)))
				continue
			}
			n++
		}
		if n > 0 {
			fmt.Println(ui.Success_(fmt.Sprintf("Revoked %d link(s).", n)))
		}
		if n < len(args) {
			return errors.New("some links could not be revoked")
		}
		return nil
	},
}
