package cli

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"time"

	"github.com/shokace/sefaly-cli/internal/api"
	"github.com/shokace/sefaly-cli/internal/ui"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(shellCmd)
}

var shellCmd = &cobra.Command{
	Use:     "shell",
	Aliases: []string{"sh", "repl"},
	Short:   "Open an interactive session in your cloud",
	Long: `Drop into an interactive prompt that keeps a current folder, so you
can navigate and manage your account like a remote filesystem:

  cd, ls, pwd, get, put, mkdir, mv, cp, rm, info, share, trash, whoami

Type 'help' inside the session for the full list, 'exit' to leave.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runShell()
	},
}

// shellSession holds the state that persists across an interactive
// session: the decrypted private key (kept in memory for the whole
// session, zeroed on exit), the client, and the current cloud folder.
type shellSession struct {
	client  *api.Client
	privKey []byte
	baseURL string
	email   string
	cwdID   *string // current folder id (nil = root)
	cwdPath string  // absolute display path, e.g. "/Photos/2026"
	reader  *bufio.Reader
}

func runShell() error {
	stored, privKey, client, baseURL, err := authedClientURL()
	if err != nil {
		return err
	}
	s := &shellSession{
		client:  client,
		privKey: privKey,
		baseURL: baseURL,
		email:   stored.Email,
		cwdPath: "/",
		reader:  bufio.NewReader(os.Stdin),
	}
	defer zero(s.privKey)

	fmt.Print(ui.Banner(Version, statusLine()))
	fmt.Println("  " + ui.Faintf("Type ") + ui.Accentf("help") + ui.Faintf(" for commands, ") + ui.Accentf("exit") + ui.Faintf(" to quit."))
	fmt.Println()

	for {
		fmt.Print(ui.Prompt(s.cwdPath))
		line, err := s.reader.ReadString('\n')
		if err == io.EOF {
			fmt.Println()
			return nil
		}
		if err != nil {
			return nil
		}
		toks := tokenize(strings.TrimSpace(line))
		if len(toks) == 0 {
			continue
		}
		if quit := s.dispatch(toks); quit {
			return nil
		}
	}
}

// dispatch runs one parsed command line. Returns true to exit the shell.
func (s *shellSession) dispatch(toks []string) (quit bool) {
	cmd, args := toks[0], toks[1:]
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()

	switch cmd {
	case "exit", "quit", "q":
		return true
	case "help", "?":
		s.printHelp()
	case "clear", "cls":
		fmt.Print("\033[H\033[2J")
	case "pwd":
		fmt.Println("  " + s.cwdPath)
	case "cd":
		s.cd(ctx, args)
	case "ls", "dir":
		resetSubFlags()
		s.runSub(ctx, lsCmd, s.cloudArgs(args, true))
	case "tree":
		resetSubFlags()
		lsTree = true
		s.runSub(ctx, lsCmd, s.cloudArgs(args, true))
	case "info", "stat":
		s.needArg(args, "info <name>", func() { resetSubFlags(); s.runSub(ctx, infoCmd, s.cloudArgs(args, false)) })
	case "get", "download", "dl":
		s.get(ctx, args)
	case "put", "upload", "up":
		s.put(ctx, args)
	case "mkdir":
		s.needArg(args, "mkdir <name>", func() { resetSubFlags(); s.runSub(ctx, mkdirCmd, s.cloudArgs(args, false)) })
	case "mv", "move", "rename":
		s.twoArg(args, "mv <src> <dst>", func() { resetSubFlags(); s.runSub(ctx, mvCmd, s.cloudArgs(args, false)) })
	case "cp", "copy":
		s.twoArg(args, "cp <src> <dst>", func() { resetSubFlags(); s.runSub(ctx, cpCmd, s.cloudArgs(args, false)) })
	case "rm", "del", "delete":
		s.rm(ctx, args)
	case "share":
		s.needArg(args, "share <name>", func() { resetSubFlags(); s.runSub(ctx, shareCmd, s.cloudArgs(args, false)) })
	case "trash":
		s.trash(ctx, args)
	case "whoami":
		resetSubFlags()
		s.runSub(ctx, whoamiCmd, nil)
	default:
		fmt.Println(ui.Error_(fmt.Sprintf("unknown command %q — type %s", cmd, ui.Accentf("help"))))
	}
	return false
}

// cloudArgs translates each cloud-path arg to a root-relative path
// against the current folder. If allowEmpty and there are no args, it
// returns [cwd] so commands like `ls` default to the current folder.
func (s *shellSession) cloudArgs(args []string, defaultToCwd bool) []string {
	if len(args) == 0 && defaultToCwd {
		return []string{s.rel(s.cwdPath)}
	}
	out := make([]string, len(args))
	for i, a := range args {
		out[i] = s.abs(a)
	}
	return out
}

// abs resolves a cloud-path arg against cwd into a cleaned root-relative
// path (no leading slash). Handles "/absolute", "relative", "..", ".".
func (s *shellSession) abs(arg string) string {
	p := arg
	if !strings.HasPrefix(p, "/") {
		p = s.cwdPath + "/" + p
	}
	return s.rel(path.Clean("/" + strings.TrimLeft(p, "/")))
}

func (s *shellSession) rel(absPath string) string {
	return strings.TrimPrefix(path.Clean("/"+strings.TrimLeft(absPath, "/")), "/")
}

// cd changes the current folder, validating the target exists.
func (s *shellSession) cd(ctx context.Context, args []string) {
	target := ""
	if len(args) > 0 {
		target = s.abs(args[0])
	}
	if target == "" {
		s.cwdID, s.cwdPath = nil, "/"
		return
	}
	tree, err := s.client.Tree(ctx)
	if err != nil {
		fmt.Println(ui.Error_(friendlyErr(err)))
		return
	}
	id, err := resolvePath(target, tree.Folders, s.privKey)
	if err != nil {
		fmt.Println(ui.Error_(err.Error()))
		return
	}
	s.cwdID, s.cwdPath = id, "/"+target
}

// get downloads a cloud file to the local working directory (or a given
// local destination as the optional 2nd arg).
func (s *shellSession) get(ctx context.Context, args []string) {
	if len(args) == 0 {
		fmt.Println(ui.Error_("usage: get <file> [local-destination]"))
		return
	}
	resetSubFlags()
	if len(args) >= 2 {
		downloadOut = args[1] // local path, used verbatim
	}
	s.runSub(ctx, downloadCmd, []string{s.abs(args[0])})
}

// put uploads local files into the current cloud folder.
func (s *shellSession) put(ctx context.Context, args []string) {
	if len(args) == 0 {
		fmt.Println(ui.Error_("usage: put <local-file>..."))
		return
	}
	resetSubFlags()
	uploadTo = s.rel(s.cwdPath) // "" = root
	s.runSub(ctx, uploadCmd, args)
}

// rm deletes cloud files/folders after a single shell-side confirmation
// (so we don't double-read stdin via the rm command's own prompt).
func (s *shellSession) rm(ctx context.Context, args []string) {
	if len(args) == 0 {
		fmt.Println(ui.Error_("usage: rm <name>..."))
		return
	}
	if !confirmDestructive(fmt.Sprintf("Delete %s? (files go to Trash; folders are permanent)", strings.Join(args, ", "))) {
		fmt.Println(ui.Mutedf("  Cancelled."))
		return
	}
	resetSubFlags()
	rmForce = true     // we already confirmed; don't prompt again
	rmRecursive = true // allow folder deletes from the shell
	s.runSub(ctx, rmCmd, s.cloudArgs(args, false))
}

// trash dispatches the trash subcommands inside the shell.
func (s *shellSession) trash(ctx context.Context, args []string) {
	resetSubFlags()
	if len(args) == 0 {
		s.runSub(ctx, trashCmd, nil)
		return
	}
	switch args[0] {
	case "restore":
		s.runSub(ctx, trashRestoreCmd, args[1:])
	case "rm", "delete":
		trashForce = true
		s.runSub(ctx, trashRmCmd, args[1:])
	case "empty":
		trashForce = true
		s.runSub(ctx, trashEmptyCmd, nil)
	default:
		fmt.Println(ui.Error_("usage: trash | trash restore <name> | trash rm <name> | trash empty"))
	}
}

// runSub invokes a cobra command's RunE directly with the given args,
// wiring a context and printing any error in the shell's style instead
// of bubbling it up (so a bad command doesn't end the session).
func (s *shellSession) runSub(ctx context.Context, cmd *cobra.Command, args []string) {
	cmd.SetContext(ctx)
	if err := cmd.RunE(cmd, args); err != nil {
		fmt.Println(ui.Error_(friendlyErr(err)))
	}
}

func (s *shellSession) needArg(args []string, usage string, fn func()) {
	if len(args) == 0 {
		fmt.Println(ui.Error_("usage: " + usage))
		return
	}
	fn()
}

func (s *shellSession) twoArg(args []string, usage string, fn func()) {
	if len(args) < 2 {
		fmt.Println(ui.Error_("usage: " + usage))
		return
	}
	fn()
}

func (s *shellSession) printHelp() {
	fmt.Println()
	fmt.Println(ui.Heading("  Navigation"))
	fmt.Println(ui.KV([][2]string{
		{"ls [path]", "List the current folder (or path)"},
		{"cd <path>", "Change folder (.. up, / root, name down)"},
		{"pwd", "Print the current folder"},
		{"tree [path]", "Recursive listing"},
		{"info <name>", "Show details for a file or folder"},
	}))
	fmt.Println()
	fmt.Println(ui.Heading("  Files"))
	fmt.Println(ui.KV([][2]string{
		{"get <file> [dest]", "Download + decrypt to your machine"},
		{"put <local-file>", "Encrypt + upload into the current folder"},
		{"mkdir <name>", "Create a folder here"},
		{"mv <src> <dst>", "Move or rename"},
		{"cp <src> <dst>", "Copy a file"},
		{"rm <name>", "Delete (files → Trash, folders permanent)"},
		{"share <name>", "Create a public link"},
		{"trash", "trash | restore <name> | rm <name> | empty"},
	}))
	fmt.Println()
	fmt.Println(ui.Heading("  Session"))
	fmt.Println(ui.KV([][2]string{
		{"whoami", "Show the signed-in account"},
		{"clear", "Clear the screen"},
		{"help", "This list"},
		{"exit", "Leave the shell"},
	}))
	fmt.Println()
	fmt.Println("  " + ui.Faintf("For options (e.g. share --to / --expires), run ") + ui.Accentf("sef share …") + ui.Faintf(" outside the shell."))
	fmt.Println()
}

// friendlyErr unwraps a couple of common API errors into shell-friendly
// one-liners.
func friendlyErr(err error) string {
	if api.IsStatus(err, 401) {
		return "your session expired — run `sef login` (outside the shell) to re-authorize"
	}
	return err.Error()
}

// resetSubFlags returns every reusable command flag to its zero value so
// state from a previous shell command never leaks into the next one.
func resetSubFlags() {
	lsLong, lsTree = false, false
	downloadOut, downloadForce = "", false
	uploadTo = ""
	mkdirParents = false
	rmForce, rmRecursive = false, false
	shareTo, shareSlug = "", ""
	shareExpires, shareMaxDowns = 0, 0
	trashForce = false
}

// tokenize splits a command line into arguments, honoring single and
// double quotes so names with spaces ("New Folder") work.
func tokenize(line string) []string {
	var toks []string
	var cur strings.Builder
	inS, inD, has := false, false, false
	flush := func() {
		if has {
			toks = append(toks, cur.String())
			cur.Reset()
			has = false
		}
	}
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case c == '\'' && !inD:
			inS = !inS
			has = true
		case c == '"' && !inS:
			inD = !inD
			has = true
		case (c == ' ' || c == '\t') && !inS && !inD:
			flush()
		default:
			cur.WriteByte(c)
			has = true
		}
	}
	flush()
	return toks
}
