package cmd

// Version is stamped at build time:
//
//	go build -ldflags "-X github.com/krishnaduttPanchagnula/actionscan/cmd.Version=v1.2.3"
//
// Without it the released binary carries no version at all.
var Version = "dev"

// Commit and Date are the build metadata, stamped the same way.
var (
	Commit = "none"
	Date   = "unknown"
)
