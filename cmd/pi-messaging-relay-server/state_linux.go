//go:build linux

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const temporaryStateAttempts = 100

func requireSupportedPlatform() error {
	return nil
}

func terminationSignals() []os.Signal {
	return []os.Signal{os.Interrupt, syscall.SIGTERM}
}

func syncOpenedDirectory(directory *os.File) error {
	return directory.Sync()
}

func prepareStateDirectoryWithSync(configured string, syncParent directorySync) (*stateDirectory, error) {
	if syncParent == nil {
		return nil, errors.New("state directory preparation requires a parent sync operation")
	}
	if configured != "" {
		return openTrustedStateDirectory(configured, false, syncParent)
	}

	parent := os.TempDir()
	for range temporaryStateAttempts {
		token, err := randomToken(12)
		if err != nil {
			return nil, fmt.Errorf("generate temporary state directory name: %w", err)
		}
		state, err := openTrustedStateDirectory(
			filepath.Join(parent, "pi-messaging-relay-"+token),
			true,
			syncParent,
		)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("create temporary state directory: %w", err)
		}
		state.temporary = true
		return state, nil
	}
	return nil, errors.New("create unique temporary state directory: collision limit reached")
}

func openTrustedStateDirectory(path string, requireCreation bool, syncParent directorySync) (_ *stateDirectory, returnErr error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve state directory: %w", err)
	}
	absolute = filepath.Clean(absolute)
	if absolute == string(filepath.Separator) {
		return nil, errors.New("state directory must not be the filesystem root")
	}
	components := strings.Split(strings.TrimPrefix(absolute, string(filepath.Separator)), string(filepath.Separator))
	if len(components) == 0 {
		return nil, errors.New("state directory path has no components")
	}

	rootFD, err := unix.Open(string(filepath.Separator), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open filesystem root: %w", err)
	}
	current := os.NewFile(uintptr(rootFD), string(filepath.Separator))
	if current == nil {
		_ = unix.Close(rootFD)
		return nil, errors.New("own filesystem root handle")
	}
	defer func() {
		if current != nil {
			returnErr = errors.Join(returnErr, current.Close())
		}
	}()
	if err := validateTrustedAncestor(current, string(filepath.Separator)); err != nil {
		return nil, err
	}

	for index, component := range components {
		if component == "" || component == "." || component == ".." {
			return nil, errors.New("state directory path contains an invalid component")
		}
		final := index == len(components)-1
		flags := unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
		childFD, openErr := unix.Openat(int(current.Fd()), component, flags, 0)
		created := false
		if final && errors.Is(openErr, unix.ENOENT) {
			if err := unix.Mkdirat(int(current.Fd()), component, 0o700); err != nil {
				return nil, fmt.Errorf("create state directory component %q: %w", component, err)
			}
			created = true
			childFD, openErr = unix.Openat(int(current.Fd()), component, flags, 0)
		}
		if openErr != nil {
			return nil, fmt.Errorf("open state directory component %q without symlinks: %w", component, openErr)
		}
		if final && requireCreation && !created {
			_ = unix.Close(childFD)
			return nil, os.ErrExist
		}
		childPath := filepath.Join(current.Name(), component)
		child := os.NewFile(uintptr(childFD), childPath)
		if child == nil {
			_ = unix.Close(childFD)
			return nil, fmt.Errorf("own state directory component %q handle", component)
		}
		if final {
			if err := validatePrivateStateDirectory(child); err != nil {
				closeErr := child.Close()
				if created {
					removeErr := unix.Unlinkat(int(current.Fd()), component, unix.AT_REMOVEDIR)
					return nil, errors.Join(err, closeErr, removeErr)
				}
				return nil, errors.Join(err, closeErr)
			}
			if created {
				if err := syncParent(current); err != nil {
					closeErr := child.Close()
					removeErr := unix.Unlinkat(int(current.Fd()), component, unix.AT_REMOVEDIR)
					return nil, errors.Join(
						fmt.Errorf("sync state directory parent: %w", err),
						closeErr,
						removeErr,
					)
				}
			}
			state := &stateDirectory{
				path:      absolute,
				directory: child,
				parent:    current,
				base:      component,
			}
			current = nil
			return state, nil
		}
		if err := validateTrustedAncestor(child, childPath); err != nil {
			return nil, errors.Join(err, child.Close())
		}
		if err := current.Close(); err != nil {
			return nil, errors.Join(fmt.Errorf("close state ancestor handle: %w", err), child.Close())
		}
		current = child
	}
	return nil, errors.New("state directory path traversal did not reach final component")
}

func validateTrustedAncestor(directory *os.File, path string) error {
	var status unix.Stat_t
	if err := unix.Fstat(int(directory.Fd()), &status); err != nil {
		return fmt.Errorf("inspect state ancestor %q: %w", path, err)
	}
	if status.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("state ancestor %q is not a directory", path)
	}
	currentUID := uint32(os.Geteuid())
	if status.Uid != 0 && status.Uid != currentUID {
		return fmt.Errorf("state ancestor %q must be owned by root or the current user", path)
	}
	attackerWritable := status.Mode&(unix.S_IWGRP|unix.S_IWOTH) != 0
	if attackerWritable && status.Mode&unix.S_ISVTX == 0 {
		return fmt.Errorf("state ancestor %q must not be group/other-writable without the sticky bit", path)
	}
	return nil
}

func validatePrivateStateDirectory(directory *os.File) error {
	var status unix.Stat_t
	if err := unix.Fstat(int(directory.Fd()), &status); err != nil {
		return fmt.Errorf("inspect opened state directory: %w", err)
	}
	if status.Mode&unix.S_IFMT != unix.S_IFDIR || status.Mode&0o777 != 0o700 {
		return errors.New("durable state directory must be a directory with permissions 0700")
	}
	if status.Uid != uint32(os.Geteuid()) {
		return errors.New("durable state directory must be owned by the current user")
	}
	return nil
}

// openStateChild opens one operator-owned state-directory child without following
// symlinks, through the retained state-directory handle, and validates the guarded
// regular-file form before the caller reads anything.
func (state *stateDirectory) openStateChild(name string) (*os.File, int64, error) {
	if state == nil || state.directory == nil {
		return nil, 0, errors.New("state directory handle is unavailable")
	}
	fd, err := unix.Openat(
		int(state.directory.Fd()),
		name,
		unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return nil, 0, err
	}
	file := os.NewFile(uintptr(fd), filepath.Join(state.path, name))
	if file == nil {
		_ = unix.Close(fd)
		return nil, 0, errors.New("own state-directory child handle")
	}
	status, err := validatePrivateRegularFile(file, name)
	if err != nil {
		return nil, 0, errors.Join(err, file.Close())
	}
	return file, status.Size, nil
}

func validatePrivateRegularFile(file *os.File, label string) (unix.Stat_t, error) {
	var status unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &status); err != nil {
		return unix.Stat_t{}, fmt.Errorf("inspect opened %s: %w", label, err)
	}
	if status.Mode&unix.S_IFMT != unix.S_IFREG || status.Mode&0o777 != 0o600 ||
		status.Uid != uint32(os.Geteuid()) {
		return unix.Stat_t{}, fmt.Errorf(
			"%s must be a current-user-owned regular file with permissions 0600",
			label,
		)
	}
	return status, nil
}

func (state *stateDirectory) removeTemporaryState() error {
	if state == nil || !state.temporary {
		return nil
	}
	state.removeOnce.Do(func() {
		var retained unix.Stat_t
		if err := unix.Fstat(int(state.directory.Fd()), &retained); err != nil {
			state.removeErr = fmt.Errorf("inspect retained temporary state directory: %w", err)
			return
		}
		currentFD, err := unix.Openat(
			int(state.parent.Fd()),
			state.base,
			unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
			0,
		)
		if err != nil {
			state.removeErr = fmt.Errorf("reopen temporary state directory from retained parent: %w", err)
			return
		}
		var current unix.Stat_t
		statErr := unix.Fstat(currentFD, &current)
		closeErr := unix.Close(currentFD)
		if statErr != nil || closeErr != nil {
			state.removeErr = errors.Join(statErr, closeErr)
			return
		}
		if retained.Dev != current.Dev || retained.Ino != current.Ino {
			state.removeErr = errors.New("temporary state directory path no longer names retained handle")
			return
		}

		names, err := state.directory.Readdirnames(-1)
		if err != nil {
			state.removeErr = fmt.Errorf("list temporary state directory: %w", err)
			return
		}
		for _, name := range names {
			if name == "" || name == "." || name == ".." || strings.ContainsRune(name, filepath.Separator) {
				state.removeErr = errors.New("temporary state directory contains an invalid entry name")
				return
			}
			if err := unix.Unlinkat(int(state.directory.Fd()), name, 0); err != nil {
				state.removeErr = fmt.Errorf("remove temporary state entry %q: %w", name, err)
				return
			}
		}
		if err := state.directory.Sync(); err != nil {
			state.removeErr = fmt.Errorf("sync emptied temporary state directory: %w", err)
			return
		}
		if err := unix.Unlinkat(int(state.parent.Fd()), state.base, unix.AT_REMOVEDIR); err != nil {
			state.removeErr = fmt.Errorf("remove temporary state directory: %w", err)
			return
		}
		if err := state.parent.Sync(); err != nil {
			state.removeErr = fmt.Errorf("sync temporary state directory parent: %w", err)
		}
	})
	return state.removeErr
}
