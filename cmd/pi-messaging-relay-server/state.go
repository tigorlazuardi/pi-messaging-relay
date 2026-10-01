package main

import (
	"errors"
	"fmt"
	"os"
	"sync"
)

type directorySync func(*os.File) error

type stateDirectory struct {
	path       string
	directory  *os.File
	parent     *os.File
	base       string
	temporary  bool
	closeOnce  sync.Once
	closeErr   error
	removeOnce sync.Once
	removeErr  error
}

func (state *stateDirectory) close() error {
	if state == nil {
		return nil
	}
	state.closeOnce.Do(func() {
		var directoryErr error
		if state.directory != nil {
			directoryErr = state.directory.Close()
			if directoryErr != nil {
				directoryErr = fmt.Errorf("close state directory: %w", directoryErr)
			}
		}
		var parentErr error
		if state.parent != nil {
			parentErr = state.parent.Close()
			if parentErr != nil {
				parentErr = fmt.Errorf("close state directory parent: %w", parentErr)
			}
		}
		state.closeErr = errors.Join(directoryErr, parentErr)
	})
	return state.closeErr
}
