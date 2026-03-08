// Copyright (c) VP.NET LLC. All rights reserved.
// Licensed under the MIT License.
// See LICENSE file in the project root for full license information.

package wgnet

import (
	"sync"
	"time"
)

var (
	nowVar   time.Time = time.Now()
	nowVarLk sync.RWMutex
)

func init() {
	go nowReader()
}

func nowReader() {
	t := time.NewTicker(100 * time.Millisecond)
	defer t.Stop()

	for n := range t.C {
		nowVarLk.Lock()
		nowVar = n
		nowVarLk.Unlock()
	}
}

// now returns the cached current time (updated every 100ms).
func now() time.Time {
	nowVarLk.RLock()
	defer nowVarLk.RUnlock()
	return nowVar
}
