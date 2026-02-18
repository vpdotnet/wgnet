// Copyright (c) VP.NET LLC. All rights reserved.
// Licensed under the MIT License.
// See LICENSE file in the project root for full license information.

package wgnet

import (
	"sync"
	"sync/atomic"
	"time"
)

var (
	nowVar   time.Time = time.Now()
	nowVarLk sync.RWMutex
	nowUint  uint32
)

func init() {
	go nowReader()
}

func nowReader() {
	t := time.NewTicker(100 * time.Millisecond)
	defer t.Stop()

	x := 0
	for n := range t.C {
		nowVarLk.Lock()
		nowVar = n
		nowVarLk.Unlock()

		x++
		if x >= 10 {
			atomic.AddUint32(&nowUint, 1)
			x = 0
		}
	}
}

// now returns the cached current time (updated every 100ms).
func now() time.Time {
	nowVarLk.RLock()
	defer nowVarLk.RUnlock()
	return nowVar
}

// now32 returns an incrementing counter (~1 per second) without locks.
func now32() uint32 {
	return atomic.LoadUint32(&nowUint)
}
