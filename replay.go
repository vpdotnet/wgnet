// Copyright (c) VP.NET LLC. All rights reserved.
// Licensed under the MIT License.
// See LICENSE file in the project root for full license information.

package wgnet

import "sync"

// SlidingWindow implements replay protection using a bitmap-based sliding window.
// It tracks which packet counters have been seen to detect duplicates.
type SlidingWindow struct {
	bitmap      [WindowSize / 64]uint64
	position    uint64 // position at start of bitmap (multiple of 64)
	offset      uint64 // offset within bitmap array (ring buffer offset)
	mutex       sync.Mutex
	initialized bool
}

// CheckReplay checks if a packet counter has been seen before.
// Returns true if the counter is a replay (already seen or too old).
// Automatically marks the counter as seen if it is new.
func (sw *SlidingWindow) CheckReplay(counter uint64) bool {
	sw.mutex.Lock()
	defer sw.mutex.Unlock()

	if !sw.initialized {
		sw.position = counter - (counter % 64)
		sw.offset = 0
		sw.initialized = true
		for n := range sw.bitmap {
			sw.bitmap[n] = 0
		}
	}

	// Counter too old
	if counter < sw.position {
		return true
	}

	// Counter outside window, advance
	if counter >= sw.position+WindowSize {
		diff := counter - (sw.position + WindowSize) + 1
		if n := diff % 64; n != 0 {
			diff += 64 - n
		}

		sw.position += diff

		if diff >= WindowSize {
			for i := range sw.bitmap {
				sw.bitmap[i] = 0
			}
			sw.offset = 0
		} else {
			wordShift := diff / 64
			bitmapWords := uint64(len(sw.bitmap))

			newOffset := (sw.offset + wordShift) % bitmapWords

			for i := uint64(0); i < wordShift; i++ {
				sw.bitmap[(newOffset+bitmapWords-1-i)%bitmapWords] = 0
			}

			sw.offset = newOffset
		}

		newPos := counter - sw.position
		newWordIndex := (sw.offset + newPos/64) % uint64(len(sw.bitmap))
		newBitIndex := newPos % 64
		sw.bitmap[newWordIndex] |= uint64(1) << newBitIndex

		return false
	}

	// Counter within window, check bitmap
	pos := counter - sw.position
	wordIndex := (sw.offset + pos/64) % uint64(len(sw.bitmap))
	bitIndex := pos % 64

	mask := uint64(1) << bitIndex
	if (sw.bitmap[wordIndex] & mask) != 0 {
		return true
	}

	sw.bitmap[wordIndex] |= mask
	return false
}

// Reset resets the sliding window, clearing all state.
func (sw *SlidingWindow) Reset() {
	sw.mutex.Lock()
	defer sw.mutex.Unlock()
	sw.initialized = false
}
