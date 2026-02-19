package wgnet

import "testing"

func TestSlidingWindowBasic(t *testing.T) {
	var sw SlidingWindow

	// Sequential counters should all pass.
	for i := uint64(0); i < 100; i++ {
		if sw.CheckReplay(i) {
			t.Fatalf("counter %d should not be a replay", i)
		}
	}
}

func TestSlidingWindowReplay(t *testing.T) {
	var sw SlidingWindow

	// First use should pass.
	if sw.CheckReplay(42) {
		t.Fatal("first use of counter 42 should not be a replay")
	}

	// Duplicate should be detected.
	if !sw.CheckReplay(42) {
		t.Fatal("duplicate counter 42 should be a replay")
	}
}

func TestSlidingWindowOld(t *testing.T) {
	var sw SlidingWindow

	// Advance the window by using a high counter.
	if sw.CheckReplay(WindowSize + 100) {
		t.Fatal("high counter should not be a replay")
	}

	// Counter 0 is now well below the window.
	if !sw.CheckReplay(0) {
		t.Fatal("counter 0 should be rejected as too old")
	}
}

func TestSlidingWindowAdvance(t *testing.T) {
	var sw SlidingWindow

	// Use counters 0-9.
	for i := uint64(0); i < 10; i++ {
		if sw.CheckReplay(i) {
			t.Fatalf("counter %d should not be a replay", i)
		}
	}

	// Jump far ahead to advance the window.
	far := uint64(WindowSize + 500)
	if sw.CheckReplay(far) {
		t.Fatalf("counter %d should not be a replay", far)
	}

	// Old counters should now be rejected.
	for i := uint64(0); i < 10; i++ {
		if !sw.CheckReplay(i) {
			t.Fatalf("counter %d should be rejected after window advance", i)
		}
	}

	// Counter just before far should still be within window if not too old.
	nearFar := far - 1
	if sw.CheckReplay(nearFar) {
		t.Fatalf("counter %d should be accepted (within window)", nearFar)
	}
}

func TestSlidingWindowOutOfOrder(t *testing.T) {
	var sw SlidingWindow

	// Use counter 200 first. This sets position = 200 - (200%64) = 192.
	if sw.CheckReplay(200) {
		t.Fatal("counter 200 should not be a replay")
	}

	// Use counter 195 (within window, >= position, out of order).
	if sw.CheckReplay(195) {
		t.Fatal("counter 195 should be accepted (within window)")
	}

	// Use counter 192 (at the window start boundary, out of order).
	if sw.CheckReplay(192) {
		t.Fatal("counter 192 should be accepted (within window)")
	}

	// Use counter 195 again (should be replay).
	if !sw.CheckReplay(195) {
		t.Fatal("duplicate counter 195 should be a replay")
	}

	// Use counter 192 again (should be replay).
	if !sw.CheckReplay(192) {
		t.Fatal("duplicate counter 192 should be a replay")
	}
}

func TestSlidingWindowLargeJump(t *testing.T) {
	var sw SlidingWindow

	// Use some initial counters.
	for i := uint64(0); i < 5; i++ {
		sw.CheckReplay(i)
	}

	// Jump by exactly WindowSize — this should reset the bitmap.
	jump := uint64(WindowSize) + 4
	if sw.CheckReplay(jump) {
		t.Fatalf("counter %d should not be a replay after large jump", jump)
	}

	// Duplicate of the jumped counter should be detected.
	if !sw.CheckReplay(jump) {
		t.Fatal("duplicate of jumped counter should be detected")
	}

	// Counter just after the jump should work.
	if sw.CheckReplay(jump + 1) {
		t.Fatal("counter after jump should not be a replay")
	}
}

func TestSlidingWindowReset(t *testing.T) {
	var sw SlidingWindow

	sw.CheckReplay(42)
	sw.Reset()

	// After reset, 42 should be accepted again.
	if sw.CheckReplay(42) {
		t.Fatal("counter 42 should be accepted after Reset")
	}
}
