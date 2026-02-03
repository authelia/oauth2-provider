package oauth2

import "time"

// NewRealClock returns a new RealClock.
func NewRealClock() *RealClock {
	return &RealClock{}
}

// RealClock is the implementation of a ClockProvider for production.
type RealClock struct{}

// Now returns the current local time.
func (RealClock) Now() time.Time {
	return time.Now()
}

// Until returns the duration until t. It is shorthand for t.Sub(time.Now()).
func (RealClock) Until(t time.Time) time.Duration {
	return time.Until(t)
}

// NewFixedClock returns a new clock with an initial time.
func NewFixedClock(t time.Time) *FixedClock {
	return &FixedClock{now: t}
}

// FixedClock implementation of ClockProvider for tests.
type FixedClock struct {
	now time.Time
}

// Now returns the current local time.
func (c *FixedClock) Now() time.Time {
	return c.now
}

// Until returns the duration until t. It is shorthand for t.Sub(time.Now()).
func (c *FixedClock) Until(t time.Time) time.Duration {
	return t.Sub(c.Now())
}

// Set the time of the clock.
func (c *FixedClock) Set(now time.Time) {
	c.now = now
}

// ClockProvider describes a type which provides clock functions.
type ClockProvider interface {
	Now() time.Time
	Until(t time.Time) time.Duration
}

var (
	_ ClockProvider = (*RealClock)(nil)
	_ ClockProvider = (*FixedClock)(nil)
)
