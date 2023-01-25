package logging

import "testing"

type testWriter struct {
	s []string
}

func (t *testWriter) Write(p []byte) (n int, err error) {
	t.s = append(t.s, string(p))
	return len(p), nil
}

func TestLevelNone(t *testing.T) {
	tw := &testWriter{}
	Initialize(LevelNone, tw, tw)
	Error("bla")
	Errorf("bla")
	Warning("bla")
	Warningf("bla")
	Info("bla")
	Infof("bla")
	Debug("bla")
	Debugf("bla")

	if len(tw.s) != 0 {
		t.Fatalf("expected log to be empty, but it is '%v'", tw.s)
	}
}

func TestLevelError(t *testing.T) {
	tw := &testWriter{}
	Initialize(LevelError, tw, tw)
	Error("bla")
	Errorf("bla")
	Warning("bla")
	Warningf("bla")
	Info("bla")
	Infof("bla")
	Debug("bla")
	Debugf("bla")

	if len(tw.s) != 2 {
		t.Fatalf("expected log to contain 2 lines, but it is '%v'", tw.s)
	}
}

func TestLevelWarning(t *testing.T) {
	tw := &testWriter{}
	Initialize(LevelWarning, tw, tw)
	Error("bla")
	Errorf("bla")
	Warning("bla")
	Warningf("bla")
	Info("bla")
	Infof("bla")
	Debug("bla")
	Debugf("bla")

	if len(tw.s) != 4 {
		t.Fatalf("expected log to contain 4 lines, but it is '%v'", tw.s)
	}
}

func TestLevelInfo(t *testing.T) {
	tw := &testWriter{}
	Initialize(LevelInfo, tw, tw)
	Error("bla")
	Errorf("bla")
	Warning("bla")
	Warningf("bla")
	Info("bla")
	Infof("bla")
	Debug("bla")
	Debugf("bla")

	if len(tw.s) != 6 {
		t.Fatalf("expected log to contain 6 lines, but it is '%v'", tw.s)
	}
}

func TestLevelDebug(t *testing.T) {
	tw := &testWriter{}
	Initialize(LevelDebug, tw, tw)
	Error("bla")
	Errorf("bla")
	Warning("bla")
	Warningf("bla")
	Info("bla")
	Infof("bla")
	Debug("bla")
	Debugf("bla")

	if len(tw.s) != 8 {
		t.Fatalf("expected log to contain 8 lines, but it is '%v'", tw.s)
	}
}
