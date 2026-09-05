package cmd

import "fmt"

// Error exit codes live outside the 0-4 verdict range so a pipeline can
// never mistake a crash or a typo for "widened" or "narrowed". They follow
// BSD sysexits: 64 for a bad command line, 70 for a failure at run time.
const (
	ExitUsage   = 64
	ExitRuntime = 70
)

// exitError carries a process exit code out of a cobra RunE. A nil err
// with a non-zero code is a verdict exit: nothing is printed, the code is
// the whole message.
type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string {
	if e.err != nil {
		return e.err.Error()
	}
	return fmt.Sprintf("exit %d", e.code)
}

func (e *exitError) Unwrap() error { return e.err }

// verdictExit converts a diff exit code into an error the executor maps
// back to a process exit code. Zero is not an error.
func verdictExit(code int) error {
	if code == 0 {
		return nil
	}
	return &exitError{code: code}
}

func runtimeErr(err error) error {
	return &exitError{code: ExitRuntime, err: err}
}

func usageErr(format string, args ...any) error {
	return &exitError{code: ExitUsage, err: fmt.Errorf(format, args...)}
}
