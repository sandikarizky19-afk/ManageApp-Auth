package utils

import "fmt"

// AppError represents an application-level error
// that can be translated into an HTTP response.
type AppError struct {
	Code    int
	Message string
	Err     error
}

// Error implements the error interface.
func (e AppError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}

	return e.Message
}

// Unwrap allows errors.Is and errors.As to inspect the underlying error.
func (e AppError) Unwrap() error {
	return e.Err
}