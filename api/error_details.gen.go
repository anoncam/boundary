// Code generated by "make api"; DO NOT EDIT.
package api

type ErrorDetails struct {
	RequestFields []*FieldError   `json:"request_fields,omitempty"`
	WrappedErrors []*WrappedError `json:"wrapped_errors,omitempty"`
}
