// Code generated by ogen, DO NOT EDIT.

package sp

import (
	"io"
	"net/url"
)

// AuthFound is response for Auth operation.
type AuthFound struct {
	Location  OptURI
	SetCookie OptString
}

// GetLocation returns the value of Location.
func (s *AuthFound) GetLocation() OptURI {
	return s.Location
}

// GetSetCookie returns the value of SetCookie.
func (s *AuthFound) GetSetCookie() OptString {
	return s.SetCookie
}

// SetLocation sets the value of Location.
func (s *AuthFound) SetLocation(val OptURI) {
	s.Location = val
}

// SetSetCookie sets the value of SetCookie.
func (s *AuthFound) SetSetCookie(val OptString) {
	s.SetCookie = val
}

func (*AuthFound) authRes() {}

// AuthInternalServerError is response for Auth operation.
type AuthInternalServerError struct{}

func (*AuthInternalServerError) authRes() {}

// CallbackInternalServerError is response for Callback operation.
type CallbackInternalServerError struct{}

func (*CallbackInternalServerError) callbackRes() {}

type CallbackOK struct {
	Data io.Reader
}

// Read reads data from the Data reader.
//
// Kept to satisfy the io.Reader interface.
func (s CallbackOK) Read(p []byte) (n int, err error) {
	if s.Data == nil {
		return 0, io.EOF
	}
	return s.Data.Read(p)
}

// CallbackOKHeaders wraps CallbackOK with response headers.
type CallbackOKHeaders struct {
	SetCookie OptString
	Response  CallbackOK
}

// GetSetCookie returns the value of SetCookie.
func (s *CallbackOKHeaders) GetSetCookie() OptString {
	return s.SetCookie
}

// GetResponse returns the value of Response.
func (s *CallbackOKHeaders) GetResponse() CallbackOK {
	return s.Response
}

// SetSetCookie sets the value of SetCookie.
func (s *CallbackOKHeaders) SetSetCookie(val OptString) {
	s.SetCookie = val
}

// SetResponse sets the value of Response.
func (s *CallbackOKHeaders) SetResponse(val CallbackOK) {
	s.Response = val
}

func (*CallbackOKHeaders) callbackRes() {}

// IndexInternalServerError is response for Index operation.
type IndexInternalServerError struct{}

func (*IndexInternalServerError) indexRes() {}

type IndexOK struct {
	Data io.Reader
}

// Read reads data from the Data reader.
//
// Kept to satisfy the io.Reader interface.
func (s IndexOK) Read(p []byte) (n int, err error) {
	if s.Data == nil {
		return 0, io.EOF
	}
	return s.Data.Read(p)
}

func (*IndexOK) indexRes() {}

// NewOptString returns new OptString with value set to v.
func NewOptString(v string) OptString {
	return OptString{
		Value: v,
		Set:   true,
	}
}

// OptString is optional string.
type OptString struct {
	Value string
	Set   bool
}

// IsSet returns true if OptString was set.
func (o OptString) IsSet() bool { return o.Set }

// Reset unsets value.
func (o *OptString) Reset() {
	var v string
	o.Value = v
	o.Set = false
}

// SetTo sets value to v.
func (o *OptString) SetTo(v string) {
	o.Set = true
	o.Value = v
}

// Get returns value and boolean that denotes whether value was set.
func (o OptString) Get() (v string, ok bool) {
	if !o.Set {
		return v, false
	}
	return o.Value, true
}

// Or returns value if set, or given parameter if does not.
func (o OptString) Or(d string) string {
	if v, ok := o.Get(); ok {
		return v
	}
	return d
}

// NewOptURI returns new OptURI with value set to v.
func NewOptURI(v url.URL) OptURI {
	return OptURI{
		Value: v,
		Set:   true,
	}
}

// OptURI is optional url.URL.
type OptURI struct {
	Value url.URL
	Set   bool
}

// IsSet returns true if OptURI was set.
func (o OptURI) IsSet() bool { return o.Set }

// Reset unsets value.
func (o *OptURI) Reset() {
	var v url.URL
	o.Value = v
	o.Set = false
}

// SetTo sets value to v.
func (o *OptURI) SetTo(v url.URL) {
	o.Set = true
	o.Value = v
}

// Get returns value and boolean that denotes whether value was set.
func (o OptURI) Get() (v url.URL, ok bool) {
	if !o.Set {
		return v, false
	}
	return o.Value, true
}

// Or returns value if set, or given parameter if does not.
func (o OptURI) Or(d url.URL) url.URL {
	if v, ok := o.Get(); ok {
		return v
	}
	return d
}
