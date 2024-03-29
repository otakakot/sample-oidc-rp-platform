// Code generated by ogen, DO NOT EDIT.

package rp

import (
	"net/url"
)

// BeginFound is response for Begin operation.
type BeginFound struct {
	Location  OptURI
	SetCookie OptString
}

// GetLocation returns the value of Location.
func (s *BeginFound) GetLocation() OptURI {
	return s.Location
}

// GetSetCookie returns the value of SetCookie.
func (s *BeginFound) GetSetCookie() OptString {
	return s.SetCookie
}

// SetLocation sets the value of Location.
func (s *BeginFound) SetLocation(val OptURI) {
	s.Location = val
}

// SetSetCookie sets the value of SetCookie.
func (s *BeginFound) SetSetCookie(val OptString) {
	s.SetCookie = val
}

func (*BeginFound) beginRes() {}

// BeginInternalServerError is response for Begin operation.
type BeginInternalServerError struct{}

func (*BeginInternalServerError) beginRes() {}

// CallbackFound is response for Callback operation.
type CallbackFound struct {
	Location  OptURI
	SetCookie OptString
}

// GetLocation returns the value of Location.
func (s *CallbackFound) GetLocation() OptURI {
	return s.Location
}

// GetSetCookie returns the value of SetCookie.
func (s *CallbackFound) GetSetCookie() OptString {
	return s.SetCookie
}

// SetLocation sets the value of Location.
func (s *CallbackFound) SetLocation(val OptURI) {
	s.Location = val
}

// SetSetCookie sets the value of SetCookie.
func (s *CallbackFound) SetSetCookie(val OptString) {
	s.SetCookie = val
}

func (*CallbackFound) callbackRes() {}

// CallbackInternalServerError is response for Callback operation.
type CallbackInternalServerError struct{}

func (*CallbackInternalServerError) callbackRes() {}

// EndInternalServerError is response for End operation.
type EndInternalServerError struct{}

func (*EndInternalServerError) endRes() {}

type EndOK struct {
	AcceesToken  string `json:"accees_token"`
	RefreshToken string `json:"refresh_token"`
}

// GetAcceesToken returns the value of AcceesToken.
func (s *EndOK) GetAcceesToken() string {
	return s.AcceesToken
}

// GetRefreshToken returns the value of RefreshToken.
func (s *EndOK) GetRefreshToken() string {
	return s.RefreshToken
}

// SetAcceesToken sets the value of AcceesToken.
func (s *EndOK) SetAcceesToken(val string) {
	s.AcceesToken = val
}

// SetRefreshToken sets the value of RefreshToken.
func (s *EndOK) SetRefreshToken(val string) {
	s.RefreshToken = val
}

func (*EndOK) endRes() {}

type EndReq struct {
	State string `json:"state"`
}

// GetState returns the value of State.
func (s *EndReq) GetState() string {
	return s.State
}

// SetState sets the value of State.
func (s *EndReq) SetState(val string) {
	s.State = val
}

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
