// Code generated by go-swagger; DO NOT EDIT.

// Copyright Authors of Cilium
// SPDX-License-Identifier: Apache-2.0

package policy

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime/middleware"
)

// NewGetFqdnGccacheParams creates a new GetFqdnGccacheParams object
//
// There are no default values defined in the spec.
func NewGetFqdnGccacheParams() GetFqdnGccacheParams {

	return GetFqdnGccacheParams{}
}

// GetFqdnGccacheParams contains all the bound params for the get fqdn gccache operation
// typically these are obtained from a http.Request
//
// swagger:parameters GetFqdnGccache
type GetFqdnGccacheParams struct {

	// HTTP Request Object
	HTTPRequest *http.Request `json:"-"`
}

// BindRequest both binds and validates a request, it assumes that complex things implement a Validatable(strfmt.Registry) error interface
// for simple values it will use straight method calls.
//
// To ensure default values, the struct must have been initialized with NewGetFqdnGccacheParams() beforehand.
func (o *GetFqdnGccacheParams) BindRequest(r *http.Request, route *middleware.MatchedRoute) error {
	var res []error

	o.HTTPRequest = r

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
