// Code generated by go-swagger; DO NOT EDIT.

// Copyright Authors of Cilium
// SPDX-License-Identifier: Apache-2.0

package bgp

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cilium/cilium/api/v1/models"
)

// GetBgpRoutesReader is a Reader for the GetBgpRoutes structure.
type GetBgpRoutesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetBgpRoutesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetBgpRoutesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 500:
		result := NewGetBgpRoutesInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewGetBgpRoutesOK creates a GetBgpRoutesOK with default headers values
func NewGetBgpRoutesOK() *GetBgpRoutesOK {
	return &GetBgpRoutesOK{}
}

/*
GetBgpRoutesOK describes a response with status code 200, with default header values.

Success
*/
type GetBgpRoutesOK struct {
	Payload []*models.BgpRoute
}

// IsSuccess returns true when this get bgp routes o k response has a 2xx status code
func (o *GetBgpRoutesOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get bgp routes o k response has a 3xx status code
func (o *GetBgpRoutesOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get bgp routes o k response has a 4xx status code
func (o *GetBgpRoutesOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get bgp routes o k response has a 5xx status code
func (o *GetBgpRoutesOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get bgp routes o k response a status code equal to that given
func (o *GetBgpRoutesOK) IsCode(code int) bool {
	return code == 200
}

func (o *GetBgpRoutesOK) Error() string {
	return fmt.Sprintf("[GET /bgp/routes][%d] getBgpRoutesOK  %+v", 200, o.Payload)
}

func (o *GetBgpRoutesOK) String() string {
	return fmt.Sprintf("[GET /bgp/routes][%d] getBgpRoutesOK  %+v", 200, o.Payload)
}

func (o *GetBgpRoutesOK) GetPayload() []*models.BgpRoute {
	return o.Payload
}

func (o *GetBgpRoutesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetBgpRoutesInternalServerError creates a GetBgpRoutesInternalServerError with default headers values
func NewGetBgpRoutesInternalServerError() *GetBgpRoutesInternalServerError {
	return &GetBgpRoutesInternalServerError{}
}

/*
GetBgpRoutesInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type GetBgpRoutesInternalServerError struct {
	Payload models.Error
}

// IsSuccess returns true when this get bgp routes internal server error response has a 2xx status code
func (o *GetBgpRoutesInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get bgp routes internal server error response has a 3xx status code
func (o *GetBgpRoutesInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get bgp routes internal server error response has a 4xx status code
func (o *GetBgpRoutesInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this get bgp routes internal server error response has a 5xx status code
func (o *GetBgpRoutesInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this get bgp routes internal server error response a status code equal to that given
func (o *GetBgpRoutesInternalServerError) IsCode(code int) bool {
	return code == 500
}

func (o *GetBgpRoutesInternalServerError) Error() string {
	return fmt.Sprintf("[GET /bgp/routes][%d] getBgpRoutesInternalServerError  %+v", 500, o.Payload)
}

func (o *GetBgpRoutesInternalServerError) String() string {
	return fmt.Sprintf("[GET /bgp/routes][%d] getBgpRoutesInternalServerError  %+v", 500, o.Payload)
}

func (o *GetBgpRoutesInternalServerError) GetPayload() models.Error {
	return o.Payload
}

func (o *GetBgpRoutesInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
