// Code generated by protoc-gen-validate. DO NOT EDIT.
// source: envoy/extensions/filters/http/ext_proc/v3/ext_proc.proto

package ext_procv3

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"google.golang.org/protobuf/types/known/anypb"
)

// ensure the imports are used
var (
	_ = bytes.MinRead
	_ = errors.New("")
	_ = fmt.Print
	_ = utf8.UTFMax
	_ = (*regexp.Regexp)(nil)
	_ = (*strings.Reader)(nil)
	_ = net.IPv4len
	_ = time.Duration(0)
	_ = (*url.URL)(nil)
	_ = (*mail.Address)(nil)
	_ = anypb.Any{}
	_ = sort.Sort
)

// Validate checks the field values on ExternalProcessor with the rules defined
// in the proto definition for this message. If any rules are violated, the
// first error encountered is returned, or nil if there are no violations.
func (m *ExternalProcessor) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on ExternalProcessor with the rules
// defined in the proto definition for this message. If any rules are
// violated, the result is a list of violation errors wrapped in
// ExternalProcessorMultiError, or nil if none found.
func (m *ExternalProcessor) ValidateAll() error {
	return m.validate(true)
}

func (m *ExternalProcessor) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	if m.GetGrpcService() == nil {
		err := ExternalProcessorValidationError{
			field:  "GrpcService",
			reason: "value is required",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	if all {
		switch v := interface{}(m.GetGrpcService()).(type) {
		case interface{ ValidateAll() error }:
			if err := v.ValidateAll(); err != nil {
				errors = append(errors, ExternalProcessorValidationError{
					field:  "GrpcService",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		case interface{ Validate() error }:
			if err := v.Validate(); err != nil {
				errors = append(errors, ExternalProcessorValidationError{
					field:  "GrpcService",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		}
	} else if v, ok := interface{}(m.GetGrpcService()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return ExternalProcessorValidationError{
				field:  "GrpcService",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	// no validation rules for FailureModeAllow

	if all {
		switch v := interface{}(m.GetProcessingMode()).(type) {
		case interface{ ValidateAll() error }:
			if err := v.ValidateAll(); err != nil {
				errors = append(errors, ExternalProcessorValidationError{
					field:  "ProcessingMode",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		case interface{ Validate() error }:
			if err := v.Validate(); err != nil {
				errors = append(errors, ExternalProcessorValidationError{
					field:  "ProcessingMode",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		}
	} else if v, ok := interface{}(m.GetProcessingMode()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return ExternalProcessorValidationError{
				field:  "ProcessingMode",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	if d := m.GetMessageTimeout(); d != nil {
		dur, err := d.AsDuration(), d.CheckValid()
		if err != nil {
			err = ExternalProcessorValidationError{
				field:  "MessageTimeout",
				reason: "value is not a valid duration",
				cause:  err,
			}
			if !all {
				return err
			}
			errors = append(errors, err)
		} else {

			lte := time.Duration(3600*time.Second + 0*time.Nanosecond)
			gte := time.Duration(0*time.Second + 0*time.Nanosecond)

			if dur < gte || dur > lte {
				err := ExternalProcessorValidationError{
					field:  "MessageTimeout",
					reason: "value must be inside range [0s, 1h0m0s]",
				}
				if !all {
					return err
				}
				errors = append(errors, err)
			}

		}
	}

	// no validation rules for StatPrefix

	if all {
		switch v := interface{}(m.GetMutationRules()).(type) {
		case interface{ ValidateAll() error }:
			if err := v.ValidateAll(); err != nil {
				errors = append(errors, ExternalProcessorValidationError{
					field:  "MutationRules",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		case interface{ Validate() error }:
			if err := v.Validate(); err != nil {
				errors = append(errors, ExternalProcessorValidationError{
					field:  "MutationRules",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		}
	} else if v, ok := interface{}(m.GetMutationRules()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return ExternalProcessorValidationError{
				field:  "MutationRules",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	if d := m.GetMaxMessageTimeout(); d != nil {
		dur, err := d.AsDuration(), d.CheckValid()
		if err != nil {
			err = ExternalProcessorValidationError{
				field:  "MaxMessageTimeout",
				reason: "value is not a valid duration",
				cause:  err,
			}
			if !all {
				return err
			}
			errors = append(errors, err)
		} else {

			lte := time.Duration(3600*time.Second + 0*time.Nanosecond)
			gte := time.Duration(0*time.Second + 0*time.Nanosecond)

			if dur < gte || dur > lte {
				err := ExternalProcessorValidationError{
					field:  "MaxMessageTimeout",
					reason: "value must be inside range [0s, 1h0m0s]",
				}
				if !all {
					return err
				}
				errors = append(errors, err)
			}

		}
	}

	// no validation rules for DisableClearRouteCache

	if all {
		switch v := interface{}(m.GetForwardRules()).(type) {
		case interface{ ValidateAll() error }:
			if err := v.ValidateAll(); err != nil {
				errors = append(errors, ExternalProcessorValidationError{
					field:  "ForwardRules",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		case interface{ Validate() error }:
			if err := v.Validate(); err != nil {
				errors = append(errors, ExternalProcessorValidationError{
					field:  "ForwardRules",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		}
	} else if v, ok := interface{}(m.GetForwardRules()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return ExternalProcessorValidationError{
				field:  "ForwardRules",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	if all {
		switch v := interface{}(m.GetFilterMetadata()).(type) {
		case interface{ ValidateAll() error }:
			if err := v.ValidateAll(); err != nil {
				errors = append(errors, ExternalProcessorValidationError{
					field:  "FilterMetadata",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		case interface{ Validate() error }:
			if err := v.Validate(); err != nil {
				errors = append(errors, ExternalProcessorValidationError{
					field:  "FilterMetadata",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		}
	} else if v, ok := interface{}(m.GetFilterMetadata()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return ExternalProcessorValidationError{
				field:  "FilterMetadata",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	// no validation rules for AllowModeOverride

	// no validation rules for DisableImmediateResponse

	if all {
		switch v := interface{}(m.GetMetadataOptions()).(type) {
		case interface{ ValidateAll() error }:
			if err := v.ValidateAll(); err != nil {
				errors = append(errors, ExternalProcessorValidationError{
					field:  "MetadataOptions",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		case interface{ Validate() error }:
			if err := v.Validate(); err != nil {
				errors = append(errors, ExternalProcessorValidationError{
					field:  "MetadataOptions",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		}
	} else if v, ok := interface{}(m.GetMetadataOptions()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return ExternalProcessorValidationError{
				field:  "MetadataOptions",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	// no validation rules for ObservabilityMode

	if len(errors) > 0 {
		return ExternalProcessorMultiError(errors)
	}

	return nil
}

// ExternalProcessorMultiError is an error wrapping multiple validation errors
// returned by ExternalProcessor.ValidateAll() if the designated constraints
// aren't met.
type ExternalProcessorMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m ExternalProcessorMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m ExternalProcessorMultiError) AllErrors() []error { return m }

// ExternalProcessorValidationError is the validation error returned by
// ExternalProcessor.Validate if the designated constraints aren't met.
type ExternalProcessorValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e ExternalProcessorValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e ExternalProcessorValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e ExternalProcessorValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e ExternalProcessorValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e ExternalProcessorValidationError) ErrorName() string {
	return "ExternalProcessorValidationError"
}

// Error satisfies the builtin error interface
func (e ExternalProcessorValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sExternalProcessor.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = ExternalProcessorValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = ExternalProcessorValidationError{}

// Validate checks the field values on MetadataOptions with the rules defined
// in the proto definition for this message. If any rules are violated, the
// first error encountered is returned, or nil if there are no violations.
func (m *MetadataOptions) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on MetadataOptions with the rules
// defined in the proto definition for this message. If any rules are
// violated, the result is a list of violation errors wrapped in
// MetadataOptionsMultiError, or nil if none found.
func (m *MetadataOptions) ValidateAll() error {
	return m.validate(true)
}

func (m *MetadataOptions) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	if all {
		switch v := interface{}(m.GetForwardingNamespaces()).(type) {
		case interface{ ValidateAll() error }:
			if err := v.ValidateAll(); err != nil {
				errors = append(errors, MetadataOptionsValidationError{
					field:  "ForwardingNamespaces",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		case interface{ Validate() error }:
			if err := v.Validate(); err != nil {
				errors = append(errors, MetadataOptionsValidationError{
					field:  "ForwardingNamespaces",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		}
	} else if v, ok := interface{}(m.GetForwardingNamespaces()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return MetadataOptionsValidationError{
				field:  "ForwardingNamespaces",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	if all {
		switch v := interface{}(m.GetReceivingNamespaces()).(type) {
		case interface{ ValidateAll() error }:
			if err := v.ValidateAll(); err != nil {
				errors = append(errors, MetadataOptionsValidationError{
					field:  "ReceivingNamespaces",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		case interface{ Validate() error }:
			if err := v.Validate(); err != nil {
				errors = append(errors, MetadataOptionsValidationError{
					field:  "ReceivingNamespaces",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		}
	} else if v, ok := interface{}(m.GetReceivingNamespaces()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return MetadataOptionsValidationError{
				field:  "ReceivingNamespaces",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	if len(errors) > 0 {
		return MetadataOptionsMultiError(errors)
	}

	return nil
}

// MetadataOptionsMultiError is an error wrapping multiple validation errors
// returned by MetadataOptions.ValidateAll() if the designated constraints
// aren't met.
type MetadataOptionsMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m MetadataOptionsMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m MetadataOptionsMultiError) AllErrors() []error { return m }

// MetadataOptionsValidationError is the validation error returned by
// MetadataOptions.Validate if the designated constraints aren't met.
type MetadataOptionsValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e MetadataOptionsValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e MetadataOptionsValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e MetadataOptionsValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e MetadataOptionsValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e MetadataOptionsValidationError) ErrorName() string { return "MetadataOptionsValidationError" }

// Error satisfies the builtin error interface
func (e MetadataOptionsValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sMetadataOptions.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = MetadataOptionsValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = MetadataOptionsValidationError{}

// Validate checks the field values on HeaderForwardingRules with the rules
// defined in the proto definition for this message. If any rules are
// violated, the first error encountered is returned, or nil if there are no violations.
func (m *HeaderForwardingRules) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on HeaderForwardingRules with the rules
// defined in the proto definition for this message. If any rules are
// violated, the result is a list of violation errors wrapped in
// HeaderForwardingRulesMultiError, or nil if none found.
func (m *HeaderForwardingRules) ValidateAll() error {
	return m.validate(true)
}

func (m *HeaderForwardingRules) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	if all {
		switch v := interface{}(m.GetAllowedHeaders()).(type) {
		case interface{ ValidateAll() error }:
			if err := v.ValidateAll(); err != nil {
				errors = append(errors, HeaderForwardingRulesValidationError{
					field:  "AllowedHeaders",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		case interface{ Validate() error }:
			if err := v.Validate(); err != nil {
				errors = append(errors, HeaderForwardingRulesValidationError{
					field:  "AllowedHeaders",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		}
	} else if v, ok := interface{}(m.GetAllowedHeaders()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return HeaderForwardingRulesValidationError{
				field:  "AllowedHeaders",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	if all {
		switch v := interface{}(m.GetDisallowedHeaders()).(type) {
		case interface{ ValidateAll() error }:
			if err := v.ValidateAll(); err != nil {
				errors = append(errors, HeaderForwardingRulesValidationError{
					field:  "DisallowedHeaders",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		case interface{ Validate() error }:
			if err := v.Validate(); err != nil {
				errors = append(errors, HeaderForwardingRulesValidationError{
					field:  "DisallowedHeaders",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		}
	} else if v, ok := interface{}(m.GetDisallowedHeaders()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return HeaderForwardingRulesValidationError{
				field:  "DisallowedHeaders",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	if len(errors) > 0 {
		return HeaderForwardingRulesMultiError(errors)
	}

	return nil
}

// HeaderForwardingRulesMultiError is an error wrapping multiple validation
// errors returned by HeaderForwardingRules.ValidateAll() if the designated
// constraints aren't met.
type HeaderForwardingRulesMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m HeaderForwardingRulesMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m HeaderForwardingRulesMultiError) AllErrors() []error { return m }

// HeaderForwardingRulesValidationError is the validation error returned by
// HeaderForwardingRules.Validate if the designated constraints aren't met.
type HeaderForwardingRulesValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e HeaderForwardingRulesValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e HeaderForwardingRulesValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e HeaderForwardingRulesValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e HeaderForwardingRulesValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e HeaderForwardingRulesValidationError) ErrorName() string {
	return "HeaderForwardingRulesValidationError"
}

// Error satisfies the builtin error interface
func (e HeaderForwardingRulesValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sHeaderForwardingRules.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = HeaderForwardingRulesValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = HeaderForwardingRulesValidationError{}

// Validate checks the field values on ExtProcPerRoute with the rules defined
// in the proto definition for this message. If any rules are violated, the
// first error encountered is returned, or nil if there are no violations.
func (m *ExtProcPerRoute) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on ExtProcPerRoute with the rules
// defined in the proto definition for this message. If any rules are
// violated, the result is a list of violation errors wrapped in
// ExtProcPerRouteMultiError, or nil if none found.
func (m *ExtProcPerRoute) ValidateAll() error {
	return m.validate(true)
}

func (m *ExtProcPerRoute) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	oneofOverridePresent := false
	switch v := m.Override.(type) {
	case *ExtProcPerRoute_Disabled:
		if v == nil {
			err := ExtProcPerRouteValidationError{
				field:  "Override",
				reason: "oneof value cannot be a typed-nil",
			}
			if !all {
				return err
			}
			errors = append(errors, err)
		}
		oneofOverridePresent = true

		if m.GetDisabled() != true {
			err := ExtProcPerRouteValidationError{
				field:  "Disabled",
				reason: "value must equal true",
			}
			if !all {
				return err
			}
			errors = append(errors, err)
		}

	case *ExtProcPerRoute_Overrides:
		if v == nil {
			err := ExtProcPerRouteValidationError{
				field:  "Override",
				reason: "oneof value cannot be a typed-nil",
			}
			if !all {
				return err
			}
			errors = append(errors, err)
		}
		oneofOverridePresent = true

		if all {
			switch v := interface{}(m.GetOverrides()).(type) {
			case interface{ ValidateAll() error }:
				if err := v.ValidateAll(); err != nil {
					errors = append(errors, ExtProcPerRouteValidationError{
						field:  "Overrides",
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			case interface{ Validate() error }:
				if err := v.Validate(); err != nil {
					errors = append(errors, ExtProcPerRouteValidationError{
						field:  "Overrides",
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			}
		} else if v, ok := interface{}(m.GetOverrides()).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return ExtProcPerRouteValidationError{
					field:  "Overrides",
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	default:
		_ = v // ensures v is used
	}
	if !oneofOverridePresent {
		err := ExtProcPerRouteValidationError{
			field:  "Override",
			reason: "value is required",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	if len(errors) > 0 {
		return ExtProcPerRouteMultiError(errors)
	}

	return nil
}

// ExtProcPerRouteMultiError is an error wrapping multiple validation errors
// returned by ExtProcPerRoute.ValidateAll() if the designated constraints
// aren't met.
type ExtProcPerRouteMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m ExtProcPerRouteMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m ExtProcPerRouteMultiError) AllErrors() []error { return m }

// ExtProcPerRouteValidationError is the validation error returned by
// ExtProcPerRoute.Validate if the designated constraints aren't met.
type ExtProcPerRouteValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e ExtProcPerRouteValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e ExtProcPerRouteValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e ExtProcPerRouteValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e ExtProcPerRouteValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e ExtProcPerRouteValidationError) ErrorName() string { return "ExtProcPerRouteValidationError" }

// Error satisfies the builtin error interface
func (e ExtProcPerRouteValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sExtProcPerRoute.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = ExtProcPerRouteValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = ExtProcPerRouteValidationError{}

// Validate checks the field values on ExtProcOverrides with the rules defined
// in the proto definition for this message. If any rules are violated, the
// first error encountered is returned, or nil if there are no violations.
func (m *ExtProcOverrides) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on ExtProcOverrides with the rules
// defined in the proto definition for this message. If any rules are
// violated, the result is a list of violation errors wrapped in
// ExtProcOverridesMultiError, or nil if none found.
func (m *ExtProcOverrides) ValidateAll() error {
	return m.validate(true)
}

func (m *ExtProcOverrides) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	if all {
		switch v := interface{}(m.GetProcessingMode()).(type) {
		case interface{ ValidateAll() error }:
			if err := v.ValidateAll(); err != nil {
				errors = append(errors, ExtProcOverridesValidationError{
					field:  "ProcessingMode",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		case interface{ Validate() error }:
			if err := v.Validate(); err != nil {
				errors = append(errors, ExtProcOverridesValidationError{
					field:  "ProcessingMode",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		}
	} else if v, ok := interface{}(m.GetProcessingMode()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return ExtProcOverridesValidationError{
				field:  "ProcessingMode",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	// no validation rules for AsyncMode

	if all {
		switch v := interface{}(m.GetGrpcService()).(type) {
		case interface{ ValidateAll() error }:
			if err := v.ValidateAll(); err != nil {
				errors = append(errors, ExtProcOverridesValidationError{
					field:  "GrpcService",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		case interface{ Validate() error }:
			if err := v.Validate(); err != nil {
				errors = append(errors, ExtProcOverridesValidationError{
					field:  "GrpcService",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		}
	} else if v, ok := interface{}(m.GetGrpcService()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return ExtProcOverridesValidationError{
				field:  "GrpcService",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	if all {
		switch v := interface{}(m.GetMetadataOptions()).(type) {
		case interface{ ValidateAll() error }:
			if err := v.ValidateAll(); err != nil {
				errors = append(errors, ExtProcOverridesValidationError{
					field:  "MetadataOptions",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		case interface{ Validate() error }:
			if err := v.Validate(); err != nil {
				errors = append(errors, ExtProcOverridesValidationError{
					field:  "MetadataOptions",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		}
	} else if v, ok := interface{}(m.GetMetadataOptions()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return ExtProcOverridesValidationError{
				field:  "MetadataOptions",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	for idx, item := range m.GetGrpcInitialMetadata() {
		_, _ = idx, item

		if all {
			switch v := interface{}(item).(type) {
			case interface{ ValidateAll() error }:
				if err := v.ValidateAll(); err != nil {
					errors = append(errors, ExtProcOverridesValidationError{
						field:  fmt.Sprintf("GrpcInitialMetadata[%v]", idx),
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			case interface{ Validate() error }:
				if err := v.Validate(); err != nil {
					errors = append(errors, ExtProcOverridesValidationError{
						field:  fmt.Sprintf("GrpcInitialMetadata[%v]", idx),
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			}
		} else if v, ok := interface{}(item).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return ExtProcOverridesValidationError{
					field:  fmt.Sprintf("GrpcInitialMetadata[%v]", idx),
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	}

	if len(errors) > 0 {
		return ExtProcOverridesMultiError(errors)
	}

	return nil
}

// ExtProcOverridesMultiError is an error wrapping multiple validation errors
// returned by ExtProcOverrides.ValidateAll() if the designated constraints
// aren't met.
type ExtProcOverridesMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m ExtProcOverridesMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m ExtProcOverridesMultiError) AllErrors() []error { return m }

// ExtProcOverridesValidationError is the validation error returned by
// ExtProcOverrides.Validate if the designated constraints aren't met.
type ExtProcOverridesValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e ExtProcOverridesValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e ExtProcOverridesValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e ExtProcOverridesValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e ExtProcOverridesValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e ExtProcOverridesValidationError) ErrorName() string { return "ExtProcOverridesValidationError" }

// Error satisfies the builtin error interface
func (e ExtProcOverridesValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sExtProcOverrides.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = ExtProcOverridesValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = ExtProcOverridesValidationError{}

// Validate checks the field values on MetadataOptions_MetadataNamespaces with
// the rules defined in the proto definition for this message. If any rules
// are violated, the first error encountered is returned, or nil if there are
// no violations.
func (m *MetadataOptions_MetadataNamespaces) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on MetadataOptions_MetadataNamespaces
// with the rules defined in the proto definition for this message. If any
// rules are violated, the result is a list of violation errors wrapped in
// MetadataOptions_MetadataNamespacesMultiError, or nil if none found.
func (m *MetadataOptions_MetadataNamespaces) ValidateAll() error {
	return m.validate(true)
}

func (m *MetadataOptions_MetadataNamespaces) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	if len(errors) > 0 {
		return MetadataOptions_MetadataNamespacesMultiError(errors)
	}

	return nil
}

// MetadataOptions_MetadataNamespacesMultiError is an error wrapping multiple
// validation errors returned by
// MetadataOptions_MetadataNamespaces.ValidateAll() if the designated
// constraints aren't met.
type MetadataOptions_MetadataNamespacesMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m MetadataOptions_MetadataNamespacesMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m MetadataOptions_MetadataNamespacesMultiError) AllErrors() []error { return m }

// MetadataOptions_MetadataNamespacesValidationError is the validation error
// returned by MetadataOptions_MetadataNamespaces.Validate if the designated
// constraints aren't met.
type MetadataOptions_MetadataNamespacesValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e MetadataOptions_MetadataNamespacesValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e MetadataOptions_MetadataNamespacesValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e MetadataOptions_MetadataNamespacesValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e MetadataOptions_MetadataNamespacesValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e MetadataOptions_MetadataNamespacesValidationError) ErrorName() string {
	return "MetadataOptions_MetadataNamespacesValidationError"
}

// Error satisfies the builtin error interface
func (e MetadataOptions_MetadataNamespacesValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sMetadataOptions_MetadataNamespaces.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = MetadataOptions_MetadataNamespacesValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = MetadataOptions_MetadataNamespacesValidationError{}
