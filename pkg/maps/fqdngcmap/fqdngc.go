// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fqdngcmap

import (
	"fmt"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
)

const (
	FqdnGCMapName = "cilium_fqdn_gc"
)

var (
	// FqdnGcMap is the BPF map to track garbage collected FQDNs
	FqdnGCMap *bpf.Map
	// MaxEntries contains the maximum number of entries that are allowed
	// in a Cilium FQDN GC map.
	MaxEntries = 100
)

func initFqdnGC() {
	FqdnGCMap = bpf.NewMap(
		FqdnGCMapName,
		bpf.MapTypeLRUHash,
		&FqdnGCKey{},
		int(unsafe.Sizeof(FqdnGCKey{})),
		&FqdnGCValue{},
		int(unsafe.Sizeof(FqdnGCValue{})),
		MaxEntries,
		0, 0,
		bpf.ConvertKeyValue,
	).WithCache().WithPressureMetric()
}

// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapKey
type FqdnGCKey struct {
	Fqdn string
}

// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapValue
type FqdnGCValue struct {
	Pad uint8 `align:"pad"`
}

func (k *FqdnGCKey) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }

func (v *FqdnGCValue) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }

func (k *FqdnGCKey) String() string {
	return fmt.Sprintf("%s", k.Fqdn)
}

func (v *FqdnGCValue) String() string {
	return ""
}

func (k *FqdnGCKey) NewValue() bpf.MapValue { return &FqdnGCKey{} }
