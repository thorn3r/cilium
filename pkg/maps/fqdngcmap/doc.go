// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package fqdngcmap represents the LRU hash map used to track FQDNs that have
// been garbage collected. Its primary use is for tracking FQDNs which have
// been garbage collected for use in debugging toFQDN policies.
// +groupName=maps
package fqdngcmap
