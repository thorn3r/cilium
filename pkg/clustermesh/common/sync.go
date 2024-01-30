// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package common

import (
	"context"
	"errors"

	"github.com/cilium/cilium/pkg/lock"
)

var (
	// ErrRemoteClusterDisconnected is the error returned by wait for sync
	// operations if the remote cluster is disconnected while still waiting.
	ErrRemoteClusterDisconnected = errors.New("remote cluster disconnected")
)

// SyncedWaitFn is the type of a function to wait for the initial synchronization
// of a given resource type from all remote clusters.
type SyncedWaitFn func(ctx context.Context) error

// NodesSynced returns after that the initial list of nodes has been received
// from all remote clusters, and synchronized with the different subscribers.
func (cm *ClusterMesh) NodesSynced(ctx context.Context) error {
	return cm.waitForSync(ctx, func(rc *remoteCluster) SyncedWaitFn { return rc.synced.Nodes })
}

// ServicesSynced returns after that the initial list of shared services has been
// received from all remote clusters, and synchronized with the BPF datapath.
func (cm *ClusterMesh) ServicesSynced(ctx context.Context) error {
	return cm.waitForSync(ctx, func(rc *remoteCluster) SyncedWaitFn { return rc.synced.Services })
}

// IPIdentitiesSynced returns after that the initial list of ipcache entries and
// identities has been received from all remote clusters, and synchronized with
// the BPF datapath.
func (cm *ClusterMesh) IPIdentitiesSynced(ctx context.Context) error {
	return cm.waitForSync(ctx, func(rc *remoteCluster) SyncedWaitFn { return rc.synced.IPIdentities })
}

func (cm *ClusterMesh) waitForSync(ctx context.Context, toWaitFn func(*remoteCluster) SyncedWaitFn) error {
	waiters := make([]SyncedWaitFn, 0)
	cm.ForEachRemoteCluster(func(rci RemoteCluster) error {
		rc := rci.(*remoteCluster)
		waiters = append(waiters, toWaitFn(rc))
		return nil
	})

	for _, wait := range waiters {
		err := wait(ctx)

		// Ignore the error in case the given cluster was disconnected in
		// the meanwhile, as we do not longer care about it.
		if err != nil && !errors.Is(err, ErrRemoteClusterDisconnected) {
			return err
		}
	}
	return nil
}

// Synced tracks the status of the initial synchronization of a remote cluster.
// ServicesSWG is exposed to allow handing control to the ServiceCache.
type Synced struct {
	ServicesSWG *lock.StoppableWaitGroup
	nodes       chan struct{}
	ipcache     chan struct{}
	identities  *lock.StoppableWaitGroup
	stopped     chan struct{}
}

// Nodes returns after that the initial list of nodes has been received
// from the remote cluster, and synchronized with the different subscribers,
// the remote cluster is disconnected, or the given context is canceled.
func (s *Synced) Nodes(ctx context.Context) error {
	return s.wait(ctx, s.nodes)
}

func (s *Synced) EndNodes(_ context.Context) {
	close(s.nodes)
}

func (s *Synced) EndIPCache(_ context.Context) {
	close(s.ipcache)
}

func (s *Synced) EndIdentities(_ context.Context) {
	s.identities.Stop()
}

// Services returns after that the initial list of shared services has been
// received from the remote cluster, and synchronized with the BPF datapath,
// the remote cluster is disconnected, or the given context is canceled.
func (s *Synced) Services(ctx context.Context) error {
	return s.wait(ctx, s.ServicesSWG.WaitChannel())
}

// IPIdentities returns after that the initial list of ipcache entries and
// identities has been received from the remote cluster, and synchronized
// with the BPF datapath, the remote cluster is disconnected, or the given
// context is canceled. We additionally need to explicitly wait for nodes
// synchronization because they also trigger the insertion of ipcache entries
// (i.e., node addresses, health, ingress, ...).
func (s *Synced) IPIdentities(ctx context.Context) error {
	return s.wait(ctx, s.ipcache, s.identities.WaitChannel(), s.nodes)
}

func (s *Synced) wait(ctx context.Context, chs ...<-chan struct{}) error {
	for _, ch := range chs {
		select {
		case <-ch:
			continue
		case <-s.stopped:
			return ErrRemoteClusterDisconnected
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	return nil
}

// NewSynced returns a new Synced instance.
func NewSynced() Synced {
	// Use a StoppableWaitGroup for identities, instead of a plain channel to
	// avoid having to deal with the possibility of a closed channel if already
	// synced (as the callback is executed every time the etcd connection
	// is restarted, differently from the other resource types).
	idswg := lock.NewStoppableWaitGroup()
	idswg.Add()
	idswg.Stop()

	return Synced{
		ServicesSWG: lock.NewStoppableWaitGroup(),
		nodes:       make(chan struct{}),
		ipcache:     make(chan struct{}),
		identities:  idswg,
		stopped:     make(chan struct{}),
	}
}

func (s *Synced) Stop() {
	close(s.stopped)
}
