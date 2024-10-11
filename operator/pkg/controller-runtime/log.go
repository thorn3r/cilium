// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package controllerruntime

import (
	"github.com/bombsimon/logrusr/v4"
	"github.com/go-logr/logr"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

func newLogrFromLogrus(logger logrus.FieldLogger) logr.Logger {
	return logr.New(logSink{logrusr.New(logger).GetSink()})
}

type logSink struct{ logr.LogSink }

func (w logSink) Error(err error, msg string, keysAndValues ...any) {
	if msg == "Reconciler error" && isRetryableError(err) {
		w.LogSink.Info(0, msg, append(keysAndValues, logfields.Error, err.Error())...)
		return
	}

	w.LogSink.Error(err, msg, keysAndValues...)
}

func (w logSink) WithValues(keysAndValues ...any) logr.LogSink {
	return logSink{w.LogSink.WithValues(keysAndValues...)}
}

func (w logSink) WithName(name string) logr.LogSink {
	return logSink{w.LogSink.WithName(name)}
}

// isRetryableError returns true if the error returned by the Reconcile
// is likely transient, and will be addressed by a subsequent iteration.
func isRetryableError(err error) bool {
	return k8serrors.IsAlreadyExists(err) ||
		k8serrors.IsConflict(err) ||
		k8serrors.IsNotFound(err) ||
		(k8serrors.IsForbidden(err) &&
			k8serrors.HasStatusCause(err, corev1.NamespaceTerminatingCause))
}
