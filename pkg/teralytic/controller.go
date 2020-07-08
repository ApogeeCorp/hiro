//
//  TERALYTIC CONFIDENTIAL
//  _________________
//   2020 TERALYTIC
//   All Rights Reserved.
//
//   NOTICE:  All information contained herein is, and remains
//   the property of TERALYTIC and its suppliers,
//   if any.  The intellectual and technical concepts contained
//   herein are proprietary to TERALYTIC
//   and its suppliers and may be covered by U.S. and Foreign Patents,
//   patents in process, and are protected by trade secret or copyright law.
//   Dissemination of this information or reproduction of this material
//   is strictly forbidden unless prior written permission is obtained
//   from TERALYTIC.
//

package teralytic

import (
	"sync"

	"github.com/sirupsen/logrus"
)

var (
	backend     Backend
	backendInit func(params map[string]interface{}, ctrl BackendController) (Backend, error)

	regOnce  sync.Once
	initOnce sync.Once
)

type (
	// BackendController defines an interface for providing resources to the backend
	BackendController interface {
		Log() *logrus.Logger
	}
)

// RegisterBackend registers the backend
func RegisterBackend(initFunc func(params map[string]interface{}, ctrl BackendController) (Backend, error)) {
	// only one backend should be initialized
	if backendInit != nil {
		panic("teralytic backend already registered")
	}

	regOnce.Do(func() {
		backendInit = initFunc
	})
}

// Initialize initializes the backend
func Initialize(params map[string]interface{}, ctrl BackendController) (Backend, error) {
	var err error

	if backendInit == nil {
		panic("teralytic backend not registered")
	}

	initOnce.Do(func() {
		backend, err = backendInit(params, ctrl)
	})

	return backend, err
}
