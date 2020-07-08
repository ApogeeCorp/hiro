/*
 * Copyright (C) 2020 Model Rocket
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file in the root of this
 * workspace for details.
 */

package hiro

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
		panic("backend already registered")
	}

	regOnce.Do(func() {
		backendInit = initFunc
	})
}

// Initialize initializes the backend
func Initialize(params map[string]interface{}, ctrl BackendController) (Backend, error) {
	var err error

	if backendInit == nil {
		panic("backend not registered")
	}

	initOnce.Do(func() {
		backend, err = backendInit(params, ctrl)
	})

	return backend, err
}
