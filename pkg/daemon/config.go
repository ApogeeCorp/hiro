/*
 * Copyright (C) 2020 Model Rocket
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file in the root of this
 * workspace for details.
 */

package daemon

import "github.com/sirupsen/logrus"

type (
	// Config is the root config
	Config struct {
		// Version is the config version
		Version string `yaml:"version"`

		// ServerAddr is the server listener addressa and port (default 127.0.0.1:9000)
		ServerAddr string `yaml:"server_addr" env:"SERVER_ADDR"`

		// Backend is the back end configuration
		Backend map[string]interface{} `yaml:"backend"`

		// LogLevel is the logrus based levels `Trace, Debug, Info, Warning, Error, Fatal and Panic.`
		LogLevel string `yaml:"log_level" env:"LOG_LEVEL"`

		// Logger is the logger for the daemon
		Logger *logrus.Logger `yaml:"-"`
	}
)
