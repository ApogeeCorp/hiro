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
