/*
 * This file is part of the Atomic Stack (https://github.com/libatomic/atomic).
 * Copyright (c) 2020 Atomic Publishing.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

package main

import (
	"fmt"
	"io/ioutil"
	"path"

	"github.com/mitchellh/go-homedir"
	"github.com/urfave/cli/v2"
	"gopkg.in/yaml.v2"
)

func loadConfig(c *cli.Context) error {
	hd, err := homedir.Dir()
	if err != nil {
		return err
	}

	p := path.Join(hd, ".hiro", "env.yml")
	data, err := ioutil.ReadFile(p)
	if err != nil {
		return err
	}

	out := make(map[string]map[string]string)
	if err := yaml.Unmarshal(data, &out); err != nil {
		return err
	}

	env, ok := out[c.String("env")]
	if !ok {
		return fmt.Errorf("env %s not found in config", c.String("env"))
	}

	for k, v := range env {
		c.Set(k, v)
	}

	return nil
}
