// Copyright 2025 Chainguard, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ldsoconf

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"slices"
	"strings"
)

func ParseLDSOConf(fsys fs.FS, ldsoconf string) ([]string, error) {
	conf, err := fsys.Open(ldsoconf)
	if err != nil {
		fmt.Printf("Warning: Could not open config file %s\n", ldsoconf)
		return nil, err
	}
	defer conf.Close()
	contents, err := io.ReadAll(conf)
	if err != nil {
		fmt.Printf("Warning: Could not read config file %s\n", ldsoconf)
		return nil, err
	}
	var libpaths []string
	var seenpaths []string

	lines := strings.Split(string(contents), "\n")
	for _, line := range lines {
		idx := strings.Index(line, "#")
		if idx > -1 {
			line = line[:idx]
		}
		line = strings.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		glob, is_include := strings.CutPrefix(line, "include ")
		if is_include {
			glob = strings.TrimSpace(glob)
			glob = strings.TrimLeft(glob, "/")
			matches, err := fs.Glob(fsys, glob)
			if err != nil {
				fmt.Printf("Warning: glob error in %s: %s", ldsoconf, glob)
				continue
			}
			if len(matches) == 0 {
				fmt.Printf("Warning: No matches for glob %s in %s\n", glob, ldsoconf)
			}

			for _, match := range matches {
				incpaths, err := ParseLDSOConf(fsys, match)
				if err != nil {
					fmt.Printf("Warning: Could not parse config file %s\n", match)
					continue
				}
				libpaths = append(libpaths, incpaths...)
			}
			return libpaths, nil
		}
		if _, err := fs.Stat(fsys, line); os.IsNotExist(err) {
			continue
		}
		realpath := line

		if err != nil {
			return nil, err
		}
		if slices.Contains(seenpaths, realpath) {
			fmt.Printf("Warning: Skipping %s because we've already seen it\n", realpath)
			continue
		}
		libpaths = append(libpaths, line)
		seenpaths = append(seenpaths, realpath)
	}
	return libpaths, nil
}
