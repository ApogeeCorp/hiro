// Code generated by go-bindata.
// sources:
// sql/0000_initialize.sql
// sql/0010_audience.sql
// sql/0020_application.sql
// sql/0030_role.sql
// sql/0040_user.sql
// sql/0060_asset.sql
// sql/0100_option.sql
// sql/0200_request_token.sql
// sql/0220_access_token.sql
// sql/0240_session.sql
// sql/0260_secrets.sql
// DO NOT EDIT!

package db

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func bindataRead(data []byte, name string) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewBuffer(data))
	if err != nil {
		return nil, fmt.Errorf("Read %q: %v", name, err)
	}

	var buf bytes.Buffer
	_, err = io.Copy(&buf, gz)
	clErr := gz.Close()

	if err != nil {
		return nil, fmt.Errorf("Read %q: %v", name, err)
	}
	if clErr != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

type asset struct {
	bytes []byte
	info  os.FileInfo
}

type bindataFileInfo struct {
	name    string
	size    int64
	mode    os.FileMode
	modTime time.Time
}

func (fi bindataFileInfo) Name() string {
	return fi.name
}
func (fi bindataFileInfo) Size() int64 {
	return fi.size
}
func (fi bindataFileInfo) Mode() os.FileMode {
	return fi.mode
}
func (fi bindataFileInfo) ModTime() time.Time {
	return fi.modTime
}
func (fi bindataFileInfo) IsDir() bool {
	return false
}
func (fi bindataFileInfo) Sys() interface{} {
	return nil
}

var _sql0000_initializeSql = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xac\x55\xc1\x4e\xe3\x48\x10\x3d\xa7\xbf\xe2\x29\x1b\xc9\xb1\x26\x1e\xcd\xec\x6d\x89\x38\x84\xd0\x64\x22\x05\x67\xd7\x76\x16\xa4\x09\x13\xf5\xd8\x85\xdd\x92\xdd\xf6\x74\x77\x80\xac\xf8\xf8\x55\xdb\x84\x09\x0c\x2c\x1c\xf6\x82\x71\xd7\x73\xd5\x7b\x55\xd5\x2f\x41\x80\x0f\x95\xcc\xb5\xb0\x84\x55\xc3\x82\x00\xf1\x5f\x0b\x48\x05\x43\xa9\x95\xb5\x82\xb7\x6a\x3c\x48\x03\xba\xa3\x74\x6b\x29\xc3\x6d\x41\x0a\xb6\x90\x06\xdd\x77\x0e\x24\x0d\x44\xd3\x94\x92\x32\x36\x8d\xf8\x24\xe1\x88\xa7\x5f\xf8\xf9\x04\xf3\x33\x84\xcb\x04\xfc\x72\x1e\x27\x31\x0a\xa9\xeb\xf1\x1e\xc1\x2f\x13\x1e\xc6\xf3\x65\xf8\x0c\xd4\x6f\xf2\x54\xef\x1a\x5b\xf7\xdf\x86\x6e\x95\x48\x53\x52\xf6\x1d\xd0\xc2\xd8\x5a\xd3\x3b\x80\xdf\xad\x26\xda\xe4\xd2\xb8\xac\xec\xb0\x3f\xb1\x15\x96\x2a\x52\xf6\x84\x72\xa9\xf6\x89\x96\x11\x22\xfe\xe7\x62\x32\xe5\x38\x5b\x85\xd3\xc4\xa5\x74\x42\x3f\x6e\x9b\x4c\x58\xda\x58\x59\x91\xb1\xa2\x6a\x86\x3e\x8b\x78\xb2\x8a\xc2\x18\x49\x34\x9f\xcd\x78\x84\x49\x8c\xc1\x80\x9d\xf2\xe9\x62\x12\x71\x06\x00\x69\x5d\x22\xe1\x97\x09\x8e\x8e\xf1\x63\x5b\x5b\xda\xc8\x8c\x94\x1d\x26\xb3\xcd\x24\x9a\xfd\xfd\xf5\xd3\x95\x3f\x66\x27\x7c\x36\x0f\x5b\x78\xc8\x2f\x1c\xd2\x3d\x7e\x3b\x46\xa7\x71\x98\xd6\xe5\x08\xe1\xf2\x62\xe8\x1f\x1d\x59\xba\xb3\xfe\x98\x01\x5d\x69\x87\x1c\x33\x1e\x9e\x8e\xd9\x60\x80\xc5\x24\x9c\xad\x26\x33\x8e\xa6\x6c\x72\xf3\xa3\x1c\xb3\x37\x45\x99\x72\x9b\xcb\xeb\xdd\xb0\x7f\x23\xca\x2d\xf5\x5b\xae\x23\xf4\xeb\x4a\xda\xee\x05\xa7\xfc\x6c\xb2\x5a\x24\xf0\xbc\x03\xbd\x2e\xd0\x89\x05\x82\x00\x9a\xaa\xfa\x86\x0c\xba\xe9\x19\x0c\x33\x29\x52\x2d\xad\x4c\x61\x64\xae\x8c\x8f\x6b\x5d\x57\x10\xc8\xe5\x0d\x29\x18\xab\xa5\xca\x11\x04\x0c\xb8\x98\x27\x5f\x7e\x0e\x9e\xb2\xbe\xcb\x3b\x6c\x9b\x11\xf3\x05\x9f\x26\xd8\xc7\xf6\x1c\x7d\x87\x78\xf8\x9f\x01\xfe\xa8\xe3\x50\xd6\xb7\xa4\x53\x61\xc8\xc0\x16\xf4\x50\x83\x01\xfd\xc7\xc0\xaf\xa9\xdb\xd0\x2b\x79\x81\xb3\x68\x79\xfe\x84\xda\x41\x35\x4d\x4d\x29\x52\x27\x59\xed\x6c\xe1\xd4\xd8\x42\x58\xcf\x40\xd5\x16\x02\x25\x59\x4b\x7a\x04\xb5\xad\xbe\xbb\x67\x3f\xe8\x8f\x50\x6b\x6c\x55\x46\xda\xa4\x6e\xaa\xde\xc6\xf3\x71\x2b\x6d\xe1\x82\x8e\x67\xb1\x6b\x0a\x52\xe2\xc5\x1e\x68\xca\xe9\xae\xd9\x3c\x54\xdd\x33\x1e\xc1\xfb\xfa\x4d\x04\xff\x7c\x0a\xfe\xf0\x70\x7f\xbf\x1f\xdb\xfd\x3d\xbc\xf5\x7a\x13\x5c\x7d\xf0\x46\xf0\x02\xf7\x27\x97\xde\x2b\xf2\x7e\x76\xe7\x40\x9d\xd5\xb2\x32\x8e\x17\xe4\xb5\xeb\xe6\x0e\x74\x27\x8d\x45\xad\xda\xde\x16\x24\x32\xa7\xc6\x0a\x59\xa2\xbe\x7e\xd6\x6f\xf7\x71\xf5\x0e\x11\xaf\x6a\x0a\xd6\xeb\x0f\x03\xc7\xda\xf3\x47\xf0\xbe\xad\xd7\x41\xf7\xf2\xb2\x80\x83\xb6\x39\x05\x87\x05\xf7\x4b\xdd\x01\xf7\xbc\x9e\x5e\x15\x67\x8f\x71\x12\xcd\xa7\x09\xe6\xe7\xe7\xab\x64\x72\xb2\xe0\x9d\x4f\xa4\x9a\x84\x75\x13\x86\xbb\x24\xdd\x06\xb7\x4a\x75\xda\x5e\x6b\xa9\x6c\xdd\x1e\x64\xc6\xba\x83\x6d\xa5\xb0\x35\xdd\x2a\x10\x4c\x43\xa9\xbc\x96\x94\xc1\x50\x23\xb4\xb0\xb5\x7e\xaf\xc3\xb8\x72\x43\x9f\xe1\x99\xbb\xb0\xe7\xee\xe2\x88\xbc\xe9\x2d\xe8\x39\x7a\xff\x89\xfb\xdc\xe2\xe0\x96\xe7\x11\x97\xd6\xa2\x24\x93\xd2\x23\xe8\xf7\xab\x76\x06\x2e\x61\xdb\x0e\x07\xdc\x3b\x57\x8f\x5f\xf2\xe9\x2a\xe1\xf0\x1e\x1a\x3f\xf8\xfc\xb1\x5d\x48\xc7\x90\xf5\x56\xf1\x3c\x9c\x39\xa7\x62\xbd\x79\x98\x2c\xdd\xe9\x18\x0c\xac\x4b\x74\x74\xfc\xd4\x89\x8c\x4e\x47\x2d\x17\x7f\xcc\x7a\xac\xf7\xa2\x23\x66\xc6\x8e\xda\xa9\x38\x3e\xbf\x9a\xe1\x2b\x5e\xf8\xa2\xf7\x73\x95\x3d\x8d\x9c\xd6\xb7\xea\x7f\xf8\xdd\xfc\x37\x00\x00\xff\xff\x5e\x01\xd4\x6a\x89\x07\x00\x00")

func sql0000_initializeSqlBytes() ([]byte, error) {
	return bindataRead(
		_sql0000_initializeSql,
		"sql/0000_initialize.sql",
	)
}

func sql0000_initializeSql() (*asset, error) {
	bytes, err := sql0000_initializeSqlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "sql/0000_initialize.sql", size: 1929, mode: os.FileMode(493), modTime: time.Unix(1609182249, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _sql0010_audienceSql = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xac\x54\x4d\x8f\xda\x30\x14\xbc\xe7\x57\x3c\x71\xd9\xa0\x42\xd5\x56\xab\x3d\x74\x4f\x21\x79\xb0\x69\x43\xc2\x3a\x76\xcb\x56\x95\x22\x0b\xbb\x60\x95\x7c\x28\x71\xb4\xfd\xf9\x55\x1c\x96\x84\xa0\x76\x51\xcb\x31\x78\x66\xcc\xbc\x99\xe7\xe9\x14\xde\xa4\x6a\x5b\x72\x2d\x81\x15\xd6\x74\x0a\xf1\x63\x00\x2a\x83\x4a\x6e\xb4\xca\x33\xb8\x61\xc5\x0d\xa8\x0a\xe4\x2f\xb9\xa9\xb5\x14\xf0\xbc\x93\x19\xe8\x9d\xaa\xa0\xe5\x35\x20\x55\x01\x2f\x8a\xbd\x92\xc2\xb2\x5c\x82\x0e\x45\xa0\xce\x2c\x40\xf0\xe7\x10\x46\x14\x70\xed\xc7\x34\x86\x9d\x2a\xf3\xb7\xbc\x16\x4a\x66\x1b\x59\xd9\x16\x00\x80\x12\xc0\x98\xef\xc1\x8a\xf8\x4b\x87\x3c\xc1\x67\x7c\x02\x0f\xe7\x0e\x0b\x28\x6c\x65\x96\x94\x3c\x13\x79\x9a\xd4\xb5\x12\xf6\x78\x62\x28\x9b\x52\x72\x2d\x45\xc2\x35\x50\x7f\x89\x31\x75\x96\x2b\xfa\xcd\x5c\x14\xb2\x20\x38\xd2\x5d\x46\x08\x86\x34\x39\x82\x5a\x7a\x5d\x88\xff\xa1\x67\x3c\x95\xf0\xc5\x21\xee\x83\x43\xec\xbb\xdb\x71\x47\x64\xa1\xff\xc8\xb0\x45\x55\xfb\x7a\xfb\x3a\x4a\xc8\x6a\x53\xaa\xc2\xcc\xf0\x05\xfc\xfe\xdd\x87\xdb\x83\x51\x91\xa7\x5c\x0d\x4e\x4e\xf8\x3a\xff\x29\xb3\x84\xef\xb7\x79\xa9\xf4\x2e\xed\x90\x77\xdd\x85\x7d\xe4\x5e\xfd\x90\x5a\xa5\x12\x66\xfe\xc2\x0f\xe9\x00\x53\xc9\xaa\x52\xf9\x5f\x50\x60\x60\xa9\xd4\x5c\x70\xcd\xe1\x53\x1c\x85\x33\x6b\x7c\x6f\x59\x1e\x89\x56\x40\x89\xbf\x58\x20\x69\x32\x3f\xe4\xdd\x4e\x3a\x69\xb4\x2a\xcd\xd3\x02\xa2\x70\xd0\x81\xfb\xae\x2f\x07\xf6\x90\x63\x01\xcc\x70\x1e\x11\x04\xb6\xf2\x1a\xe0\x99\x86\x05\x30\x8f\x08\xa0\xe3\x3e\x00\x89\xbe\x5a\x00\xb8\x46\x97\x51\x84\x15\x89\x5c\xf4\x18\xc1\x96\x31\x94\xb6\x47\x5d\x15\x46\xaf\xdb\x30\x91\x5e\xee\xa0\x81\x77\x7f\xde\x0f\x63\x24\x14\x22\x72\x35\x1b\x8d\xbe\x3d\x6a\xda\x38\x9a\xc0\xa8\xf9\x32\x1e\x2e\x5d\xbf\xa4\x90\x65\xaa\x4c\xe0\x66\x13\x8f\xbf\xbf\x2c\xe4\xb1\xb0\x04\xe7\x48\x30\x74\xf1\x6c\x81\x95\x18\x37\x3e\x3c\x0c\x90\x22\xb8\x4e\xec\x3a\x9e\x69\x66\xa7\x0d\x14\xd7\xa7\x3d\xeb\x2d\xba\xdd\xbb\x74\xd2\x23\x8d\x2f\x28\x95\x49\xe3\x6c\x8a\x7d\x57\xd7\x4a\xa6\xaf\xf9\x6f\x21\x75\x02\x4d\x54\xa7\x5f\xdf\x3f\x9a\xd8\xfa\xef\xb0\x97\x3f\x67\x57\x78\x89\xdb\xf9\x99\x1e\x0c\x2b\xfb\xa7\xa3\x93\xf1\xfd\x0e\x00\x00\xff\xff\x3f\x6c\x61\x00\x1b\x06\x00\x00")

func sql0010_audienceSqlBytes() ([]byte, error) {
	return bindataRead(
		_sql0010_audienceSql,
		"sql/0010_audience.sql",
	)
}

func sql0010_audienceSql() (*asset, error) {
	bytes, err := sql0010_audienceSqlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "sql/0010_audience.sql", size: 1563, mode: os.FileMode(493), modTime: time.Unix(1615748464, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _sql0020_applicationSql = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xbc\x55\x5d\x6f\xda\x4a\x10\x7d\xf7\xaf\x18\xf1\x62\xa3\x0b\x57\xf7\x5e\x45\xf7\x25\x4f\x8e\x3d\x10\xb7\x60\x93\xf5\xba\x25\x7d\xb1\xb6\xde\x29\xac\x02\xb6\xe5\x5d\x44\xd3\x5f\x5f\xd9\x86\xe0\x00\x21\x8d\x1a\xf5\xcd\x1f\x73\xce\xcc\x99\x33\xb3\x3b\x1c\xc2\x5f\x6b\xb5\xa8\x84\x21\x48\x4a\x6b\x38\x84\xf8\x6e\x02\x2a\x07\x4d\x99\x51\x45\x0e\x76\x52\xda\xa0\x34\xd0\x77\xca\x36\x86\x24\x6c\x97\x94\x83\x59\x2a\x0d\x2d\xae\x0e\x52\x1a\x44\x59\xae\x14\x49\xcb\x63\xe8\x72\x04\x7e\x3f\x43\x58\xaa\xaa\xf8\x7b\xcc\xdc\x90\xa7\xcd\xbb\x1b\x03\x86\xc9\x14\x1c\x5b\x6c\xcc\xb2\xa8\xd4\x8f\x06\x9e\x66\x85\x24\x7b\x00\x76\xb6\x52\x94\x9b\x34\xab\x48\x52\x6e\x94\x58\xe9\xfa\x6b\x29\xb4\xde\x16\x95\xac\x9f\x2b\xfa\x56\x91\x5e\xa6\xa6\x78\xa0\xdc\xee\x5f\x5b\x4f\xf9\xdc\x9b\x09\x42\x30\x82\x30\xe2\x80\xf3\x20\xe6\x71\x9b\xbe\xa9\x2b\x6b\xf2\x68\xc7\x02\x00\x50\x12\x92\x24\xf0\x61\xc6\x82\xa9\xcb\xee\xe1\x23\xde\x83\x8f\x23\x37\x99\x70\x58\x50\x9e\x56\x22\x97\xc5\x3a\xdd\x6c\x94\x74\xfa\x83\x06\x92\x55\x24\x0c\xc9\x54\x18\xe0\xc1\x14\x63\xee\x4e\x67\xfc\x4b\x93\x2b\x4c\x26\x93\x27\xb8\x97\x30\x86\xb5\xda\x7d\x50\x0b\xdf\x94\xf2\x77\xe0\xb9\x58\x13\x7c\x72\x99\x77\xeb\x32\xe7\xff\xab\xfe\x01\x98\x84\xc1\x5d\x82\x6d\x94\x5e\x6d\x16\xaf\x47\x49\xd2\x59\xa5\xca\xc6\xb5\x7d\xf0\xbf\xff\xfc\x77\xb5\x13\x6a\x1e\x4b\x02\x8e\x73\x7e\x5a\x9c\xbd\xa5\xaf\xf6\x2e\x15\x65\x15\x99\xf4\x81\x1e\x9b\xd8\x9d\xc8\x4a\x69\xf8\x10\x47\xe1\x4d\xfb\xbe\x26\x23\xa4\x30\xa2\xfd\x66\x75\xbc\x0a\x42\x1f\xe7\x47\x5e\x75\x6c\xea\xfa\x0f\x51\x78\xc6\x46\x25\x07\x9d\x1a\x6a\x66\x9f\x45\x33\xe0\x2c\x18\x8f\x91\xd5\xcc\x3b\xd6\xb6\xf1\xa9\x51\x6b\xd2\x46\xac\xcb\xb3\x74\x9d\x21\xda\x11\x1c\xc3\x2c\x80\x1b\x1c\x45\x0c\x21\x99\xf9\x75\xe0\x39\x1a\x0b\x60\x14\x31\x40\xd7\xbb\x05\x16\x7d\xb6\x00\x70\x8e\x5e\xc2\x11\x66\x2c\xf2\xd0\x4f\xd8\x6e\x21\x8e\xd9\x9d\xde\x61\x3e\x7a\xaf\x8b\x69\x7c\x7e\x93\x8e\x1a\x71\x90\x10\x84\x31\x32\x0e\x11\x7b\x4f\x31\x75\x0a\xa7\x57\x0f\x6a\x6f\x00\xbd\xfa\xad\xf7\xc6\xe5\x4c\x4b\xaa\xd6\x4a\xeb\xfd\x9e\x76\x7f\xed\x37\xf6\x69\x26\x19\x8e\x90\x61\xe8\xe1\xb9\x25\x57\xb2\x5f\x6b\xf2\x71\x82\x1c\xc1\x73\x63\xcf\xf5\x9b\xe9\x17\x1b\xa9\x28\xcf\xe8\x84\xaf\xfe\x79\x48\xff\x7c\xfe\x07\x6d\x2b\x30\x18\x87\xf5\x49\xe1\x74\x48\x06\x1d\x50\x1f\x9a\xa1\x3f\x29\x6c\x1f\xdd\x55\x77\x99\xe2\xa4\xf4\xfd\xd7\x9d\x5d\x1d\x41\x9d\x13\xcc\x79\xde\xaf\x01\xbc\x94\xc4\x7a\xab\x2f\x8b\x4a\xe4\xe6\x8f\x5b\xf2\x62\x27\x2f\x90\x35\x95\xa6\xcd\x11\x76\x7c\xf3\x74\xdd\xfc\xe5\xae\x1d\xf8\xda\xae\x75\xef\x4a\xbf\xd8\xe6\xef\x70\x5b\xb6\xab\xde\xd8\x70\x66\x9f\x2f\xfc\xed\x0e\xd4\xe5\xc0\xd6\xbf\xeb\x9f\x01\x00\x00\xff\xff\xd7\x68\xd9\x1a\xe9\x07\x00\x00")

func sql0020_applicationSqlBytes() ([]byte, error) {
	return bindataRead(
		_sql0020_applicationSql,
		"sql/0020_application.sql",
	)
}

func sql0020_applicationSql() (*asset, error) {
	bytes, err := sql0020_applicationSqlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "sql/0020_application.sql", size: 2025, mode: os.FileMode(493), modTime: time.Unix(1615486498, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _sql0030_roleSql = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xac\x54\xdd\x6e\x9b\x4c\x14\xbc\xe7\x29\x46\xbe\x09\xd6\x67\x7f\x6a\xab\xa8\x17\xf5\x15\x81\xe3\x84\xd6\x01\x67\xd9\x6d\x9d\xaa\x12\x42\x66\x95\xac\x14\x7e\xc4\x8f\xd2\xc7\xaf\x76\x81\x80\x9d\xc4\x6d\xd5\x5c\x59\xde\x73\xce\xb0\x33\x73\x66\x97\x4b\xfc\x97\xa9\xbb\x2a\x69\x24\x44\x69\x2d\x97\x88\x6e\x36\x50\x39\x6a\xb9\x6f\x54\x91\xe3\x4c\x94\x67\x50\x35\xe4\x4f\xb9\x6f\x1b\x99\xe2\xf1\x5e\xe6\x68\xee\x55\x8d\x6e\x4e\x37\xa9\x1a\x49\x59\x3e\x28\x99\x5a\x2e\x23\x87\x13\xb8\x73\xb1\x21\xf8\x6b\x04\x21\x07\xed\xfc\x88\x47\xb8\x57\x55\xf1\x7f\x55\x3c\xc8\xda\xb6\x00\x40\xa5\x10\xc2\xf7\xb0\x65\xfe\xb5\xc3\x6e\xf1\x85\x6e\xe1\xd1\xda\x11\x1b\x8e\x3b\x99\xc7\x55\x92\xa7\x45\x16\xb7\xad\x4a\xed\xf9\xc2\x8c\x24\x6d\xaa\x64\xbe\x97\xf1\x30\xab\xe1\x03\xb1\xd9\x74\xe5\x7d\x25\x93\x46\xa6\x71\xd2\x80\xfb\xd7\x14\x71\xe7\x7a\xcb\xbf\x3f\x35\x3d\xa1\xbb\x82\x31\x0a\x78\xfc\xd4\xd4\x8d\xb7\x65\xfa\x2f\xe3\x79\x92\x49\x7c\x75\x98\x7b\xe5\x30\xfb\xe3\xf9\xfc\xe8\x72\xf5\x43\x7b\x77\xa2\x9c\xca\x7a\x5f\xa9\xd2\xe8\x39\x74\xbd\x7f\xf7\xe1\xbc\x67\x9e\xc9\x26\x49\x93\x26\xc1\xe7\x28\x0c\x2e\xba\xb3\x75\xc8\xc8\xbf\x0c\x8c\x70\xf6\x44\x9a\x39\x18\xad\x89\x51\xe0\x52\xaf\xfa\x50\xac\x6d\x5d\x0d\x03\x78\xb4\x21\x4e\x70\x9d\xc8\x75\x3c\xb2\xe6\x2b\x6b\x70\x4e\x04\xfe\x8d\x20\xf8\x81\x47\xbb\x23\x03\xb5\x77\xb1\x61\x19\x06\x53\x37\x27\x9f\x5e\x18\x15\xe6\xab\x3f\x45\x33\xa2\x9c\x40\xd3\x75\x7d\x39\x8f\x85\x5b\x70\xe6\x5f\x5e\x12\xd3\x38\x3d\x46\xe7\x58\xdc\xa8\x4c\xd6\x4d\x92\x95\x28\xf2\x09\xd4\x40\x6f\x24\x37\x20\x1c\xcf\x59\xc0\x05\x69\x39\x21\xb6\x9e\x6e\x3c\xb8\x92\x65\xa4\x06\x39\xee\x15\x58\xf8\xcd\x02\x68\x47\xae\xe0\x84\x2d\x0b\x5d\xf2\x04\xa3\xae\xfb\x18\xd6\x9e\x8d\x2b\x35\xfb\x3d\x0d\x23\xc6\xdf\x31\xd0\x23\xe3\xe5\xfd\x20\x22\xc6\x11\xb2\x37\xa1\xa1\xb1\xed\x99\xf6\x73\xb6\xc0\x4c\xff\xd3\xbf\x3f\x3e\xcd\x26\xdb\x72\x32\xe7\x71\x29\xab\x4c\xd5\xb5\x2a\x72\x13\x79\x73\x76\x9c\xdc\x67\xbb\xda\x6d\xc1\x8b\x7b\xaa\xd7\xfe\xe4\x13\x30\x7e\x10\x9c\x76\xfc\xa0\x36\x49\xcb\xe1\x8e\x8d\x43\x73\x98\x5c\xbd\x96\x9e\x03\x3e\xa7\x21\x9e\x47\xac\x3f\xed\x8d\x99\x10\x9a\x3c\x7f\x76\xaf\xd0\x02\xaf\xa1\x9b\xa4\x4e\x1f\x6d\xaf\x78\xcc\xdf\xe0\xd9\xee\x16\xd3\x98\x39\x9a\xb0\x7a\xf1\x78\xaa\xc2\xca\xfa\x15\x00\x00\xff\xff\x3f\x18\x51\xc0\x41\x06\x00\x00")

func sql0030_roleSqlBytes() ([]byte, error) {
	return bindataRead(
		_sql0030_roleSql,
		"sql/0030_role.sql",
	)
}

func sql0030_roleSql() (*asset, error) {
	bytes, err := sql0030_roleSqlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "sql/0030_role.sql", size: 1601, mode: os.FileMode(420), modTime: time.Unix(1615486571, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _sql0040_userSql = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xac\x93\x4f\x8f\xda\x30\x10\xc5\xef\xf9\x14\x4f\x7b\x59\xa2\x42\xa5\x56\x55\x55\x89\x53\x48\x86\xdd\xb4\x21\x61\x1d\xbb\xdd\xed\x25\xb2\xb0\x0b\x56\x21\x89\x62\x47\xec\xc7\xaf\x92\x00\x0b\xf4\xdf\xa1\x3d\x7a\xe6\xbd\x99\xd1\xfc\xc6\x93\x09\x5e\xed\xcc\xba\x91\x4e\x43\xd4\xde\x64\x82\xfc\x21\x81\x29\x61\xf5\xca\x99\xaa\xc4\xad\xa8\x6f\x61\x2c\xf4\xb3\x5e\xb5\x4e\x2b\xec\x37\xba\x84\xdb\x18\x8b\xc1\xd7\x89\x8c\x85\xac\xeb\xad\xd1\xca\x0b\x19\x05\x9c\xc0\x83\x59\x42\x88\xe7\x48\x33\x0e\x7a\x8c\x73\x9e\x63\x63\x9a\xea\x75\x6b\x75\x63\x47\x1e\x00\x18\x05\x21\xe2\x08\x4b\x16\x2f\x02\xf6\x84\x4f\xf4\x84\x88\xe6\x81\x48\x38\xd6\xba\x2c\x1a\x59\xaa\x6a\x57\xb4\xad\x51\x23\x7f\xdc\x5b\x56\x8d\x96\x4e\xab\x42\x3a\xf0\x78\x41\x39\x0f\x16\x4b\xfe\xb5\x6f\x92\x8a\x24\x39\xd9\x43\xc1\x18\xa5\xbc\x38\x89\x06\x7b\x5b\xab\x7f\xb1\x6f\xab\xb5\x29\xf1\x39\x60\xe1\x7d\xc0\x46\x6f\xde\x7e\xf0\x5f\xac\x22\x8d\x1f\x04\x0d\xba\x5a\x5a\xbb\xaf\x1a\x55\x6c\xa4\xdd\xa0\x17\xbf\x7f\xe7\x8f\xbb\xd4\x65\x5e\x3f\xd7\xa6\xd1\xf6\x6a\x9e\x63\xb3\xd5\x77\xad\x8a\xb6\x74\x66\xfb\x73\xb6\x6e\xaa\x6f\x66\xab\xf1\x31\xcf\xd2\xd9\x10\xda\x69\x27\x95\x74\x72\x88\x79\xfe\xd4\xf3\x22\x96\x2d\xc1\x59\x7c\x77\x47\xac\x83\x71\x00\x31\xac\xa1\x70\x66\xa7\xad\x93\xbb\x1a\x59\x7a\x06\x67\xea\x9d\x20\x1e\x9c\xd7\x7a\x0f\x98\xd1\x3c\x63\x04\xb1\x8c\x3a\xe1\x85\xdf\x03\xe6\x19\x03\x05\xe1\x3d\x58\xf6\xc5\x03\xe8\x91\x42\xc1\x09\x4b\x96\x85\x14\x09\x46\x07\xf5\x55\xd9\xd1\xcd\x0b\x9f\x1b\xff\x6c\x8c\x3f\xdd\x52\xd1\x54\x5b\xdd\x1f\x54\xff\x3a\xde\xd4\x89\x0b\xa3\x39\x31\x4a\x43\xba\xb8\x3f\xa3\xfc\x6e\xe8\x88\x12\xe2\x84\x30\xc8\xc3\x20\xea\xe1\x75\xd5\xfe\x5e\x64\xe8\xf9\xdb\x22\x67\x07\x3d\x3a\x4c\x35\x3e\x56\xf6\x7b\x30\xe7\xdf\x2e\xaa\xf6\xe5\x7f\xf8\x78\x03\xeb\x7e\x55\xe7\x2c\x7f\x15\x1e\x76\x36\xf5\x7e\x04\x00\x00\xff\xff\xa3\x7c\xa1\x83\xfd\x03\x00\x00")

func sql0040_userSqlBytes() ([]byte, error) {
	return bindataRead(
		_sql0040_userSql,
		"sql/0040_user.sql",
	)
}

func sql0040_userSql() (*asset, error) {
	bytes, err := sql0040_userSqlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "sql/0040_user.sql", size: 1021, mode: os.FileMode(493), modTime: time.Unix(1615486513, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _sql0060_assetSql = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xe4\x55\x4d\x6f\xdb\x3a\x10\xbc\xeb\x57\x2c\x72\x89\x8d\x17\x3f\x24\xc6\x4b\x2e\x39\xc9\xd2\xda\xd1\xab\x22\x39\x14\xd5\x26\xbd\x08\xac\xb4\x8d\x09\x58\xb2\x20\x52\x70\xdb\x5f\x5f\xe8\xd3\x8e\xec\x38\x0d\xda\x5b\xaf\xdc\xd9\x21\x39\x33\x5c\x4e\x26\xf0\x4f\x2a\x9f\x0b\xa1\x09\xc2\xdc\x98\x4c\x20\x78\x70\x41\x66\xa0\x28\xd6\x72\x93\xc1\x79\x98\x9f\x83\x54\x40\xdf\x28\x2e\x35\x25\xb0\x5d\x51\x06\x7a\x25\x15\x34\x7d\x15\x48\x2a\x10\x79\xbe\x96\x94\x18\x86\xc5\xd0\xe4\x08\xdc\x9c\xb9\x08\xce\x1c\x3c\x9f\x03\x3e\x3a\x01\x0f\x60\x25\x8b\xcd\xbf\x42\x29\xd2\x6a\x64\x00\x00\xc8\x04\xc2\xd0\xb1\x61\xc9\x9c\x7b\x93\x3d\xc1\x07\x7c\x02\x1b\xe7\x66\xe8\x72\x78\xa6\x2c\x2a\x44\x96\x6c\xd2\xa8\x2c\x65\x32\x1a\x5f\xd4\x2d\xa2\x4c\x24\x65\x31\x45\x5d\x6f\xc5\xef\x85\xae\xdb\x94\x37\xdb\x8c\x8a\xae\xd6\x2c\xc5\x05\x09\x4d\x49\x24\x34\x70\xe7\x1e\x03\x6e\xde\x2f\xf9\xe7\xbe\xaf\xdf\xd0\x0a\x19\x43\x8f\x47\x3d\xa8\x69\x2f\xf3\xe4\x77\xda\xb5\xd4\x6b\x82\x8f\x26\xb3\xee\x4c\x36\x9a\x5e\xdf\x8c\x07\x27\xfe\x2a\xd7\x94\x89\x74\x87\xb9\xbe\x9a\x0e\x31\x09\xa9\xb8\x90\x79\xad\x75\x07\xbb\xba\x9c\xfe\xd7\x6a\x92\xca\x94\x22\xfd\x3d\x3f\xb9\x8f\x92\x3f\x08\x66\xce\xc2\xf1\xf8\xe1\xe1\x2f\x1b\x4c\x5e\x7e\x59\xcb\x18\x66\xbe\xef\xa2\xe9\xf5\xd5\xb9\xe9\x06\x38\xa4\x5b\x89\xe9\xf5\x0d\xd4\xbb\xdd\xf4\x07\x21\x2d\x12\xa1\x05\xfc\x1f\xf8\xde\xac\x59\x9b\xfb\x0c\x9d\x85\x57\x7b\x3b\xda\x73\x6f\x0c\x0c\xe7\xc8\xd0\xb3\xb0\x4b\x46\x5b\x54\xa3\xaa\xea\x57\xfb\xbb\xc8\x11\x2c\x33\xb0\x4c\x1b\x8f\xd0\x75\x6e\x1f\x72\x95\x8a\x8a\x57\x78\x8c\xf1\x6d\x9f\xd2\xd0\x73\x1e\x42\x04\xc7\xb3\xf1\x71\x10\xd6\x3a\xa7\x51\x2e\xf4\xaa\xa2\xd8\x8f\xee\xde\x25\x2e\x7a\xfb\xc6\xb7\x1d\xe7\xeb\x64\x95\x3c\x43\xb2\x4e\xb2\xea\x50\x36\xf3\x97\xc0\x99\xb3\x58\x20\xab\x08\xda\xe6\x26\x81\x91\x96\x29\x29\x2d\xd2\x7c\x40\xb1\xbb\x4d\xd7\x3a\x6c\x30\x00\x66\x58\x09\x07\xe1\xd2\xae\x80\x2f\x09\x8c\x5a\x55\x40\xd3\xba\x03\xe6\x7f\x32\x00\xf0\x11\xad\x90\x23\x2c\x99\x6f\xa1\x1d\x32\x6c\x45\x1d\xf0\x8e\xce\x76\x8f\xe3\x6c\x4f\xd5\xd3\x6f\x3f\x12\xf1\x3a\x2a\x36\x6b\x6a\x87\x40\xb3\x78\xfc\x39\x57\xb0\xd7\x4a\x24\x92\x48\xc4\x31\x29\xd5\x07\xf6\x20\xd7\x9c\x85\x6d\x6e\xb6\x85\xd4\xf4\x26\xbe\x4e\x7a\x1f\xf0\xe2\x5d\x0d\x2f\x83\xde\x5e\xea\x48\xca\x1b\xdf\x7f\x35\xe2\xad\x02\x87\x3c\x8d\x82\x27\x68\xf6\x87\x6a\x7f\x9e\x8b\x4e\xd2\xb1\xf1\x3e\xc3\x9a\x07\xf5\xa6\x61\x15\xec\xef\x36\xac\x55\xe0\x5d\x23\xe9\xa4\x61\x1d\x61\x6d\xd8\xfe\x7f\x6d\x6f\xb6\xd9\x1f\xf8\xb1\x9b\xa9\x53\x27\xe0\xc5\x54\x39\xba\xbe\x7b\xbc\xa7\x00\xf5\x55\x6f\x8d\x9f\x01\x00\x00\xff\xff\x87\x18\xc6\xbd\x5d\x08\x00\x00")

func sql0060_assetSqlBytes() ([]byte, error) {
	return bindataRead(
		_sql0060_assetSql,
		"sql/0060_asset.sql",
	)
}

func sql0060_assetSql() (*asset, error) {
	bytes, err := sql0060_assetSqlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "sql/0060_asset.sql", size: 2141, mode: os.FileMode(420), modTime: time.Unix(1615821604, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _sql0100_optionSql = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xac\x90\xc1\x4e\x83\x40\x10\x86\xef\xfb\x14\xff\xad\x10\x8b\x07\x13\xbd\xf4\x44\xcb\x36\xa2\x08\x75\x01\x63\x4f\x66\xc3\x4e\x64\x92\x76\xd9\x74\xc1\xfa\xf8\xa6\x50\x0d\x0f\xe0\x75\xe6\xfb\x66\x92\x2f\x8a\x70\x73\xe4\xcf\x93\xee\x09\xb5\x13\x51\x84\xf2\x35\x03\x5b\x78\x6a\x7a\xee\x2c\x16\xb5\x5b\x80\x3d\xe8\x9b\x9a\xa1\x27\x83\x73\x4b\x16\x7d\xcb\x1e\x93\x77\x81\xd8\x43\x3b\x77\x60\x32\x62\xa3\x64\x5c\x49\x54\xf1\x3a\x93\x48\xb7\xc8\x8b\x0a\xf2\x3d\x2d\xab\x12\x2d\x9f\xba\xdb\xce\x5d\x0c\x1f\x08\x00\xd0\x83\x61\xb2\x0d\x7d\xb0\x41\x5d\xa7\xc9\x48\xe7\x75\x96\x41\xc9\xad\x54\x32\xdf\xc8\xab\xf6\x4b\xfa\x80\x4d\xb8\x1c\x65\xab\x8f\x84\xb7\x58\x6d\x1e\x63\x15\xdc\xdd\x3f\x84\x7f\xf6\xb4\xff\xd2\x87\x81\xf0\x54\x16\xf9\x7a\x1a\xec\x54\xfa\x12\xab\x3d\x9e\xe5\x3e\x98\x7d\x5e\x8e\x97\x42\x11\xae\x84\x98\xe7\x48\xba\xb3\xfd\x87\x20\x89\x2a\x76\xd7\x1c\xf3\x00\xab\x9f\x00\x00\x00\xff\xff\x8b\x95\xf3\x30\x7a\x01\x00\x00")

func sql0100_optionSqlBytes() ([]byte, error) {
	return bindataRead(
		_sql0100_optionSql,
		"sql/0100_option.sql",
	)
}

func sql0100_optionSql() (*asset, error) {
	bytes, err := sql0100_optionSqlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "sql/0100_option.sql", size: 378, mode: os.FileMode(493), modTime: time.Unix(1615486399, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _sql0200_request_tokenSql = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xac\x94\x4f\x73\xda\x30\x10\xc5\xef\xfe\x14\x7b\x03\x4f\x43\x0f\x69\x9a\x4b\x4e\x8e\x2d\x5a\xb7\xc6\x50\x59\xee\x90\x5e\x34\x1e\x6b\x07\x34\x05\x49\x95\xe4\x49\xfa\xed\x3b\xfe\x07\x81\xc0\x4c\x0e\xbd\xee\xee\xfb\x59\x4f\x7a\xde\xd9\x0c\x3e\xec\xe5\xc6\x56\x1e\xa1\x34\xc1\x6c\x06\xc5\x8f\x0c\xa4\x02\x87\xb5\x97\x5a\xc1\xa4\x34\x13\x90\x0e\xf0\x05\xeb\xc6\xa3\x80\xe7\x2d\x2a\xf0\x5b\xe9\xa0\xd7\xb5\x43\xd2\x41\x65\xcc\x4e\xa2\x08\x62\x4a\x22\x46\x80\x45\x8f\x19\x81\x74\x0e\xf9\x92\x01\x59\xa7\x05\x2b\x60\x2b\xad\xfe\x68\xf1\x4f\x83\xce\x73\xaf\x7f\xa3\x72\xd3\x00\x00\x40\x0a\x28\xcb\x34\x81\x15\x4d\x17\x11\x7d\x82\xef\xe4\x09\x12\x32\x8f\xca\x8c\xc1\x06\x15\xb7\x95\x12\x7a\xcf\x9b\x46\x8a\x69\x78\xd3\x49\x6a\x8b\x95\x47\xc1\x2b\x0f\x2c\x5d\x90\x82\x45\x8b\x15\xfb\xd5\x7d\x2d\x2f\xb3\xec\x20\x8f\x4b\x4a\x49\xce\xf8\x61\xa8\x97\x57\x8d\x90\xa8\x6a\xe4\xe3\xa7\x47\xe1\xd0\x6e\xcd\xd4\x9d\xb7\x2b\x13\x8d\x43\x3b\xb6\xfa\x8a\xff\x6b\x10\x7e\x46\x34\xfe\x1a\xd1\xe9\xa7\xdb\xf0\x4c\xe0\x6a\x6d\x10\xbe\x15\xcb\xfc\xb1\x2f\xe0\x8b\x91\x16\xdd\x35\x07\xfd\x90\xa9\x9c\xab\xb5\x38\x82\xef\xef\xc6\x0b\xd0\x02\x79\xbd\xad\x76\x3b\x54\x1b\x04\x46\xd6\xec\x4c\x7b\x3a\xc1\xf7\xe8\xb7\x5a\x40\x47\xb9\x0b\xdf\xde\xd4\xa4\xb8\xfd\x7c\x3f\x39\xf8\xe7\x8d\x95\x1d\xb5\xaf\x58\x14\xd2\x62\xed\xcf\xca\x3b\xbd\x91\x8a\x57\xde\xe3\xde\x78\x07\x69\x3e\xd4\x9d\x6f\x03\x75\x9c\x9b\x2f\x29\x49\xbf\xe4\xdd\xcb\x4e\x5f\x5d\x7e\x08\x94\xcc\x09\x25\x79\x4c\x86\x7c\x8c\x4d\x37\x6d\xbb\xcb\x1c\x12\x92\x11\x46\x20\x8e\x8a\x38\x4a\xc8\x25\xdc\xc9\x63\x5d\x20\x1e\xfb\xef\x87\x0e\xef\xfb\x96\xd6\x36\xae\x60\x82\xf0\x21\x18\xf3\x9f\xe6\x09\x59\x9f\xe5\xff\x24\xfa\xbc\x32\xa6\x45\x5c\xfa\x29\x4e\x1d\xdd\x74\xd1\x0a\x1f\xde\x8f\x6e\xcf\x78\x8d\x3d\x18\x3b\x40\x83\xd7\x1b\x20\xd1\xcf\xea\x3f\xec\x80\x84\x2e\x57\xc3\x06\xb8\x70\x84\x87\x7f\x01\x00\x00\xff\xff\xa2\xf4\x86\xa9\x74\x04\x00\x00")

func sql0200_request_tokenSqlBytes() ([]byte, error) {
	return bindataRead(
		_sql0200_request_tokenSql,
		"sql/0200_request_token.sql",
	)
}

func sql0200_request_tokenSql() (*asset, error) {
	bytes, err := sql0200_request_tokenSqlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "sql/0200_request_token.sql", size: 1140, mode: os.FileMode(493), modTime: time.Unix(1615486413, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _sql0220_access_tokenSql = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xac\x53\x4d\x6f\x9b\x40\x10\xbd\xf3\x2b\xde\x2d\x58\xad\x7b\xaa\x7a\xf1\x69\x03\xe3\x96\x16\x83\xbb\x2c\x95\xd3\x0b\x42\x30\x8a\x57\x89\x17\xb4\x0b\x4d\x7e\x7e\xc5\x57\xea\xc6\x8e\xd4\x43\xaf\xf3\xe6\xbd\xd9\x37\xfb\x66\xbd\xc6\xbb\x93\xbe\xb7\x65\xc7\xc8\x5b\x6f\xbd\x46\xf6\x3d\x86\x36\x70\x5c\x75\xba\x31\xb8\xc9\xdb\x1b\x68\x07\x7e\xe6\xaa\xef\xb8\xc6\xd3\x91\x0d\xba\xa3\x76\x98\x78\x43\x93\x76\x28\xdb\xf6\x51\x73\xed\x05\x92\x84\x22\x28\x71\x1b\x13\xa2\x2d\x92\x54\x81\x0e\x51\xa6\x32\x1c\xb5\x6d\x3e\x94\x55\xc5\xce\x15\x5d\xf3\xc0\xc6\xf9\x1e\x00\xe8\x1a\x79\x1e\x85\xd8\xcb\x68\x27\xe4\x1d\xbe\xd1\x1d\x42\xda\x8a\x3c\x56\xb8\x67\x53\xd8\xd2\xd4\xcd\xa9\xe8\x7b\x5d\xfb\xab\xf7\x23\xa5\xb2\x5c\x76\x5c\x17\x65\x07\x15\xed\x28\x53\x62\xb7\x57\x3f\xc7\x61\x49\x1e\xc7\x2f\xf4\x20\x97\x92\x12\x55\xbc\x34\x4d\xf4\xb2\xaf\x35\x9b\x8a\x8b\x65\xf4\x42\x9c\xe1\xc1\x4b\x35\x5a\x7b\xa3\x43\x3b\xd7\xb3\x85\xa2\x83\x9a\x0a\xbd\x63\xbb\xf4\x4e\x95\xd1\x61\xd1\x3b\xc6\x0f\x21\x83\x2f\x42\xfa\x9f\x3e\xce\xaf\x77\x55\xd3\x32\xbe\x66\x69\x72\x3b\xdb\x79\x2c\xf5\xc9\x9d\x57\xf8\xb9\xd5\x96\xdd\x2b\x83\x13\x66\xf9\x57\xf3\x70\x61\x7e\xc2\xb6\xa9\xa4\xe8\x73\x32\xee\xd0\x3f\xb3\xb9\x82\xa4\x2d\x49\x4a\x02\x5a\x3e\x62\x06\x9d\x3f\xa0\x69\x82\x90\x62\x52\x84\x40\x64\x81\x08\xe9\x9a\xdc\x5f\x6b\xb9\xa2\xf8\x07\xff\x77\xd1\x79\x71\x97\x6a\x03\xf0\x86\x8c\xb7\xda\x78\x4b\xd0\xa2\x24\xa4\xc3\xab\xa0\x9d\x67\x6c\xf8\x01\x3b\x48\x5c\x49\xdf\x32\x7b\xe3\x79\xe7\x77\x10\x36\x4f\xe6\x3f\x5c\x42\x28\xd3\xfd\x7c\x07\x97\xb3\x37\xbf\x03\x00\x00\xff\xff\x7b\x07\x31\x7b\x79\x03\x00\x00")

func sql0220_access_tokenSqlBytes() ([]byte, error) {
	return bindataRead(
		_sql0220_access_tokenSql,
		"sql/0220_access_token.sql",
	)
}

func sql0220_access_tokenSql() (*asset, error) {
	bytes, err := sql0220_access_tokenSqlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "sql/0220_access_token.sql", size: 889, mode: os.FileMode(420), modTime: time.Unix(1615486419, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _sql0240_sessionSql = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xac\x52\xcd\x8e\xa2\x40\x10\xbe\xf3\x14\xdf\x4d\xcc\x2e\xfb\x02\x9e\x58\x28\x36\x64\x11\xdc\xa6\x49\x74\x2f\xa4\x43\x57\xb4\xb3\x6b\x43\x68\x18\x7d\xfc\x89\xc2\x18\xcd\xe8\x6d\x8e\x5d\xdf\x4f\x75\x55\x7d\x41\x80\x6f\x47\xb3\xef\xd5\xc0\xa8\x3a\x2f\x08\x50\xfe\xc9\x60\x2c\x1c\x37\x83\x69\x2d\x16\x55\xb7\x80\x71\xe0\x33\x37\xe3\xc0\x1a\xa7\x03\x5b\x0c\x07\xe3\x30\xe9\x2e\x24\xe3\xa0\xba\xee\xbf\x61\xed\x45\x82\x42\x49\x90\xe1\xcf\x8c\x90\x26\xc8\x0b\x09\xda\xa6\xa5\x2c\x71\x30\x7d\xfb\xc3\xb1\x73\xa6\xb5\xce\xf7\x00\xc0\x68\x54\x55\x1a\x63\x23\xd2\x75\x28\x76\xf8\x4d\x3b\xc4\x94\x84\x55\x26\xb1\x67\x5b\xf7\xca\xea\xf6\x58\x8f\xa3\xd1\xfe\xf2\xfb\x55\xa2\x46\x6d\xd8\x36\x5c\xcf\xda\xa9\x3a\x3a\xee\x1f\x2b\x5a\x0d\x0a\x92\xb6\x72\x7a\x36\x3d\xab\x81\x75\xad\x06\xc8\x74\x4d\xa5\x0c\xd7\x1b\xf9\xf7\xfa\xbd\xbc\xca\xb2\x5b\xd7\xa8\x12\x82\x72\x59\xdf\x48\x93\x9c\xcf\x9d\xe9\xd9\xbd\x92\x4f\xa4\x9e\xdf\xda\x7f\x4f\x7a\xdc\x08\x49\x21\x28\xfd\x95\x5f\xc7\xf4\xef\x06\x59\x42\x50\x42\x82\xf2\x88\xe6\x35\x7d\x80\xce\xbf\xa0\x45\x8e\x98\x32\x92\x84\x28\x2c\xa3\x30\xa6\x27\x76\xf3\x06\x3e\x5b\x5d\x80\x17\x36\xde\x72\xe5\x79\xde\x7d\x06\xe2\xf6\x64\xbf\x20\x05\xb1\x28\x36\x73\x06\x1e\xae\xbe\x7a\x0f\x00\x00\xff\xff\xc5\xce\x04\x91\x70\x02\x00\x00")

func sql0240_sessionSqlBytes() ([]byte, error) {
	return bindataRead(
		_sql0240_sessionSql,
		"sql/0240_session.sql",
	)
}

func sql0240_sessionSql() (*asset, error) {
	bytes, err := sql0240_sessionSqlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "sql/0240_session.sql", size: 624, mode: os.FileMode(420), modTime: time.Unix(1608157203, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _sql0260_secretsSql = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xac\x91\xc1\xae\x9b\x30\x10\x45\xf7\x7c\xc5\xdd\x3d\x50\x4b\xa5\xb6\x52\x37\x59\xb9\x30\xb4\xa8\x04\x52\x63\xaa\xa4\x1b\x84\x60\x14\xac\x26\x80\xb0\x51\x92\xbf\xaf\x12\x12\x14\x65\xfd\x96\xd6\x99\x7b\x3d\xf6\xf1\x7d\x7c\x38\xea\xfd\x58\x59\x46\x31\x38\xbe\x8f\xfc\x77\x02\xdd\xc1\x70\x6d\x75\xdf\xe1\xad\x18\xde\xa0\x0d\xf8\xcc\xf5\x64\xb9\xc1\xa9\xe5\x0e\xb6\xd5\x06\x73\xee\x3a\xa4\x0d\xaa\x61\x38\x68\x6e\x9c\x40\x92\x50\x04\x25\xbe\x27\x84\x38\x42\x9a\x29\xd0\x36\xce\x55\x8e\x56\x8f\xfd\x27\xc3\xf5\xc8\xd6\xb8\x0e\x00\xe8\x06\x45\x11\x87\xd8\xc8\x78\x2d\xe4\x0e\xbf\x68\x87\x90\x22\x51\x24\x0a\x7b\xee\xca\xb1\xea\x9a\xfe\x58\x4e\x93\x6e\x5c\xef\xe3\x2d\x62\x2f\x03\xe3\x8f\x90\xc1\x4f\x21\xdd\xaf\x5f\xbc\xdb\x05\x69\x91\x24\x33\xae\xa6\x46\x73\x57\x73\xf9\xa8\x7e\xc1\x87\x7d\x3f\x6a\xdb\x1e\x97\x8a\xcf\xdf\xee\xc5\xff\xf8\x02\x45\x5b\x35\x9f\xea\x91\x2b\xcb\x4d\x59\x59\xa8\x78\x4d\xb9\x12\xeb\x8d\xfa\xbb\xb4\x2d\x5b\x06\x85\x94\x94\xaa\x72\x19\x9a\xe3\x7c\x1e\xf4\xc8\xe6\x25\x3e\xb3\x28\x93\x14\xff\x48\x6f\x8f\x75\x9f\xf6\xf5\x20\x29\x22\x49\x69\x40\xf7\xbf\x7a\x40\xe3\x5e\x69\x96\x22\xa4\x84\x14\x21\x10\x79\x20\x42\x72\xbc\x95\xe3\x3c\x0b\x0c\xfb\x53\xf7\x0e\x0a\x43\x99\x6d\xee\x02\x9f\x95\xad\xfe\x07\x00\x00\xff\xff\x2e\xbf\xd3\x68\x2c\x02\x00\x00")

func sql0260_secretsSqlBytes() ([]byte, error) {
	return bindataRead(
		_sql0260_secretsSql,
		"sql/0260_secrets.sql",
	)
}

func sql0260_secretsSql() (*asset, error) {
	bytes, err := sql0260_secretsSqlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "sql/0260_secrets.sql", size: 556, mode: os.FileMode(420), modTime: time.Unix(1608531281, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

// Asset loads and returns the asset for the given name.
// It returns an error if the asset could not be found or
// could not be loaded.
func Asset(name string) ([]byte, error) {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[cannonicalName]; ok {
		a, err := f()
		if err != nil {
			return nil, fmt.Errorf("Asset %s can't read by error: %v", name, err)
		}
		return a.bytes, nil
	}
	return nil, fmt.Errorf("Asset %s not found", name)
}

// MustAsset is like Asset but panics when Asset would return an error.
// It simplifies safe initialization of global variables.
func MustAsset(name string) []byte {
	a, err := Asset(name)
	if err != nil {
		panic("asset: Asset(" + name + "): " + err.Error())
	}

	return a
}

// AssetInfo loads and returns the asset info for the given name.
// It returns an error if the asset could not be found or
// could not be loaded.
func AssetInfo(name string) (os.FileInfo, error) {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[cannonicalName]; ok {
		a, err := f()
		if err != nil {
			return nil, fmt.Errorf("AssetInfo %s can't read by error: %v", name, err)
		}
		return a.info, nil
	}
	return nil, fmt.Errorf("AssetInfo %s not found", name)
}

// AssetNames returns the names of the assets.
func AssetNames() []string {
	names := make([]string, 0, len(_bindata))
	for name := range _bindata {
		names = append(names, name)
	}
	return names
}

// _bindata is a table, holding each asset generator, mapped to its name.
var _bindata = map[string]func() (*asset, error){
	"sql/0000_initialize.sql": sql0000_initializeSql,
	"sql/0010_audience.sql": sql0010_audienceSql,
	"sql/0020_application.sql": sql0020_applicationSql,
	"sql/0030_role.sql": sql0030_roleSql,
	"sql/0040_user.sql": sql0040_userSql,
	"sql/0060_asset.sql": sql0060_assetSql,
	"sql/0100_option.sql": sql0100_optionSql,
	"sql/0200_request_token.sql": sql0200_request_tokenSql,
	"sql/0220_access_token.sql": sql0220_access_tokenSql,
	"sql/0240_session.sql": sql0240_sessionSql,
	"sql/0260_secrets.sql": sql0260_secretsSql,
}

// AssetDir returns the file names below a certain
// directory embedded in the file by go-bindata.
// For example if you run go-bindata on data/... and data contains the
// following hierarchy:
//     data/
//       foo.txt
//       img/
//         a.png
//         b.png
// then AssetDir("data") would return []string{"foo.txt", "img"}
// AssetDir("data/img") would return []string{"a.png", "b.png"}
// AssetDir("foo.txt") and AssetDir("notexist") would return an error
// AssetDir("") will return []string{"data"}.
func AssetDir(name string) ([]string, error) {
	node := _bintree
	if len(name) != 0 {
		cannonicalName := strings.Replace(name, "\\", "/", -1)
		pathList := strings.Split(cannonicalName, "/")
		for _, p := range pathList {
			node = node.Children[p]
			if node == nil {
				return nil, fmt.Errorf("Asset %s not found", name)
			}
		}
	}
	if node.Func != nil {
		return nil, fmt.Errorf("Asset %s not found", name)
	}
	rv := make([]string, 0, len(node.Children))
	for childName := range node.Children {
		rv = append(rv, childName)
	}
	return rv, nil
}

type bintree struct {
	Func     func() (*asset, error)
	Children map[string]*bintree
}
var _bintree = &bintree{nil, map[string]*bintree{
	"sql": &bintree{nil, map[string]*bintree{
		"0000_initialize.sql": &bintree{sql0000_initializeSql, map[string]*bintree{}},
		"0010_audience.sql": &bintree{sql0010_audienceSql, map[string]*bintree{}},
		"0020_application.sql": &bintree{sql0020_applicationSql, map[string]*bintree{}},
		"0030_role.sql": &bintree{sql0030_roleSql, map[string]*bintree{}},
		"0040_user.sql": &bintree{sql0040_userSql, map[string]*bintree{}},
		"0060_asset.sql": &bintree{sql0060_assetSql, map[string]*bintree{}},
		"0100_option.sql": &bintree{sql0100_optionSql, map[string]*bintree{}},
		"0200_request_token.sql": &bintree{sql0200_request_tokenSql, map[string]*bintree{}},
		"0220_access_token.sql": &bintree{sql0220_access_tokenSql, map[string]*bintree{}},
		"0240_session.sql": &bintree{sql0240_sessionSql, map[string]*bintree{}},
		"0260_secrets.sql": &bintree{sql0260_secretsSql, map[string]*bintree{}},
	}},
}}

// RestoreAsset restores an asset under the given directory
func RestoreAsset(dir, name string) error {
	data, err := Asset(name)
	if err != nil {
		return err
	}
	info, err := AssetInfo(name)
	if err != nil {
		return err
	}
	err = os.MkdirAll(_filePath(dir, filepath.Dir(name)), os.FileMode(0755))
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(_filePath(dir, name), data, info.Mode())
	if err != nil {
		return err
	}
	err = os.Chtimes(_filePath(dir, name), info.ModTime(), info.ModTime())
	if err != nil {
		return err
	}
	return nil
}

// RestoreAssets restores an asset under the given directory recursively
func RestoreAssets(dir, name string) error {
	children, err := AssetDir(name)
	// File
	if err != nil {
		return RestoreAsset(dir, name)
	}
	// Dir
	for _, child := range children {
		err = RestoreAssets(dir, filepath.Join(name, child))
		if err != nil {
			return err
		}
	}
	return nil
}

func _filePath(dir, name string) string {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	return filepath.Join(append([]string{dir}, strings.Split(cannonicalName, "/")...)...)
}

