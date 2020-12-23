// Code generated by go-bindata.
// sources:
// sql/0000_initialize.sql
// sql/0010_audience.sql
// sql/0020_application.sql
// sql/0030_role.sql
// sql/0040_user.sql
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

var _sql0000_initializeSql = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xac\x55\x41\x4f\xe3\x48\x13\x3d\xa7\x7f\xc5\x53\xbe\x48\x8e\x45\x3c\x9a\xf9\x6e\x4b\xc4\x21\x84\x26\x13\x29\x38\xbb\xb6\xb3\x20\x4d\x98\xa8\xd7\x2e\xe2\x96\xec\xb6\xa7\xbb\x0d\x64\xc5\x8f\x5f\xb5\x4d\x98\xc0\xc0\xc2\x61\x2f\x18\x77\x3d\x57\xbd\x57\x55\xfd\x12\x04\x38\x2a\xe5\x56\x0b\x4b\x58\xd5\x2c\x08\x10\xff\xb1\x80\x54\x30\x94\x5a\x59\x29\x78\xab\xda\x83\x34\xa0\x7b\x4a\x1b\x4b\x19\xee\x72\x52\xb0\xb9\x34\xe8\xbe\x73\x20\x69\x20\xea\xba\x90\x94\xb1\x69\xc4\x27\x09\x47\x3c\xfd\xca\x2f\x26\x98\x9f\x23\x5c\x26\xe0\x57\xf3\x38\x89\x91\x4b\x5d\x8d\xf7\x08\x7e\x95\xf0\x30\x9e\x2f\xc3\x17\xa0\x7e\xbd\x4d\xf5\xae\xb6\x55\xff\x7d\x68\xa3\x44\x9a\x92\xb2\x1f\x80\xe6\xc6\x56\x9a\xfa\x63\xc6\x0e\x25\xc7\x56\x58\x2a\x49\xd9\x53\xda\x4a\xb5\x4f\xb2\x8c\x10\xf1\xdf\x17\x93\x29\xc7\xf9\x2a\x9c\x26\x2e\x9d\xe3\xfe\xa9\xa9\x33\x61\x69\x63\x65\x49\xc6\x8a\xb2\x1e\xfa\x2c\xe2\xc9\x2a\x0a\x63\x24\xd1\x7c\x36\xe3\x11\x26\x31\x06\x03\x76\xc6\xa7\x8b\x49\xc4\x19\x00\xa4\x55\x81\x84\x5f\x25\x38\x3e\xc1\x8f\xa6\xb2\xb4\x91\x19\x29\x3b\x4c\x66\x9b\x49\x34\xfb\xf3\xdb\xe7\x6b\x7f\xcc\x4e\xf9\x6c\x1e\xb6\xf0\x90\x5f\x3a\xa4\x7b\xfc\xef\x04\x1d\xed\x61\x5a\x15\x23\x84\xcb\xcb\xa1\x7f\x7c\x6c\xe9\xde\xfa\x63\x06\x74\xa5\x1d\x72\xcc\x78\x78\x36\x66\x83\x01\x16\x93\x70\xb6\x9a\xcc\x38\xea\xa2\xde\x9a\x1f\xc5\x98\xbd\x2b\xca\x14\xcd\x56\xde\xec\x86\xfd\x5b\x51\x34\xd4\x6f\xb9\x8e\xd0\xaf\x4a\x69\xbb\x17\x9c\xf1\xf3\xc9\x6a\x91\xc0\xf3\x0e\xf4\xba\x40\x27\x16\x08\x02\x68\x2a\xab\x5b\x32\xe8\x06\x62\x30\xcc\xa4\x48\xb5\xb4\x32\x85\x91\x5b\x65\x7c\xdc\xe8\xaa\x84\xc0\x56\xde\x92\x82\xb1\x5a\xaa\x2d\x82\x80\x01\x97\xf3\xe4\xeb\xcf\x59\x52\xd6\x77\x79\x87\x6d\x33\x62\xbe\xe0\xd3\x04\xfb\xd8\x9e\xa3\xef\x10\x8f\xff\x33\xc0\x1f\x75\x1c\x8a\xea\x8e\x74\x2a\x0c\x19\xd8\x9c\x1e\x6b\x30\xa0\xff\x14\xf8\x35\x75\x1b\x7a\x23\x2f\x70\x1e\x2d\x2f\x9e\x51\x3b\xa8\xa6\xa9\x2e\x44\xea\x24\xab\x9d\xcd\x9d\x1a\x9b\x0b\xeb\x19\xa8\xca\x42\xa0\x20\x6b\x49\x8f\xa0\x9a\xf2\x2f\xf7\xec\x07\xfd\x11\x2a\x8d\x46\x65\xa4\x4d\xea\xa6\xea\x6d\x3c\x1f\x77\xd2\xe6\x2e\xe8\x78\xe6\xbb\x3a\x27\x25\x5e\xed\x81\xa6\x2d\xdd\xd7\x9b\xc7\xaa\x7b\xc6\x23\x78\xdf\xbe\x8b\xe0\xef\xcf\xc1\x6f\x1e\x1e\x1e\xf6\x63\x7b\x78\x80\xb7\x5e\x6f\x82\xeb\x23\x6f\x04\x2f\x70\x7f\xb6\xd2\x7b\x43\xde\xcf\xee\x1c\xa8\xb3\x5a\x96\xc6\xf1\x82\xbc\x71\xdd\xdc\x81\xee\xa5\xb1\xa8\x54\xdb\xdb\x9c\x44\xe6\xd4\x58\x21\x0b\x54\x37\x2f\xfa\xed\x3e\x2e\x3f\x20\xe2\x4d\x4d\xc1\x7a\x7d\x34\x70\xac\x3d\x7f\x04\xef\xfb\x7a\x1d\x74\x2f\xaf\x0b\x38\x68\x9b\x53\x70\x58\x70\xbf\xd4\x1d\x70\xcf\xeb\xf9\x55\x71\x8e\x17\x27\xd1\x7c\x9a\x60\x7e\x71\xb1\x4a\x26\xa7\x0b\xde\xf9\x44\xaa\x49\x58\x37\x61\xb8\x4b\xd2\x6d\x70\xab\x54\xa7\xed\xb5\x96\xca\x56\xed\x41\x66\xac\x3b\x68\x4a\x85\xc6\x74\xab\x40\x30\x35\xa5\xf2\x46\x52\x06\x43\xb5\xd0\xc2\x56\xfa\xa3\x0e\xe3\xca\x0d\x7d\x86\x17\xee\xc2\x5e\xba\x8b\x23\xf2\xae\xb7\xa0\xe7\xe8\xfd\x2b\xee\x4b\x8b\x83\x5b\x9e\x27\x5c\x5a\x89\x82\x4c\x4a\x4f\xa0\xff\x5f\xb7\x33\x70\x09\xdb\x76\x38\xe0\xde\xb9\x7a\xfc\x8a\x4f\x57\x09\x87\xf7\xd8\xf8\xc1\x97\x4f\xed\x42\x3a\x86\xac\xb7\x8a\xe7\xe1\xcc\x39\x15\xeb\xcd\xc3\x64\xe9\x4e\xc7\x60\x60\x5d\xa2\xe3\x93\xe7\x4e\x64\x74\x3a\x6a\xb9\xf8\x63\xd6\x63\xbd\x57\x1d\x31\x33\x76\xd4\x4e\xc5\xf1\xf9\xd5\x0c\xdf\xf0\xc2\x57\xbd\x9f\xab\xec\x79\xe4\xac\xba\x53\xff\xc1\x4f\xe1\x3f\x01\x00\x00\xff\xff\x60\x63\x72\x68\x5c\x07\x00\x00")

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

	info := bindataFileInfo{name: "sql/0000_initialize.sql", size: 1884, mode: os.FileMode(493), modTime: time.Unix(1608246101, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _sql0010_audienceSql = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xac\x54\x4d\x6f\x9b\x40\x14\xbc\xf3\x2b\x46\xbe\x04\xab\x71\xd5\x56\x51\x0e\xcd\x09\xc3\xb3\x43\x8b\xc1\x59\x76\x5b\xa7\xaa\x84\x56\x66\x6b\xaf\x6a\x3e\x04\x8b\xd2\x9f\x5f\x81\x1d\x83\x5d\x25\x51\xdb\x1c\x17\x66\x66\xdf\x9b\x79\xfb\x26\x13\xbc\xc9\xf4\xa6\x92\x46\x41\x94\xd6\x64\x82\xf8\x2e\x80\xce\x51\xab\xb5\xd1\x45\x8e\x0b\x51\x5e\x40\xd7\x50\xbf\xd4\xba\x31\x2a\xc5\xc3\x56\xe5\x30\x5b\x5d\x63\xcf\x6b\x41\xba\x86\x2c\xcb\x9d\x56\xa9\x65\xb9\x8c\x1c\x4e\xe0\xce\x34\x20\xf8\x33\x84\x11\x07\xad\xfc\x98\xc7\xd8\xea\xaa\x78\x2b\x9b\x54\xab\x7c\xad\x6a\xdb\x02\x00\x9d\x42\x08\xdf\xc3\x92\xf9\x0b\x87\xdd\xe3\x33\xdd\xc3\xa3\x99\x23\x02\x8e\x8d\xca\x93\x4a\xe6\x69\x91\x25\x4d\xa3\x53\x7b\x7c\xd9\x51\xd6\x95\x92\x46\xa5\x89\x34\xe0\xfe\x82\x62\xee\x2c\x96\xfc\x5b\x77\x51\x28\x82\xe0\x48\x77\x05\x63\x14\xf2\xe4\x08\xda\xd3\x9b\x32\xfd\x1f\x7a\x2e\x33\x85\x2f\x0e\x73\x6f\x1d\x66\x5f\x5f\x8d\x7b\xa2\x08\xfd\x3b\x41\x7b\x54\xbd\x6b\x36\x2f\xa3\x52\x55\xaf\x2b\x5d\x76\x1e\x3e\x82\xdf\xbf\xfb\x70\x75\x68\xd4\x14\x3f\x55\x9e\xc8\xdd\xa6\xa8\xb4\xd9\x66\x3d\xe4\xba\xd7\x1b\x22\x77\xfa\x87\x32\x3a\x53\x98\xfa\x73\x3f\xe4\x67\x98\x5a\xd5\xb5\x2e\x9e\x41\xa1\x83\x65\xca\xc8\x54\x1a\x89\x4f\x71\x14\x4e\xad\xf1\x4d\x1f\x29\xf3\xe7\x73\x62\x07\x03\x93\x56\xa3\x36\x32\x2b\x2d\x60\x4a\xb3\x88\x11\xc4\xd2\x6b\x81\x51\x78\x16\xb5\x05\xcc\x22\x06\x72\xdc\x5b\xb0\xe8\xab\x05\xd0\x8a\x5c\xc1\x09\x4b\x16\xb9\xe4\x09\x46\x7b\xc6\xb9\xb4\x3d\xea\xd3\x1a\x3d\x5d\x4a\xeb\x76\x5f\x85\x1f\xc6\xc4\x38\x22\xf6\x6a\xf5\xb4\xfa\xf6\xa8\x4d\x7e\x74\x89\x51\x7b\x3a\x29\xe6\xa5\x51\x4f\x4a\x55\x65\xba\x73\xbf\x9b\xfa\xe3\xf7\xc7\xe1\x3f\x0e\x07\xa3\x19\x31\x0a\x5d\xfa\xe3\xb1\xe8\x74\xdc\xf6\xe1\x51\x40\x9c\xe0\x3a\xb1\xeb\x78\xdd\x14\xf5\xda\xe0\xb4\x3a\x0d\x7d\xf0\xa8\xec\xc1\xa5\x97\x03\xd2\xf8\x99\x84\xff\xd2\xd6\x61\x9b\xff\xe6\x70\x2f\xd0\xfa\x7c\x7a\xfa\xfe\xb1\xf3\x7c\xb8\xb0\xbc\xe2\x21\x7f\x85\x95\xe5\xb1\x68\x79\x08\xf1\xd4\xf4\x9b\x27\x7f\x0d\x5b\xbd\xf9\x1d\x00\x00\xff\xff\xb4\x75\x39\x77\x44\x05\x00\x00")

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

	info := bindataFileInfo{name: "sql/0010_audience.sql", size: 1348, mode: os.FileMode(493), modTime: time.Unix(1608743408, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _sql0020_applicationSql = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xbc\x55\x4d\x6f\xdb\x38\x10\xbd\xeb\x57\x0c\x7c\x91\x8c\xb5\x17\xbb\x45\xd0\x4b\x4e\x8a\x34\x76\xd4\xda\x92\x43\x49\xad\xd3\x8b\xc0\x8a\x53\x9b\x88\x2d\x09\x22\x0d\x37\xfd\xf5\x85\x3e\x1c\x33\x71\xe2\x36\x68\xd0\x9b\x48\xbe\x99\xf7\x66\xde\x90\x1a\x8f\xe1\x9f\xad\x5c\xd5\x5c\x13\xa4\x95\x35\x1e\x43\x7c\x33\x03\x59\x80\xa2\x5c\xcb\xb2\x00\x3b\xad\x6c\x90\x0a\xe8\x3b\xe5\x3b\x4d\x02\xf6\x6b\x2a\x40\xaf\xa5\x82\x2e\xae\x01\x49\x05\xbc\xaa\x36\x92\x84\xe5\x31\x74\x13\x84\xe4\x76\x81\xb0\x96\x75\xf9\xef\x94\xb9\x61\x92\xb5\x6b\x37\x06\x0c\xd3\x39\x38\x36\xdf\xe9\x75\x59\xcb\x1f\x6d\x78\x96\x97\x82\xec\x11\xd8\xf9\x46\x52\xa1\xb3\xbc\x26\x41\x85\x96\x7c\xa3\x9a\xdd\x8a\x2b\xb5\x2f\x6b\xd1\x7c\xd7\xf4\xad\x26\xb5\xce\x74\x79\x47\x85\x3d\xbc\xb4\x1e\xf8\xdc\xab\x19\x42\x30\x81\x30\x4a\x00\x97\x41\x9c\xc4\x1d\x7d\xab\x2b\x6f\x79\x94\x63\x01\x00\x48\x01\x69\x1a\xf8\xb0\x60\xc1\xdc\x65\xb7\xf0\x11\x6f\xc1\xc7\x89\x9b\xce\x12\x58\x51\x91\xd5\xbc\x10\xe5\x36\xdb\xed\xa4\x70\x86\xa3\x36\x24\xaf\x89\x6b\x12\x19\xd7\x90\x04\x73\x8c\x13\x77\xbe\x48\xbe\xb4\x5c\x61\x3a\x9b\x3d\x84\x7b\x29\x63\xd8\x54\x7b\x00\x75\xe1\xbb\x4a\xfc\x49\x78\xc1\xb7\x04\x9f\x5c\xe6\x5d\xbb\xcc\x79\x7f\x31\x3c\x06\xa6\x61\x70\x93\x62\x87\x52\x9b\xdd\xea\xd7\x28\x41\x2a\xaf\x65\xd5\xba\x76\x00\xff\xff\xdf\xbb\x8b\xbe\x50\x7d\x5f\x11\x24\xb8\x4c\x4e\xc5\xd9\x7b\xfa\x6a\xf7\x54\x94\xd7\xa4\xb3\x3b\xba\x6f\xb1\x7d\x91\xb5\x54\xf0\x21\x8e\xc2\xab\x6e\xbd\x25\xcd\x05\xd7\xbc\xdb\xb3\x0c\xaf\x82\xd0\xc7\x25\x18\xc6\x98\x8e\x43\x14\x3e\x63\x9c\x14\x23\x83\xd5\xf4\x9d\x05\xd3\x29\xb2\xbe\xc5\x99\x96\x5b\x52\x9a\x6f\x2b\x0b\xe0\x0a\x27\x11\x43\x48\x17\x7e\x03\x7c\x2e\xad\x05\x30\x89\x18\xa0\xeb\x5d\x03\x8b\x3e\x5b\x00\xb8\x44\x2f\x4d\x10\x16\x2c\xf2\xd0\x4f\x59\x3f\xc3\x4f\xb3\x3b\x83\xa3\xa5\x83\x97\xd5\x34\x96\x1c\x85\x04\x61\x8c\x2c\x81\x88\xbd\xa5\xa4\x86\xc2\x19\x34\x13\x32\x18\xc1\xa0\x59\x0d\x5e\x79\x2b\xb2\x8a\xea\xad\x54\xea\x70\x41\xcc\xa3\xc3\x55\x79\x18\x06\x86\x13\x64\x18\x7a\xf8\xdc\xed\x92\x62\xd8\xd4\xe4\xe3\x0c\x13\x04\xcf\x8d\x3d\xd7\x6f\xc7\x8e\xef\x84\xa4\x22\xa7\x93\x7c\xcd\xe1\x91\xfe\xf1\xe0\x8d\xba\x56\x60\x30\x0d\x9b\x2b\xea\x18\x49\x46\x46\xd0\x10\xda\x69\x3b\x11\x76\x40\x9b\xd5\x9d\x4f\x71\x22\xfd\xb0\xdb\xdb\x65\x14\x64\x3c\x1d\xce\xe3\x7e\x8d\xe0\x25\x12\xeb\xb5\xbe\xac\x6a\x5e\xe8\xbf\x6e\xc9\x8b\x9d\x3c\x93\xac\x55\x9a\xb5\x6f\xc7\xd3\x27\xdf\x74\xf3\xb7\xbb\x76\xcc\xd7\x75\xcd\xfc\x49\xf9\xe5\xbe\x78\x83\xdf\x94\xcf\xa2\x45\x6f\xc3\x49\xd7\x2e\xcf\x9d\x9a\x03\x75\x1e\xd8\xf9\x77\xf9\x33\x00\x00\xff\xff\x06\x5d\xa6\x2d\x62\x07\x00\x00")

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

	info := bindataFileInfo{name: "sql/0020_application.sql", size: 1890, mode: os.FileMode(493), modTime: time.Unix(1608570003, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _sql0030_roleSql = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xac\x54\xcb\x6e\xdb\x30\x10\xbc\xeb\x2b\x06\xbe\x44\x46\xed\xa2\x2d\x82\x1e\x9a\x93\x22\xad\x1d\xb5\xb2\xe4\x50\x64\xeb\x14\x05\x04\xc2\x24\x6c\x02\xd6\x03\x7a\x20\xfd\xfc\x82\xf2\x4b\x4e\x9a\xf4\xd0\x9c\x0c\x2f\x67\x96\xb3\xb3\x23\x4e\xa7\x78\x97\x9b\x4d\x2d\x5b\x0d\x51\x39\xd3\x29\xd2\xfb\x08\xa6\x40\xa3\xd7\xad\x29\x0b\x5c\x89\xea\x0a\xa6\x81\xfe\xad\xd7\x5d\xab\x15\x1e\xb7\xba\x40\xbb\x35\x0d\xf6\x3c\x0b\x32\x0d\x64\x55\xed\x8c\x56\x8e\xcf\xc8\xe3\x04\xee\xdd\x46\x84\x70\x86\x38\xe1\xa0\x55\x98\xf2\x14\x5b\x53\x97\xef\xeb\x72\xa7\x1b\xd7\x01\x00\xa3\x20\x44\x18\x60\xc9\xc2\x85\xc7\x1e\xf0\x8d\x1e\x10\xd0\xcc\x13\x11\xc7\x46\x17\x59\x2d\x0b\x55\xe6\x59\xd7\x19\xe5\x8e\x27\x3d\x65\x5d\x6b\xd9\x6a\x95\xc9\x16\x3c\x5c\x50\xca\xbd\xc5\x92\xff\xec\x2f\x89\x45\x14\x9d\xe8\xbe\x60\x8c\x62\x9e\x9d\x40\x7b\x7a\x57\xa9\xff\xa1\x17\x32\xd7\xf8\xee\x31\xff\xce\x63\xee\xe7\xeb\xf1\x99\x28\xe2\xf0\x5e\xd0\x1e\xd5\xec\xba\xcd\xbf\x51\x4a\x37\xeb\xda\x54\xbd\x7d\x47\xf0\xc7\x0f\x9f\xae\x0f\x83\xe6\xba\x95\x4a\xb6\x12\x5f\xd3\x24\xbe\x75\xc6\x37\xce\xc9\x59\x16\xce\xe7\xc4\x0e\xb3\x64\xad\xc9\x75\xd3\xca\xbc\x72\x80\x5b\x9a\x25\x8c\x20\x96\x81\x05\x26\xf1\xc0\x71\x07\x98\x25\x0c\xe4\xf9\x77\x60\xc9\x0f\x07\xa0\x15\xf9\x82\x13\x96\x2c\xf1\x29\x10\x8c\xf6\xe8\xa7\x6d\xdd\xd1\xd9\xb4\xd1\xcb\x32\xec\xd0\x67\x05\x61\x9c\x12\xe3\x48\xd8\x9b\x68\xb1\xbd\xdd\x91\x35\x7f\x34\xc1\xc8\xfe\xb3\xbf\xbf\xbe\x5c\xc8\x79\x2d\x6f\x59\xa5\xeb\xdc\x34\x8d\x29\x8b\x3e\x7a\x7d\xed\x98\xbe\xd3\x76\x18\xcd\x88\x51\xec\xd3\x45\x52\x8d\x1a\x5b\xf5\x01\x45\xc4\x09\xbe\x97\xfa\x5e\xd0\xaf\x50\x76\xca\xe8\x62\xfd\xbc\x91\x3d\x3c\x5f\x08\x4e\x2b\x7e\x71\x66\x1d\x0a\xe7\xb1\x8d\xbb\x3b\x68\x32\x19\x90\xc6\xe8\x43\xf0\x54\xd1\x09\x3d\x9c\xe7\xf5\x16\xcf\xa4\x1f\xab\x87\xc5\x0c\x06\x1a\x7c\x86\xee\xc1\xa1\x09\x5e\xea\xde\x27\x72\xf8\x78\x04\xe5\x63\xf1\x06\xcf\x47\xc0\x92\xe5\x61\x99\xe7\x25\xdc\xfc\xb5\x3c\x74\xe1\xc6\xf9\x13\x00\x00\xff\xff\xee\x5f\xa9\xe0\xc9\x04\x00\x00")

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

	info := bindataFileInfo{name: "sql/0030_role.sql", size: 1225, mode: os.FileMode(420), modTime: time.Unix(1608252430, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _sql0040_userSql = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xac\x53\x4d\x6f\xd3\x40\x10\xbd\xfb\x57\x3c\xf5\xd2\x44\x34\x48\x20\x84\x90\x7a\x72\xec\x49\x6b\x70\xec\x74\xbd\x0b\x2d\x17\x6b\x95\x5d\x92\x15\xf1\x87\x76\xd7\x4a\x7f\x3e\xb2\x9d\x26\x69\xa9\xe0\x00\xc7\x9d\x79\x6f\x66\xf6\xcd\x9b\xd9\x0c\x6f\x2a\xb3\xb1\xd2\x6b\x88\x36\x98\xcd\x50\xdc\xa5\x30\x35\x9c\x5e\x7b\xd3\xd4\xb8\x14\xed\x25\x8c\x83\x7e\xd4\xeb\xce\x6b\x85\xfd\x56\xd7\xf0\x5b\xe3\x30\xf2\x7a\x90\x71\x90\x6d\xbb\x33\x5a\x05\x11\xa3\x90\x13\x78\x38\x4f\x09\xc9\x02\x59\xce\x41\xf7\x49\xc1\x0b\x6c\x8d\x6d\xde\x76\x4e\x5b\x37\x09\x00\xc0\x28\x08\x91\xc4\x58\xb1\x64\x19\xb2\x07\x7c\xa1\x07\xc4\xb4\x08\x45\xca\xb1\xd1\x75\x69\x65\xad\x9a\xaa\xec\x3a\xa3\x26\xd3\xab\x81\xb2\xb6\x5a\x7a\xad\x4a\xe9\xc1\x93\x25\x15\x3c\x5c\xae\xf8\xf7\xa1\x49\x26\xd2\xf4\x48\x8f\x04\x63\x94\xf1\xf2\x08\x1a\xe9\x5d\xab\xfe\x85\xbe\x6b\x36\xa6\xc6\xd7\x90\x45\xb7\x21\x9b\xbc\x7b\xff\x69\x7a\xa2\x8a\x2c\xb9\x13\x34\xe2\x5a\xe9\xdc\xbe\xb1\xaa\xdc\x4a\xb7\xc5\x00\xfe\xf8\x61\x7a\xd5\xa7\x9e\xe7\xf5\x63\x6b\xac\x76\x2f\xe6\x79\x6a\xb6\xfe\xa9\x55\xd9\xd5\xde\xec\x7e\xcf\xb6\xb6\xf9\x61\x76\x1a\x9f\x8b\x3c\x9b\x8f\xa1\x4a\x7b\xa9\xa4\x97\x63\x2c\x98\x5e\x07\xc7\x65\xb0\xe4\xe6\x86\xd8\xe1\xfb\xa5\x37\x95\x76\x5e\x56\x6d\x00\xcc\x69\x91\x33\x82\x58\xc5\x3d\x30\xcf\xce\x96\x14\x00\x8b\x9c\x81\xc2\xe8\x16\x2c\xff\x16\x00\x74\x4f\x91\xe0\x84\x15\xcb\x23\x8a\x05\xa3\x03\xfa\x45\xd9\xc9\xc5\x49\xe7\x8b\xf3\x31\xfe\xe4\x89\xd2\x36\x3b\x3d\x18\x63\x78\x3d\x79\xe3\xa8\x2f\xa3\x05\x31\xca\x22\x7a\xe6\x23\xa3\xa6\xfd\xd0\x31\xa5\xc4\x09\x51\x58\x44\x61\x3c\x2c\xa1\xaf\xf6\xf7\x22\x63\xcf\x57\x8b\x0c\xfa\x9d\x5f\x47\xdc\xec\xeb\xff\x70\x1f\x31\xcb\x57\x07\x25\x4e\xff\xb8\x7e\x35\x5c\xb6\xda\x56\xc6\x39\xd3\xd4\xee\x3a\xf8\x15\x00\x00\xff\xff\xf0\x7a\xb4\xe3\xaa\x03\x00\x00")

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

	info := bindataFileInfo{name: "sql/0040_user.sql", size: 938, mode: os.FileMode(493), modTime: time.Unix(1608428804, 0)}
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

	info := bindataFileInfo{name: "sql/0100_option.sql", size: 378, mode: os.FileMode(493), modTime: time.Unix(1607702932, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _sql0200_request_tokenSql = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xac\x93\x4f\x73\xd3\x30\x10\xc5\xef\xfe\x14\x7b\x4b\x3c\x34\x1c\x4a\xe9\xa5\x27\xd7\x56\xc0\xe0\x38\x41\x96\x99\x94\x8b\xc6\x63\xed\x24\x1a\x12\x49\x48\xf2\xb4\x7c\x7b\xc6\xff\x92\x26\x4d\x18\x0e\x5c\xf7\xbd\xf7\x93\x56\xda\x9d\xcd\xe0\xdd\x5e\x6e\x6c\xe5\x11\x4a\x13\xcc\x66\x50\x7c\xcb\x40\x2a\x70\x58\x7b\xa9\x15\x4c\x4a\x33\x01\xe9\x00\x5f\xb0\x6e\x3c\x0a\x78\xde\xa2\x02\xbf\x95\x0e\xfa\x5c\x6b\x92\x0e\x2a\x63\x76\x12\x45\x10\x53\x12\x31\x02\x2c\x7a\xcc\x08\xa4\x73\xc8\x97\x0c\xc8\x3a\x2d\x58\x01\x5b\x69\xf5\x7b\x8b\xbf\x1a\x74\x9e\x7b\xfd\x13\x95\x9b\x06\x00\x00\x52\x40\x59\xa6\x09\xac\x68\xba\x88\xe8\x13\x7c\x25\x4f\x90\x90\x79\x54\x66\x0c\x36\xa8\xb8\xad\x94\xd0\x7b\xde\x34\x52\x4c\xc3\x9b\x2e\x52\x5b\xac\x3c\x0a\x5e\x79\x60\xe9\x82\x14\x2c\x5a\xac\xd8\x8f\xee\xb4\xbc\xcc\xb2\x43\x3c\x2e\x29\x25\x39\xe3\x07\x53\x1f\xaf\x1a\x21\x51\xd5\xc8\xc7\xa3\xc7\xe0\x20\xb7\xcd\xd4\x5d\x6f\x57\x1c\x8d\x43\x3b\x4a\x7d\xc5\xff\x36\x08\xdf\x23\x1a\x7f\x8e\xe8\xf4\xc3\x6d\x78\x16\x70\xb5\x36\x08\x5f\x8a\x65\xfe\xd8\x17\xf0\xc5\x48\x8b\xee\x5a\x07\xbd\xc9\x54\xce\xd5\x5a\x1c\xc1\xf7\x77\xe3\x03\x68\x81\xbc\xde\x56\xbb\x1d\xaa\x0d\x02\x23\x6b\x76\x96\x3d\x75\xf0\x3d\xfa\xad\x16\xd0\x51\xee\xc2\xb7\x2f\x35\x29\x6e\x3f\xde\x4f\x0e\xfd\xf3\xc6\xca\x8e\xda\x57\x2c\x0a\x69\xb1\xf6\x67\xe5\x9d\xde\x48\xc5\x2b\xef\x71\x6f\xbc\x83\x34\x1f\xea\xce\xb7\x03\x75\xf4\xcd\x97\x94\xa4\x9f\xf2\xee\x67\xa7\xaf\x1e\x3f\x04\x4a\xe6\x84\x92\x3c\x26\xc3\x7c\x8c\xa2\x9b\xb6\xea\x32\x87\x84\x64\x84\x11\x88\xa3\x22\x8e\x12\x72\x09\x77\xf2\x59\x17\x88\x47\xfd\xdf\xa1\xc3\xff\xbe\xa5\xb5\xc2\x15\x4c\x10\x3e\x04\xe3\xfc\xa7\x79\x42\xd6\x70\x32\xec\xbc\x32\xa6\x0d\x5d\x5a\x83\xd3\x1e\x6e\xba\x61\x0a\x1f\xfe\x06\x6b\xef\x71\x8d\x36\x5c\xfe\x80\x09\x5e\x6f\x79\xa2\x9f\xd5\x7f\xd8\xf3\x84\x2e\x57\xc3\x96\x5f\xb8\xc2\xc3\x9f\x00\x00\x00\xff\xff\xc6\xa1\xf1\xbb\x58\x04\x00\x00")

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

	info := bindataFileInfo{name: "sql/0200_request_token.sql", size: 1112, mode: os.FileMode(493), modTime: time.Unix(1608583322, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _sql0220_access_tokenSql = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xac\x52\x4d\x6f\x9b\x40\x14\xbc\xf3\x2b\xe6\x16\xac\xd6\x3d\x55\xbd\xf8\xb4\x81\xe7\x96\x16\x83\xbb\x2c\x95\xd3\x0b\x42\xf0\x14\xaf\x12\x2f\x68\x17\x9a\xfc\xfc\x8a\xaf\xd4\xad\x1d\xa9\x87\x5c\xdf\xbc\x99\xb7\x33\x3b\xeb\x35\xde\x9d\xf4\xbd\x2d\x3b\x46\xde\x7a\xeb\x35\xb2\xef\x31\xb4\x81\xe3\xaa\xd3\x8d\xc1\x4d\xde\xde\x40\x3b\xf0\x33\x57\x7d\xc7\x35\x9e\x8e\x6c\xd0\x1d\xb5\xc3\xc4\x1b\x96\xb4\x43\xd9\xb6\x8f\x9a\x6b\x2f\x90\x24\x14\x41\x89\xdb\x98\x10\x6d\x91\xa4\x0a\x74\x88\x32\x95\xe1\xa8\x6d\xf3\xa1\xac\x2a\x76\xae\xe8\x9a\x07\x36\xce\xf7\x00\x40\xd7\xc8\xf3\x28\xc4\x5e\x46\x3b\x21\xef\xf0\x8d\xee\x10\xd2\x56\xe4\xb1\xc2\x3d\x9b\xc2\x96\xa6\x6e\x4e\x45\xdf\xeb\xda\x5f\xbd\x1f\x29\x95\xe5\xb2\xe3\xba\x28\x3b\xa8\x68\x47\x99\x12\xbb\xbd\xfa\x39\x1e\x4b\xf2\x38\x7e\xa1\x07\xb9\x94\x94\xa8\xe2\x65\x69\xa2\x97\x7d\xad\xd9\x54\x5c\x2c\xa7\x17\xe2\x0c\x0f\x5e\xaa\xd1\xda\x2b\x1b\xda\xb9\x9e\x2d\x14\x1d\xd4\x34\xe8\x1d\xdb\x65\x77\x9a\x8c\x0e\x8b\xde\x31\x7e\x08\x19\x7c\x11\xd2\xff\xf4\x71\x7e\xbd\xab\x9a\x96\xf1\x35\x4b\x93\xdb\xd9\xce\x63\xa9\x4f\xee\x7c\xc2\xcf\xad\xb6\xec\xfe\x31\x38\x61\x96\x7f\x35\x0f\x17\xe6\x27\x6c\x9b\x4a\x8a\x3e\x27\x63\x86\xfe\x99\xcd\x15\x24\x6d\x49\x52\x12\xd0\xf2\x11\x33\xe8\xfc\x01\x4d\x13\x84\x14\x93\x22\x04\x22\x0b\x44\x48\xd7\xe4\xfe\x8a\xe5\x8a\xe2\x1f\xfc\xff\x45\xe7\xe0\x2e\xd5\x06\xe0\x15\x19\x6f\xb5\xf1\x96\xa2\x45\x49\x48\x07\x9c\xb7\x6a\xc8\xdc\x0e\xa4\x2b\x7d\x5b\xae\x6d\x3c\xef\xbc\xf9\x61\xf3\x64\xde\xa0\xfb\xa1\x4c\xf7\x73\xf3\x2f\x6f\x6f\x7e\x07\x00\x00\xff\xff\xc2\x70\x6e\x26\x6b\x03\x00\x00")

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

	info := bindataFileInfo{name: "sql/0220_access_token.sql", size: 875, mode: os.FileMode(420), modTime: time.Unix(1608276459, 0)}
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

