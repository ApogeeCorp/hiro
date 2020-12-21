// Code generated by go-bindata.
// sources:
// ../../api/swagger/v1/hiro.swagger.yaml
// DO NOT EDIT!

package hiro

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

var _ApiSwaggerV1HiroSwaggerYaml = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\x94\x94\xcd\x72\xe3\x36\x0c\xc7\xef\x7a\x0a\x0c\x7d\x69\x67\x12\x39\xcd\x51\x37\xcf\x26\x6d\xd2\x99\xdd\x64\x92\x6c\x7b\x0d\x2d\x42\x16\x37\x14\xa1\x12\x54\x14\x77\xbb\xef\xde\x01\x24\x3b\xeb\xc6\x69\xa7\x17\x5b\x04\xc1\x1f\xf1\xf1\x07\x17\xb0\x82\xfb\xd1\x6e\x36\x98\xe0\xbc\x3c\x83\x1f\x6c\xf9\x54\xda\x12\x6e\x7a\x8c\xab\xdb\xeb\x1f\xc1\x61\xe3\xa3\xcf\x9e\x22\x50\x03\xb9\x45\x68\x7d\x22\x58\xdd\x5e\x97\xc5\xa2\x58\xc0\x43\xeb\x19\x3c\xc3\xc0\xe8\xa0\xa1\x04\x1b\x8c\x98\x6c\xf6\x71\x23\x4e\xe0\xa8\x1e\x3a\x8c\xd9\x2a\xc2\x46\xa7\x8c\xbc\xed\x71\x3e\xb3\xde\x8a\xa5\x58\x40\x1d\x3c\xc6\xbc\x64\x4c\xcf\x98\x4a\xb8\x47\x04\xdb\xfb\xe5\xdd\xe5\xea\xe2\xe3\x65\xd9\x4d\xf4\x8e\x12\x82\x8f\x0d\xa5\x4e\x89\x53\x10\xf7\xd4\x21\x70\xde\x06\x84\x48\x19\xb9\x2a\x16\x70\x3a\x85\xd6\xf8\x80\xfb\xf8\xd6\x5b\xb8\xc3\x0b\xaa\x4f\x60\x6c\x7d\xdd\x82\x0d\x81\x46\x86\x5f\x7c\xbe\x1a\xd6\xf0\x73\xb0\xcf\x94\xd0\xc1\x47\x9b\x9e\x1c\x8d\x11\x7c\x2c\x16\x00\xe0\x90\xeb\xe4\x7b\xb9\x8f\xcb\x19\x8d\x49\xb1\x91\xa0\xb3\x2f\xbe\x1b\x3a\x08\x3e\x22\x04\x8c\x9b\xdc\x9e\x68\xac\x68\x19\xa5\x68\xe8\xbc\x96\x43\x92\xef\x13\xe6\xbc\x05\xe7\x9b\x66\x46\x51\xaf\xe5\xa2\x78\xed\x18\xac\x66\xa7\x25\x9a\x52\x04\xf3\x89\x86\xf8\x1b\xa6\xb5\x39\x81\xd1\xe7\x16\x2c\xb0\x8f\x9b\x21\xd8\x04\x91\x86\x58\x16\x05\x4f\xfd\xab\xc0\x9c\x97\x67\xa6\xe0\xba\xc5\x4e\x6a\x00\x70\x0a\xa6\xcd\xb9\x37\xaf\x9f\x6c\x8a\x3e\x91\x1b\xea\xbd\x83\xed\xfb\xe0\x6b\x8d\x60\xf9\x85\x29\x9a\xb7\xe6\x97\x2e\x98\xa2\xa6\xc8\x43\xf7\xbf\x8e\x9d\x8e\xe3\x78\x2a\x79\x9c\x0e\x29\x60\xac\xc9\xa1\x33\x45\x21\xed\x13\x4a\xf6\x39\x60\x05\xe6\x6a\x16\x94\x20\x9e\x31\xb1\xa7\x58\x81\xf9\xa9\x3c\x93\x6c\x0e\xaa\x5f\xc1\x5f\x05\x00\x4c\x9d\x15\x75\xf5\x89\x9e\xbd\x43\xd6\x8a\x75\x98\x5b\x72\x3c\xe9\xc4\x46\xbb\x91\xa2\xab\x5a\x69\xfd\x05\xeb\xcc\xe5\x5e\xad\x91\x32\x58\xd1\x44\x12\x8d\x29\x53\xba\xc3\x2d\x0d\xc1\x01\xc5\xb0\x85\x35\xbe\x6a\x7a\x6d\xeb\x27\xa0\xa6\xf1\x35\x4e\x64\x14\x49\x97\x50\xe8\xc9\x05\xac\x86\xdc\x62\xcc\x73\xe2\x93\x55\xb3\x1a\x18\x19\x6e\x64\x5b\xa7\x4b\x58\xf6\xc0\x57\xaf\x15\x13\x25\xff\xe7\xac\xe8\x19\x7a\x99\x12\x25\x2e\xe6\x84\x51\xf3\x55\x1e\x67\x1b\x9d\x4d\x0e\xae\x1e\x1e\x6e\x65\x95\x07\x06\x29\x2e\x43\x26\xf0\xd1\x09\x1b\xb5\x24\x3c\xd4\x35\x32\x03\x25\x68\xac\x0f\x43\x42\xc5\xcd\x93\x2c\xc4\xda\x86\x50\x2a\x7f\x4d\x6e\xbb\xdb\x49\xc8\x3d\x45\x46\x18\x7d\x08\x52\x8a\x5f\xef\x6f\x3e\xbd\x2a\x53\xc6\xc6\xc7\x8d\xb2\x26\x9d\x56\xfa\xfd\xf8\xf8\xa8\xff\x5f\xf5\x17\xc0\x74\xc8\x6c\x37\x68\x2a\x30\x53\x0f\xb4\xf2\x0d\x0d\xd1\x99\x93\x9d\x93\xc3\x6c\x7d\x10\x1f\x6d\x88\x23\x9c\x1a\x84\x2f\x9e\xf3\xec\xf6\x6d\xcf\x2f\xb2\xdd\xcc\x22\x8c\xb6\xdb\xe9\xc7\xe8\xfe\x11\xa9\xcc\x8d\x90\x54\x6f\x76\x93\xc6\x32\x34\x58\x0f\xc9\xe7\xed\xc5\xfe\x7d\x53\xa8\xf6\x6a\x4a\x46\xde\x28\x89\x5b\xba\x73\x3e\xf1\x9b\x40\x63\x05\xc6\x6a\x51\x3f\x90\xc3\xc9\x7c\xd0\xbf\xcf\x29\x54\xf3\xac\x55\xcb\xa5\x6c\x95\xf3\x93\x16\xa8\xb6\x61\xa9\xbc\xe5\xee\xc8\x4c\xc8\xf4\x84\xff\x79\x52\x5e\x43\x75\x9c\xce\x70\x4d\xfd\x34\x8e\x53\x0c\xce\x63\xac\xb1\x4a\x68\x5d\x05\xe6\x0e\xad\xdb\x1b\xd9\xfc\xd3\x6b\x4c\x3e\x4b\x76\x1f\x12\x8a\x56\xf4\x65\x75\xbe\xd9\x1e\x39\xf2\x3a\xd1\x87\xec\x57\xfb\x51\xdf\xf7\x6f\x38\x72\x30\x51\x38\x8c\x5c\x95\x20\xd6\x43\x97\x77\xa1\x6f\xfd\xc5\xf2\x06\x79\xb8\xbb\xa3\xfd\x2e\xff\x3b\x58\x9e\x69\x6c\x8a\xc2\x1d\x8a\x63\xb5\xab\xde\x81\x3e\x54\xd7\xc2\x5d\x7d\x97\xfd\x71\x8f\xcf\x72\xeb\xf1\xad\x3b\xfc\x63\x40\xce\x0f\xd2\xdf\xf7\xf8\x2a\xbb\x7f\xf3\xb8\x47\xe6\xf7\x6e\x2f\x7a\x9b\x5b\x4d\x63\xb9\xef\x71\x05\x5f\xbf\xa9\xe1\xbb\x96\xec\x6c\x5a\x83\xdd\x22\x4d\xd1\xed\xd7\x2a\xc3\xfd\x8a\xa7\x6b\x75\xfd\x77\x00\x00\x00\xff\xff\xe1\x14\xb0\xcd\x51\x08\x00\x00")

func ApiSwaggerV1HiroSwaggerYamlBytes() ([]byte, error) {
	return bindataRead(
		_ApiSwaggerV1HiroSwaggerYaml,
		"../../api/swagger/v1/hiro.swagger.yaml",
	)
}

func ApiSwaggerV1HiroSwaggerYaml() (*asset, error) {
	bytes, err := ApiSwaggerV1HiroSwaggerYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "../../api/swagger/v1/hiro.swagger.yaml", size: 2129, mode: os.FileMode(420), modTime: time.Unix(1608454341, 0)}
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
	"../../api/swagger/v1/hiro.swagger.yaml": ApiSwaggerV1HiroSwaggerYaml,
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
	"..": &bintree{nil, map[string]*bintree{
		"..": &bintree{nil, map[string]*bintree{
			"api": &bintree{nil, map[string]*bintree{
				"swagger": &bintree{nil, map[string]*bintree{
					"v1": &bintree{nil, map[string]*bintree{
						"hiro.swagger.yaml": &bintree{ApiSwaggerV1HiroSwaggerYaml, map[string]*bintree{}},
					}},
				}},
			}},
		}},
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

