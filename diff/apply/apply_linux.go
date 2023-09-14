/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package apply

import (
	"context"
	"fmt"
	"io"
	"strings"
	"archive/tar"
    "path/filepath"
	"os"
	"sync"


	"github.com/containerd/containerd/archive"
	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/mount"
	"github.com/containerd/containerd/pkg/userns"
)

//Add Untar
var bufPool = &sync.Pool{
    New: func() interface{} {
        buffer := make([]byte, 32*1024)
        return &buffer
    },
}

func Untar(dst string, r io.Reader) error {

    tr := tar.NewReader(r)

    for {
        header, err := tr.Next()

        switch {

        // if no more files are found return
        case err == io.EOF:
            return nil

        // return any other error
        case err != nil:
            return err

        // if the header is nil, just skip it (not sure how this happens)
        case header == nil:
            continue
        }

        // the target location where the dir/file should be created
        target := filepath.Join(dst, header.Name)

        // the following switch could also be done using fi.Mode(), not sure if there
        // a benefit of using one vs. the other.
        // fi := header.FileInfo()

        // check the file type
        switch header.Typeflag {

        // if its a dir and it doesn't exist create it
        case tar.TypeDir:
            if _, err := os.Stat(target); err != nil {
                if err := os.MkdirAll(target, 0755); err != nil {
                    return err
                }
            }

        // if it's a file create it
        case tar.TypeReg:
            f, err := os.OpenFile(target, os.O_CREATE|os.O_RDWR, os.FileMode(header.Mode))
            if err != nil {
                return err
            }

            // copy over contents
            //if _, err := io.Copy(f, tr); err != nil {
            //    return err
            //}
            buf := bufPool.Get().(*[]byte)
            defer bufPool.Put(buf)
            //buf := make([]byte, 32*1024)
            for {
                nr, err := r.Read(*buf)
                if err == io.EOF {
                  break
                }
                if nr > 0 {
                    //_, _= f.Write(buf[:nr])
                    _, _= f.Write((*buf)[0:nr])

                }
            }
            // manually close here after each file operation; defering would cause each file close
            // to wait until all operations have completed.
            f.Close()
        }
    }
}

//End Untar

func apply(ctx context.Context, mounts []mount.Mount, r io.Reader) error {
    fmt.Println("I got into apply under apply_linux.go")
	switch {
	case len(mounts) == 1 && mounts[0].Type == "overlay":
		// OverlayConvertWhiteout (mknod c 0 0) doesn't work in userns.
		// https://github.com/containerd/containerd/issues/3762
		if userns.RunningInUserNS() {
			break
		}
		path, parents, err := getOverlayPath(mounts[0].Options)
		if err != nil {
			if errdefs.IsInvalidArgument(err) {
				break
			}
			return err
		}
		opts := []archive.ApplyOpt{
			archive.WithConvertWhiteout(archive.OverlayConvertWhiteout),
		}
		if len(parents) > 0 {
			opts = append(opts, archive.WithParents(parents))
		}
		//fmt.Println("ARCHIVE OPTS PATH: ", path)
		
		//var wg sync.WaitGroup
		//wg.Add(1)
		//go func() {
			Untar(path, r)
			//wg.Done()
		//}()
		//_ , err = archive.Apply(ctx, path, r, opts...)

		
		return nil
	case len(mounts) == 1 && mounts[0].Type == "aufs":
		path, parents, err := getAufsPath(mounts[0].Options)
		if err != nil {
			if errdefs.IsInvalidArgument(err) {
				break
			}
			return err
		}
		opts := []archive.ApplyOpt{
			archive.WithConvertWhiteout(archive.AufsConvertWhiteout),
		}
		if len(parents) > 0 {
			opts = append(opts, archive.WithParents(parents))
		}
		_, err = archive.Apply(ctx, path, r, opts...)
		return err
	}
	return mount.WithTempMount(ctx, mounts, func(root string) error {
		_, err := archive.Apply(ctx, root, r)
		return err
	})
}

func getOverlayPath(options []string) (upper string, lower []string, err error) {
	const upperdirPrefix = "upperdir="
	const lowerdirPrefix = "lowerdir="

	for _, o := range options {
		if strings.HasPrefix(o, upperdirPrefix) {
			upper = strings.TrimPrefix(o, upperdirPrefix)
		} else if strings.HasPrefix(o, lowerdirPrefix) {
			lower = strings.Split(strings.TrimPrefix(o, lowerdirPrefix), ":")
		}
	}
	if upper == "" {
		return "", nil, fmt.Errorf("upperdir not found: %w", errdefs.ErrInvalidArgument)
	}

	return
}

// getAufsPath handles options as given by the containerd aufs package only,
// formatted as "br:<upper>=rw[:<lower>=ro+wh]*"
func getAufsPath(options []string) (upper string, lower []string, err error) {
	const (
		sep      = ":"
		brPrefix = "br:"
		rwSuffix = "=rw"
		roSuffix = "=ro+wh"
	)
	for _, o := range options {
		if strings.HasPrefix(o, brPrefix) {
			o = strings.TrimPrefix(o, brPrefix)
		} else {
			continue
		}

		for _, b := range strings.Split(o, sep) {
			if strings.HasSuffix(b, rwSuffix) {
				if upper != "" {
					return "", nil, fmt.Errorf("multiple rw branch found: %w", errdefs.ErrInvalidArgument)
				}
				upper = strings.TrimSuffix(b, rwSuffix)
			} else if strings.HasSuffix(b, roSuffix) {
				if upper == "" {
					return "", nil, fmt.Errorf("rw branch be first: %w", errdefs.ErrInvalidArgument)
				}
				lower = append(lower, strings.TrimSuffix(b, roSuffix))
			} else {
				return "", nil, fmt.Errorf("unhandled aufs suffix: %w", errdefs.ErrInvalidArgument)
			}

		}
	}
	if upper == "" {
		return "", nil, fmt.Errorf("rw branch not found: %w", errdefs.ErrInvalidArgument)
	}
	return
}
