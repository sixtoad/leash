package idmap

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
)

const Env = "LEASH_IDMAP_MOUNTS_B64"

type Spec struct {
	Target       string `json:"target"`
	HostUID      uint32 `json:"host_uid"`
	HostGID      uint32 `json:"host_gid"`
	ContainerUID uint32 `json:"container_uid"`
	ContainerGID uint32 `json:"container_gid"`
}

func Encode(specs []Spec) (string, error) {
	data, err := json.Marshal(specs)
	if err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(data), nil
}

func Decode(raw string) ([]Spec, error) {
	data, err := base64.RawStdEncoding.DecodeString(raw)
	if err != nil {
		return nil, err
	}
	var specs []Spec
	if err := json.Unmarshal(data, &specs); err != nil {
		return nil, err
	}
	if len(specs) == 0 {
		return nil, errors.New("idmap mount payload is empty")
	}
	return specs, nil
}

// HoldUserNamespace is the private child mode used while the parent opens the
// newly-created user namespace. The mount itself retains the namespace after
// this process exits.
func HoldUserNamespace() { _, _ = io.Copy(io.Discard, os.Stdin) }
