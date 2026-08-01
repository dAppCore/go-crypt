// SPDX-Licence-Identifier: EUPL-1.2

package keys

import core "dappco.re/go"

// defaultKeysDir returns $HOME/Lethean/data/keys/, creating the tree if
// missing, and reports it in Result.Value (string).
//
// WHY this location rather than ~/.config or ~/Library: the Lethean
// estate keeps a user's data where the user can see it — sealed blobs
// included. A credential store hidden in a platform cache directory is
// one the owner cannot audit, back up, or delete without tooling.
// The directory itself is 0700; the parents are 0755 because they are
// the ordinary visible tree, not the secret.
//
// WHY it is only a default: where an application keeps its files is the
// application's business, not this package's. A host with its own path
// policy injects a resolver instead of inheriting this one.
func defaultKeysDir() core.Result {
	homeR := core.UserHomeDir()
	if !homeR.OK {
		return homeR
	}
	root := core.PathJoin(homeR.Value.(string), "Lethean")
	if r := core.MkdirAll(root, 0o755); !r.OK {
		return r
	}
	data := core.PathJoin(root, "data")
	if r := core.MkdirAll(data, 0o755); !r.OK {
		return r
	}
	dir := core.PathJoin(data, "keys")
	if r := core.MkdirAll(dir, dirMode); !r.OK {
		return r
	}
	return core.Ok(dir)
}
