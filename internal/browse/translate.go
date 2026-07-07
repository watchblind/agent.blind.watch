package browse

import (
	"sort"

	"github.com/watchblind/agent/internal/pathbrowser"
)

// TranslateListing converts a pathbrowser.Listing (legacy paths_preview
// shape: name/is_dir/size/mtime/readable) into the spec browse_response
// shape (name/type/size/modified). Broken symlinks are omitted, size and
// modified are null for directories (and symlinks resolving to directories),
// and entries are re-sorted directories first, then alphabetical.
func TranslateListing(l pathbrowser.Listing) DirectoryPayload {
	out := DirectoryPayload{Path: l.Path, Entries: []DirEntry{}, Truncated: l.Truncated}
	if l.Error != "" {
		msg := l.Error
		out.Error = &msg
		return out
	}

	type row struct {
		entry   DirEntry
		dirLike bool
	}
	rows := make([]row, 0, len(l.Entries))
	for _, e := range l.Entries {
		if e.Symlink && !e.Readable {
			continue // broken symlink — target does not resolve
		}
		typ := "file"
		dirLike := e.IsDir
		switch {
		case e.Symlink:
			typ = "symlink"
			dirLike = e.TargetDir // symlink sorts/nulls by what it points at
		case e.IsDir:
			typ = "dir"
		}
		de := DirEntry{Name: e.Name, Type: typ}
		if !dirLike && e.Readable {
			size, modified := e.Size, e.Mtime
			de.Size = &size
			de.Modified = &modified
		}
		rows = append(rows, row{entry: de, dirLike: dirLike})
	}

	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].dirLike != rows[j].dirLike {
			return rows[i].dirLike
		}
		return rows[i].entry.Name < rows[j].entry.Name
	})
	for _, r := range rows {
		out.Entries = append(out.Entries, r.entry)
	}
	return out
}
