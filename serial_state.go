package peirates

type FullPeiratesState struct {
	ServiceAccounts      []ServiceAccount // All known service accounts
	ActiveServiceAccount int              // Index in ServiceAccounts of the current active service account
}
