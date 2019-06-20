package peirates

type FullPeiratesState struct {
	ServiceAccounts      []ServiceAccount // All known service accounts
	ActiveServiceAccount int              // Index in ServiceAccounts of the current active service account
}

func ExportFullPeiratesState(serviceAccounts []ServiceAccount, serverInfo ServerInfo) FullPeiratesState {
	activeAccount := 0
	for i, account := range serviceAccounts {
		if account.Name == serverInfo.TokenName {
			activeAccount = i
			break
		}
	}
	fullState := FullPeiratesState{
		ServiceAccounts:      serviceAccounts,
		ActiveServiceAccount: activeAccount,
	}
	return fullState
}
