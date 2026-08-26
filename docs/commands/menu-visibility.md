# Change menu visibility

## Menu entry

- **Menu items and canonical commands:** `short`, `full`
- **Aliases:** `minimal` selects `short`; `help` selects `full`
- **Maturity:** Supported presentation setting

## Purpose

Switch between the full classic menu and the smaller menu that emphasizes common context and utility commands.

## Prerequisites and authorization

None. Menu visibility does not change cluster access or enable and disable commands.

## Usage

Enter `short` from the full menu or `full` from the minimal menu. The aliases `minimal` and `help` are also accepted.

Although `peirates -m short` and `peirates -m full` are accepted, one-shot mode exits immediately, so changing visibility there has no practical effect.

## What it does

The command changes the in-memory `FullMenu` flag and immediately redraws the menu during an interactive session. Commands omitted from the minimal display remain callable by name.

## Expected output

Peirates redraws either the compact or classic main menu.

## Side effects and cleanup

The change lasts only for the current process and has no cluster, cloud, or filesystem effect.

## Failure modes

There are no expected runtime failures. The setting is not persisted between Peirates runs.

## Implementation and tests

See [`menu.go`](../../internal/app/menu.go), [`module_registry.go`](../../internal/app/module_registry.go), and aliases in [`dispatch.go`](../../internal/app/dispatch.go). One-shot and completion behavior is covered by [`module_commands_test.go`](../../internal/app/module_commands_test.go).
