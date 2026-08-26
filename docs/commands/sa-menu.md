# Service account menu

## Menu entry

- Number: `1`
- Canonical command: `sa-menu`
- Aliases: `service-account-menu`, `sa`, `service-account`
- Maturity: Stable; all seven submenu actions have live Kind coverage.

## Purpose

Manage the Kubernetes service-account tokens held in the current Peirates process. The submenu can list, select, add, export, import, decode, or display tokens.

## Prerequisites and authorization

The menu itself operates on Peirates' in-memory token collection and does not call the Kubernetes API. Tokens may already have been loaded from the current pod or discovered on an accessible node filesystem; they may also be entered or imported by the user.

Treat every token as a credential. Only use this command on systems and clusters you are authorized to assess.

## Usage

At the main interactive prompt, enter:

```text
1
```

or `sa-menu` (or one of its aliases). Then choose one submenu action:

```text
1 / list / listsa          list stored accounts
2 / switch / switchsa      select the active account
3 / add        enter a token and name
4 / export / exportsa      print the collection as JSON
5 / import / importsa      read a JSON collection from stdin
6 / decode     decode an entered or stored JWT
7 / display    print a stored token
```

Module mode is supported, but the submenu still reads its selection and any additional values from stdin:

```sh
peirates -m sa-menu
```

Direct main-menu commands such as `list-sa`, `switch-sa`, and `decode-jwt` are related commands, not aliases for `sa-menu`.

## What it does

Peirates keeps service accounts in memory with a name, token, discovery time, and discovery method. Selecting an account installs its token in the active Kubernetes connection and clears any active client-certificate authentication. Adding appends an account and then asks whether to switch to it; importing appends every decoded record. Neither path performs duplicate detection. Export emits the collection as JSON; decode displays decoded JWT header and payload text plus the still-encoded signature; display emits the raw token.

The submenu handles one action and then returns to the main menu (or exits when invoked with `-m`).

## Expected output

List and switch show indexed account names, marking the active account with `>`. Switch also prints the selected name **and full token**. Export prints JSON containing the full tokens. Decode prints JWT header, payload, and signature. Display prints the selected full token.

## Side effects and cleanup

Adding and importing retain credentials in process memory. Switching changes the active Kubernetes authentication context for the remainder of the process and clears certificate fields. Export, switch, and display can place raw credentials in terminal output, scrollback, logs, or a configured Peirates output file.

No cluster object is changed. Exit Peirates to discard the in-memory collection. Remove or securely handle any captured output containing credentials.

## Failure modes

- Empty, malformed, or out-of-range submenu/index selections return without making the requested selection. An invalid answer to the post-add switch prompt does not undo the account that was already appended.
- Adding requires a non-empty token; the name falls back to `Unnamed` if reading it fails.
- Import requires JSON compatible with Peirates' service-account structure, but it does not validate credentials or reject duplicate names.
- Other discovery paths use `AddNewServiceAccount`, which rejects duplicate trimmed names, but the submenu's add and import actions bypass that helper.
- Decode requires a three-part JWT with base64url-decodable header and payload. Invalid structure or base64 causes a process panic; a decoded non-JSON payload is displayed as `Error pretty printing JSON`.
- The submenu uses multiple stdin readers; scripted input may need to be paced, as demonstrated by the live test.

## Implementation and tests

- [Submenu implementation](../../internal/app/menu_serviceaccounts.go)
- [Service-account storage and context switching](../../internal/app/service_account_utils.go)
- [Registry and aliases](../../internal/app/module_registry.go), [dispatch aliases](../../internal/app/dispatch.go)
- [Unit tests](../../internal/app/service_account_utils_test.go), [module tests](../../internal/app/module_commands_test.go)
- [Kind integration test](../../test/service-account-kind-integration.sh)
