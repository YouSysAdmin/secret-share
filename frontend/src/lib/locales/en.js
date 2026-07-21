// English - the reference dictionary.
// Every key used anywhere in the UI must exist here (other locales fall back to these strings).
export default {
  // shared
  "common.copy": "Copy",
  "common.copied": "Copied.",
  "common.copyFailed": "Copy failed - select and copy manually.",
  "common.loading": "Loading…",
  "common.shareYourOwn": "Share your own",
  "common.shareASecret": "Share a secret",
  "common.passphrase": "Passphrase",
  "common.decrypt": "Decrypt",
  "common.decrypting": "Decrypting…",
  "common.enterPassphrase": "Enter the passphrase.",

  // nav / chrome
  "nav.signin": "Sign in",
  "nav.users": "Users",
  "nav.account": "Account",
  "nav.signout": "Sign out",
  "theme.system": "System",
  "theme.light": "Light",
  "theme.dark": "Dark",
  "theme.title": "Theme: {name} — click to change",
  "lang.label": "Language",

  // TTL presets
  "ttl.5m": "5 minutes",
  "ttl.1h": "1 hour",
  "ttl.24h": "1 day",
  "ttl.168h": "7 days",

  // create form
  "create.title": "Share a secret",
  "create.intro1": "End-to-end encrypted in your browser - we can't read it.",
  "create.intro2": "Anyone with the link can view it once, then it's deleted.",
  "create.tabText": "Text",
  "create.tabFile": "File",
  "create.secretLabel": "Secret",
  "create.secretPlaceholder": "Paste a password, token, or any text…",
  "create.fileLabel": "File",
  "create.chooseFile": "Choose a file…",
  "create.changeFile": "Choose another file…",
  "create.fileHint":
    "Encrypted in your browser - name and content included. Up to {max}.",
  "create.lifetime": "Lifetime",
  "create.customOption": "Custom…",
  "create.customLifetime": "Custom lifetime",
  "create.minutes": "minutes",
  "create.hours": "hours",
  "create.days": "days",
  "create.views": "Views",
  "create.viewsHintMulti":
    "The link can be opened {n} times before the secret is deleted.",
  "create.viewsHintOne": "One-time: the secret is deleted on the first view.",
  "create.passphraseToggle": "Protect with a passphrase",
  "create.passphraseHintOn":
    "The key is derived from your passphrase instead of being part of the link. Share the passphrase over a different channel.",
  "create.passphraseHintOff":
    "By default the decryption key is embedded in the link itself.",
  "create.passphrasePlaceholder": "At least 6 characters",
  "create.access": "Access",
  "create.private": "Private",
  "create.public": "Public",
  "create.accessHintPrivate": "Only signed-in users can open this link.",
  "create.accessHintPublic":
    "Anyone with the link can open it once, no account needed.",
  "create.submit": "Create link",
  "create.submitBusy": "Encrypting…",
  "create.errNoSecret": "Enter a secret first.",
  "create.errNoFile": "Choose a file first.",
  "create.errBadTTL": "Enter a valid custom lifetime.",
  "create.errShortPassphrase": "Use a passphrase of at least 6 characters.",
  "create.errFileTooLarge": "File is too large - the limit is {max}.",

  // result card
  "result.title": "Your link is ready",
  "result.introFile":
    "This link downloads the file once, then it's gone. It also expires automatically.",
  "result.introOne":
    "This link reveals the secret once, then it's gone. It also expires automatically.",
  "result.introMulti_one":
    "This link reveals the secret up to {n} time, then it's gone. It also expires automatically.",
  "result.introMulti_other":
    "This link reveals the secret up to {n} times, then it's gone. It also expires automatically.",
  "result.passNote":
    "The recipient will need the passphrase to decrypt it - share the passphrase over a different channel (not alongside the link).",
  "result.keyNote":
    "The decryption key is in the link after the # and never reached our server.",
  "result.linkCopied": "Link copied.",
  "result.showQR": "Show QR code",
  "result.hideQR": "Hide QR code",
  "result.shareAnother": "Share another",

  // secret reveal page
  "reveal.title": "Secret",
  "reveal.deleted": "This secret has now been deleted and can't be viewed again.",
  "reveal.viewsLeft_one":
    "This secret can be viewed {n} more time before it is deleted.",
  "reveal.viewsLeft_other":
    "This secret can be viewed {n} more times before it is deleted.",
  "reveal.unavailableTitle": "Secret unavailable",
  "reveal.unavailableBody":
    "This secret has already been viewed, has expired, or never existed. Secrets are one-time and disappear after the first view.",
  "reveal.incompleteTitle": "Incomplete link",
  "reveal.incompleteBody":
    "This link is missing its decryption key (the part after the #). Ask the sender for the complete link.",
  "reveal.receivedTitle": "You've received a secret",
  "reveal.receivedBody":
    "Viewing it will permanently delete it - you can only see it once. Make sure you're ready.",
  "reveal.receivedBodyMulti_one":
    "This secret can be viewed {n} more time in total - opening it now uses one of them.",
  "reveal.receivedBodyMulti_other":
    "This secret can be viewed {n} more times in total - opening it now uses one of them.",
  "reveal.button": "Reveal secret",
  "reveal.buttonBusy": "Revealing…",
  "reveal.passTitle": "You've received a passphrase-protected secret",
  "reveal.passBody":
    "Viewing it will permanently delete it from the server - you can only retrieve it once. You'll need the passphrase the sender shared with you to decrypt it.",
  "reveal.passEnterTitle": "Enter the passphrase",
  "reveal.passRetrievedGone":
    "The secret has been retrieved and deleted from the server - it now exists only on this page.",
  "reveal.passRetrievedLeft_one":
    "The secret has been retrieved (it can be viewed {n} more time).",
  "reveal.passRetrievedLeft_other":
    "The secret has been retrieved (it can be viewed {n} more times).",
  "reveal.passEnterTail":
    "Enter the passphrase the sender gave you. Don't close this page until you've decrypted it.",
  "reveal.wrongPassphrase":
    "Wrong passphrase - try again. The secret stays on this page until you close it.",
  "reveal.missingKey": "This link is missing its decryption key.",

  // file page
  "file.readyTitle": "File ready",
  "file.readyBody":
    "The file has been deleted from the server - save it now, it only exists on this page.",
  "file.download": "Download",
  "file.unavailableTitle": "File unavailable",
  "file.unavailableBody":
    "This file has already been downloaded, has expired, or never existed. Shared files are one-time and disappear after the first download.",
  "file.receivedTitle": "You've received a file",
  "file.receivedBody":
    "Downloading it will permanently delete it from the server - you can only retrieve it once ({size} encrypted). Make sure you're ready.",
  "file.passTitle": "You've received a passphrase-protected file",
  "file.passBody":
    "Retrieving it will permanently delete it from the server - you can only download it once ({size} encrypted). You'll need the passphrase the sender shared with you.",
  "file.passRetrieved":
    "The file has been retrieved and deleted from the server - it now exists only on this page. Enter the passphrase the sender gave you. Don't close this page until you've decrypted it.",
  "file.retrieve": "Retrieve file",
  "file.retrieving": "Retrieving…",
  "file.wrongPassphrase":
    "Wrong passphrase - try again. The file stays on this page until you close it.",

  // sign-in
  "signin.title": "Sign in",
  "signin.ssoWith": "Sign in with {label}",
  "signin.or": "or",
  "signin.passkey": "Sign in with a passkey",
  "signin.passkeyBusy": "Waiting for passkey…",
  "signin.email": "Email",
  "signin.password": "Password",
  "signin.submit": "Sign in",
  "signin.submitBusy": "Signing in…",
  "signin.mfaHint":
    "Enter the 6-digit code from your authenticator app, or a recovery code.",
  "signin.codeLabel": "Authentication code",
  "signin.verify": "Verify",
  "signin.verifying": "Verifying…",
  "signin.noMethods": "No sign-in methods are configured.",
  "signin.failed": "Sign-in failed.",
  "signin.invalidCreds": "Invalid email or password.",
  "signin.ssoIdpError": "The identity provider reported an error.",
  "signin.ssoBadCallback": "The sign-in response was incomplete. Try again.",
  "signin.ssoStateMissing": "Your sign-in attempt expired. Try again.",
  "signin.ssoTokenInvalid": "Could not verify the sign-in. Try again.",
  "signin.ssoAccessDenied": "Your account isn't allowed to sign in here.",
  "signin.ssoInternal": "Something went wrong completing sign-in.",

  // account
  "account.title": "Account",
  "account.signedInAs": "Signed in as",
  "account.changePassword": "Change password",
  "account.currentPassword": "Current password",
  "account.newPassword": "New password",
  "account.updatePassword": "Update password",
  "account.pwChanged": "Password changed.",
  "account.changeEmail": "Change email",
  "account.newEmail": "New email",
  "account.updateEmail": "Update email",
  "account.emailChanged": "Email changed to {email}.",
  "account.twofa": "Two-factor authentication",
  "account.recoverySave":
    "Save these one-time recovery codes somewhere safe - each works once if you lose your authenticator.",
  "account.copyCodes": "Copy codes",
  "account.codesCopied": "Recovery codes copied.",
  "account.scanQR":
    "Scan this QR code with your authenticator app (or enter the secret manually), then enter the 6-digit code to confirm.",
  "account.totpQRAlt": "TOTP QR code",
  "account.secretManual": "Secret (manual entry)",
  "account.code": "Code",
  "account.enable2fa": "Enable 2FA",
  "account.twofaEnabled": "Two-factor authentication enabled.",
  "account.protected": "Your account is protected by an authenticator app.",
  "account.confirmPassword": "Confirm password",
  "account.regenCodes": "Regenerate recovery codes",
  "account.newCodes": "New recovery codes generated.",
  "account.disable2fa": "Disable 2FA",
  "account.twofaDisabled": "Two-factor authentication disabled.",
  "account.addFactor":
    "Add a second factor with an authenticator app (local password accounts only).",
  "account.setup2fa": "Set up 2FA",
  "account.passkeys": "Passkeys",
  "account.noPasskeys": "No passkeys yet.",
  "account.colName": "Name",
  "account.colAdded": "Added",
  "account.remove": "Remove",
  "account.pkRemovePrompt": "Confirm your password to remove this passkey:",
  "account.pkRemoved": "Passkey removed.",
  "account.pkNameLabel": "Name (to recognize this device)",
  "account.pkNamePlaceholder": "e.g. MacBook Touch ID",
  "account.addPasskey": "Add passkey",
  "account.pkBusy": "Waiting for authenticator…",
  "account.pkAdded": "Passkey added.",

  // users (admin)
  "users.title": "Users",
  "users.intro":
    "Manage who can sign in. A password makes a local account, leave it blank for an SSO account provisioned by email.",
  "users.phEmail": "email",
  "users.phName": "name (optional)",
  "users.phPassword": "password (optional)",
  "users.add": "Add",
  "users.localCreated": "Local user created.",
  "users.oidcCreated": "OIDC user created.",
  "users.colEmail": "Email",
  "users.colRole": "Role",
  "users.colSource": "Source",
  "users.col2fa": "2FA",
  "users.colPasskeys": "Passkeys",
  "users.colEnabled": "Enabled",
  "users.colActions": "Actions",
  "users.roleUser": "user",
  "users.roleAdmin": "admin",
  "users.pinned": "pinned",
  "users.on": "on",
  "users.roleSet": "{email} is now {role}.",
  "users.disable": "disable",
  "users.enable": "enable",
  "users.disabled": "User disabled.",
  "users.enabled": "User enabled.",
  "users.resetPw": "reset pw",
  "users.pwPrompt": "New password for {email} (8-72 chars):",
  "users.pwReset": "Password reset.",
  "users.revoke2fa": "revoke 2FA",
  "users.confirm2fa": "Revoke 2FA for {email}?",
  "users.twofaRevoked": "2FA revoked.",
  "users.revokeKeys": "revoke keys",
  "users.confirmKeys": "Remove all passkeys for {email}?",
  "users.keysRemoved": "Passkeys removed.",
  "users.delete": "delete",
  "users.confirmDelete": "Delete {email}? This cannot be undone.",
  "users.deleted": "User deleted.",
};
