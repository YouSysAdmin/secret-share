// Українська. Ключі, яких тут немає, показуються англійською (fallback на en).
export default {
  // shared
  "common.copy": "Копіювати",
  "common.copied": "Скопійовано.",
  "common.copyFailed": "Не вдалося скопіювати - виділіть і скопіюйте вручну.",
  "common.loading": "Завантаження…",
  "common.shareYourOwn": "Поділитися своїм",
  "common.shareASecret": "Поділитися секретом",
  "common.passphrase": "Парольна фраза",
  "common.decrypt": "Розшифрувати",
  "common.decrypting": "Розшифрування…",
  "common.enterPassphrase": "Введіть парольну фразу.",

  // nav / chrome
  "nav.signin": "Увійти",
  "nav.users": "Користувачі",
  "nav.account": "Обліковий запис",
  "nav.signout": "Вийти",
  "theme.system": "Системна",
  "theme.light": "Світла",
  "theme.dark": "Темна",
  "theme.title": "Тема: {name} — натисніть, щоб змінити",
  "lang.label": "Мова",

  // TTL presets
  "ttl.5m": "5 хвилин",
  "ttl.1h": "1 година",
  "ttl.24h": "1 день",
  "ttl.168h": "7 днів",

  // create form
  "create.title": "Поділитися секретом",
  "create.intro1":
    "Наскрізне шифрування у вашому браузері - ми не можемо його прочитати.",
  "create.intro2":
    "Будь-хто з посиланням може переглянути його один раз, після чого воно видаляється.",
  "create.tabText": "Текст",
  "create.tabFile": "Файл",
  "create.secretLabel": "Секрет",
  "create.secretPlaceholder": "Вставте пароль, токен або будь-який текст…",
  "create.fileLabel": "Файл",
  "create.fileHint":
    "Шифрується у вашому браузері - разом з назвою та вмістом. До {max}.",
  "create.lifetime": "Термін дії",
  "create.customOption": "Інший…",
  "create.customLifetime": "Власний термін дії",
  "create.minutes": "хвилин",
  "create.hours": "годин",
  "create.days": "днів",
  "create.views": "Перегляди",
  "create.viewsHintMulti":
    "Посилання можна відкрити {n} разів, перш ніж секрет буде видалено.",
  "create.viewsHintOne":
    "Одноразово: секрет видаляється після першого перегляду.",
  "create.passphraseToggle": "Захистити парольною фразою",
  "create.passphraseHintOn":
    "Ключ виводиться з парольної фрази і не є частиною посилання. Передайте фразу іншим каналом.",
  "create.passphraseHintOff":
    "Типово ключ розшифрування вбудований у саме посилання.",
  "create.passphrasePlaceholder": "Щонайменше 6 символів",
  "create.access": "Доступ",
  "create.private": "Приватний",
  "create.public": "Публічний",
  "create.accessHintPrivate":
    "Відкрити це посилання можуть лише користувачі, що увійшли.",
  "create.accessHintPublic":
    "Будь-хто з посиланням може відкрити його один раз, без облікового запису.",
  "create.submit": "Створити посилання",
  "create.submitBusy": "Шифрування…",
  "create.errNoSecret": "Спершу введіть секрет.",
  "create.errNoFile": "Спершу виберіть файл.",
  "create.errBadTTL": "Введіть коректний власний термін дії.",
  "create.errShortPassphrase":
    "Парольна фраза має містити щонайменше 6 символів.",
  "create.errFileTooLarge": "Файл завеликий - обмеження {max}.",

  // result card
  "result.title": "Ваше посилання готове",
  "result.introFile":
    "Це посилання дозволяє завантажити файл один раз, після чого він зникає. Також воно спливає автоматично.",
  "result.introOne":
    "Це посилання показує секрет один раз, після чого він зникає. Також воно спливає автоматично.",
  "result.introMulti_one":
    "Це посилання показує секрет до {n} разу, після чого він зникає. Також воно спливає автоматично.",
  "result.introMulti_few":
    "Це посилання показує секрет до {n} разів, після чого він зникає. Також воно спливає автоматично.",
  "result.introMulti_many":
    "Це посилання показує секрет до {n} разів, після чого він зникає. Також воно спливає автоматично.",
  "result.introMulti_other":
    "Це посилання показує секрет до {n} разів, після чого він зникає. Також воно спливає автоматично.",
  "result.passNote":
    "Отримувачу знадобиться парольна фраза для розшифрування - передайте її іншим каналом (не разом із посиланням).",
  "result.keyNote":
    "Ключ розшифрування міститься в посиланні після # і ніколи не потрапляв на наш сервер.",
  "result.linkCopied": "Посилання скопійовано.",
  "result.showQR": "Показати QR-код",
  "result.hideQR": "Сховати QR-код",
  "result.shareAnother": "Поділитися ще",

  // secret reveal page
  "reveal.title": "Секрет",
  "reveal.deleted": "Цей секрет видалено, переглянути його ще раз неможливо.",
  "reveal.viewsLeft_one":
    "Цей секрет можна переглянути ще {n} раз, перш ніж його буде видалено.",
  "reveal.viewsLeft_few":
    "Цей секрет можна переглянути ще {n} рази, перш ніж його буде видалено.",
  "reveal.viewsLeft_many":
    "Цей секрет можна переглянути ще {n} разів, перш ніж його буде видалено.",
  "reveal.viewsLeft_other":
    "Цей секрет можна переглянути ще {n} разів, перш ніж його буде видалено.",
  "reveal.unavailableTitle": "Секрет недоступний",
  "reveal.unavailableBody":
    "Цей секрет уже переглянули, він сплив або ніколи не існував. Секрети одноразові та зникають після першого перегляду.",
  "reveal.incompleteTitle": "Неповне посилання",
  "reveal.incompleteBody":
    "У цьому посиланні відсутній ключ розшифрування (частина після #). Попросіть відправника надіслати повне посилання.",
  "reveal.receivedTitle": "Ви отримали секрет",
  "reveal.receivedBody":
    "Перегляд остаточно видалить його - побачити його можна лише один раз. Переконайтеся, що ви готові.",
  "reveal.receivedBodyMulti_one":
    "Цей секрет можна переглянути ще {n} раз загалом - відкриття зараз використає один із переглядів.",
  "reveal.receivedBodyMulti_few":
    "Цей секрет можна переглянути ще {n} рази загалом - відкриття зараз використає один із переглядів.",
  "reveal.receivedBodyMulti_many":
    "Цей секрет можна переглянути ще {n} разів загалом - відкриття зараз використає один із переглядів.",
  "reveal.receivedBodyMulti_other":
    "Цей секрет можна переглянути ще {n} разів загалом - відкриття зараз використає один із переглядів.",
  "reveal.button": "Показати секрет",
  "reveal.buttonBusy": "Відкриття…",
  "reveal.passTitle": "Ви отримали секрет, захищений парольною фразою",
  "reveal.passBody":
    "Перегляд остаточно видалить його з сервера - отримати його можна лише один раз. Для розшифрування знадобиться парольна фраза від відправника.",
  "reveal.passEnterTitle": "Введіть парольну фразу",
  "reveal.passRetrievedGone":
    "Секрет отримано й видалено з сервера - тепер він існує лише на цій сторінці.",
  "reveal.passRetrievedLeft_one":
    "Секрет отримано (його можна переглянути ще {n} раз).",
  "reveal.passRetrievedLeft_few":
    "Секрет отримано (його можна переглянути ще {n} рази).",
  "reveal.passRetrievedLeft_many":
    "Секрет отримано (його можна переглянути ще {n} разів).",
  "reveal.passRetrievedLeft_other":
    "Секрет отримано (його можна переглянути ще {n} разів).",
  "reveal.passEnterTail":
    "Введіть парольну фразу від відправника. Не закривайте цю сторінку, доки не розшифруєте.",
  "reveal.wrongPassphrase":
    "Неправильна парольна фраза - спробуйте ще. Секрет залишається на цій сторінці, доки ви її не закриєте.",
  "reveal.missingKey": "У цьому посиланні відсутній ключ розшифрування.",

  // file page
  "file.readyTitle": "Файл готовий",
  "file.readyBody":
    "Файл видалено з сервера - збережіть його зараз, він існує лише на цій сторінці.",
  "file.download": "Завантажити",
  "file.unavailableTitle": "Файл недоступний",
  "file.unavailableBody":
    "Цей файл уже завантажили, він сплив або ніколи не існував. Спільні файли одноразові та зникають після першого завантаження.",
  "file.receivedTitle": "Ви отримали файл",
  "file.receivedBody":
    "Завантаження остаточно видалить його з сервера - отримати його можна лише один раз ({size} у зашифрованому вигляді). Переконайтеся, що ви готові.",
  "file.passTitle": "Ви отримали файл, захищений парольною фразою",
  "file.passBody":
    "Отримання остаточно видалить його з сервера - завантажити його можна лише один раз ({size} у зашифрованому вигляді). Знадобиться парольна фраза від відправника.",
  "file.passRetrieved":
    "Файл отримано й видалено з сервера - тепер він існує лише на цій сторінці. Введіть парольну фразу від відправника. Не закривайте цю сторінку, доки не розшифруєте.",
  "file.retrieve": "Отримати файл",
  "file.retrieving": "Отримання…",
  "file.wrongPassphrase":
    "Неправильна парольна фраза - спробуйте ще. Файл залишається на цій сторінці, доки ви її не закриєте.",

  // sign-in
  "signin.title": "Вхід",
  "signin.ssoWith": "Увійти через {label}",
  "signin.or": "або",
  "signin.passkey": "Увійти з ключем доступу",
  "signin.passkeyBusy": "Очікування ключа доступу…",
  "signin.email": "Електронна пошта",
  "signin.password": "Пароль",
  "signin.submit": "Увійти",
  "signin.submitBusy": "Вхід…",
  "signin.mfaHint":
    "Введіть 6-значний код із застосунку-автентифікатора або код відновлення.",
  "signin.codeLabel": "Код автентифікації",
  "signin.verify": "Підтвердити",
  "signin.verifying": "Перевірка…",
  "signin.noMethods": "Жодного способу входу не налаштовано.",
  "signin.failed": "Не вдалося увійти.",
  "signin.invalidCreds": "Неправильна пошта або пароль.",
  "signin.ssoIdpError": "Постачальник ідентифікації повідомив про помилку.",
  "signin.ssoBadCallback": "Відповідь на вхід була неповною. Спробуйте ще раз.",
  "signin.ssoStateMissing": "Спроба входу спливла. Спробуйте ще раз.",
  "signin.ssoTokenInvalid": "Не вдалося перевірити вхід. Спробуйте ще раз.",
  "signin.ssoAccessDenied": "Вашому обліковому запису вхід тут заборонено.",
  "signin.ssoInternal": "Під час завершення входу щось пішло не так.",

  // account
  "account.title": "Обліковий запис",
  "account.signedInAs": "Ви увійшли як",
  "account.changePassword": "Змінити пароль",
  "account.currentPassword": "Поточний пароль",
  "account.newPassword": "Новий пароль",
  "account.updatePassword": "Оновити пароль",
  "account.pwChanged": "Пароль змінено.",
  "account.changeEmail": "Змінити пошту",
  "account.newEmail": "Нова пошта",
  "account.updateEmail": "Оновити пошту",
  "account.emailChanged": "Пошту змінено на {email}.",
  "account.twofa": "Двофакторна автентифікація",
  "account.recoverySave":
    "Збережіть ці одноразові коди відновлення в надійному місці - кожен спрацьовує один раз, якщо ви втратите автентифікатор.",
  "account.copyCodes": "Копіювати коди",
  "account.codesCopied": "Коди відновлення скопійовано.",
  "account.scanQR":
    "Проскануйте цей QR-код застосунком-автентифікатором (або введіть секрет вручну), потім введіть 6-значний код для підтвердження.",
  "account.totpQRAlt": "QR-код TOTP",
  "account.secretManual": "Секрет (ручне введення)",
  "account.code": "Код",
  "account.enable2fa": "Увімкнути 2FA",
  "account.twofaEnabled": "Двофакторну автентифікацію увімкнено.",
  "account.protected": "Ваш обліковий запис захищено застосунком-автентифікатором.",
  "account.confirmPassword": "Підтвердьте пароль",
  "account.regenCodes": "Перегенерувати коди відновлення",
  "account.newCodes": "Нові коди відновлення згенеровано.",
  "account.disable2fa": "Вимкнути 2FA",
  "account.twofaDisabled": "Двофакторну автентифікацію вимкнено.",
  "account.addFactor":
    "Додайте другий фактор із застосунком-автентифікатором (лише для локальних облікових записів із паролем).",
  "account.setup2fa": "Налаштувати 2FA",
  "account.passkeys": "Ключі доступу",
  "account.noPasskeys": "Ключів доступу ще немає.",
  "account.colName": "Назва",
  "account.colAdded": "Додано",
  "account.remove": "Видалити",
  "account.pkRemovePrompt": "Підтвердьте пароль, щоб видалити цей ключ доступу:",
  "account.pkRemoved": "Ключ доступу видалено.",
  "account.pkNameLabel": "Назва (щоб упізнати цей пристрій)",
  "account.pkNamePlaceholder": "напр. MacBook Touch ID",
  "account.addPasskey": "Додати ключ доступу",
  "account.pkBusy": "Очікування автентифікатора…",
  "account.pkAdded": "Ключ доступу додано.",

  // users (admin)
  "users.title": "Користувачі",
  "users.intro":
    "Керуйте тим, хто може входити. Пароль створює локальний обліковий запис, залиште поле порожнім для SSO-запису, що створюється за поштою.",
  "users.phEmail": "пошта",
  "users.phName": "ім'я (необов'язково)",
  "users.phPassword": "пароль (необов'язково)",
  "users.add": "Додати",
  "users.localCreated": "Локального користувача створено.",
  "users.oidcCreated": "OIDC-користувача створено.",
  "users.colEmail": "Пошта",
  "users.colRole": "Роль",
  "users.colSource": "Джерело",
  "users.col2fa": "2FA",
  "users.colPasskeys": "Ключі",
  "users.colEnabled": "Активний",
  "users.colActions": "Дії",
  "users.roleUser": "user",
  "users.roleAdmin": "admin",
  "users.pinned": "закріплений",
  "users.on": "так",
  "users.roleSet": "{email} тепер має роль {role}.",
  "users.disable": "вимкнути",
  "users.enable": "увімкнути",
  "users.disabled": "Користувача вимкнено.",
  "users.enabled": "Користувача увімкнено.",
  "users.resetPw": "скинути пароль",
  "users.pwPrompt": "Новий пароль для {email} (8-72 символи):",
  "users.pwReset": "Пароль скинуто.",
  "users.revoke2fa": "відкликати 2FA",
  "users.confirm2fa": "Відкликати 2FA для {email}?",
  "users.twofaRevoked": "2FA відкликано.",
  "users.revokeKeys": "відкликати ключі",
  "users.confirmKeys": "Видалити всі ключі доступу для {email}?",
  "users.keysRemoved": "Ключі доступу видалено.",
  "users.delete": "видалити",
  "users.confirmDelete": "Видалити {email}? Цю дію неможливо скасувати.",
  "users.deleted": "Користувача видалено.",
};
