# Учёт винтажа — GitHub Pages

## Put it online

1. Create a GitHub account (if needed) and a **new repository**, e.g. `uchet-vintazha`.
2. Click **Add file → Upload files** and drag in **all the files of this folder**
   (`index.html`, `storage.js`, `seed.enc.json`, `manifest.webmanifest`, `icon-192.png`, `icon-512.png`, `.nojekyll`).
   Click **Commit changes**.
3. Go to **Settings → Pages**. Under *Build and deployment*, choose **Deploy from a branch**,
   branch **main**, folder **/ (root)**, then **Save**.
4. After 1–2 minutes your site is at `https://YOUR-NAME.github.io/uchet-vintazha/`.

## Password

The app asks for the password when it opens. Your data file (`seed.enc.json`) is **encrypted** with it
(AES-256), so it can't be read on GitHub without the password.
Tick **«Запомнить на этом устройстве»** to skip the password on your own phone/computer.
**«Выйти (заблокировать)»** at the top locks it again.

## Important: how the data is saved

GitHub Pages has no server, so changes are saved **in the browser of each device** (encrypted).
Your phone and your computer do **not** share changes automatically.

- To move data between devices: **Бухгалтерия → Резервная копия → Скачать JSON** on one device,
  then **Загрузить из JSON** on the other.
- Download a backup regularly — clearing the browser's data erases the local copy.
- The backup JSON file is **not** encrypted: keep it private.

If you want one shared database for all devices, use the server version (`uchet-vintazha.zip`) instead.

## Change the password

The password is built into the encrypted file, so changing it means creating a new `seed.enc.json`.
Ask Claude to re-encrypt with a new password, or use the server version, which has its own login.
