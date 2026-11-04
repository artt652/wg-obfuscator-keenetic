# wg-obfuscator-keenetic

Пакет [WireGuard Obfuscator](https://github.com/ClusterM/wg-obfuscator) (ClusterM) для роутеров
Keenetic с Entware, с веб-панелью управления.

- `wg-obfuscator` v1.6 — официальная статическая сборка;
- веб-панель (`http://<IP роутера>:8090`): форма настроек и текстовый режим, импорт конфига с сервера,
  старт/стоп/перезапуск, журнал, туннели WireGuard с именами из KeeneticOS, время работы, MTU;
- проверка конфига по правилам парсера v1.6 и автоматический откат, если обфускатор не запустился;
- журнал по умолчанию на уровне `ERROR`, его можно выключить совсем («Выключен» — без файла журнала,
  на накопитель ничего не пишется);
- вкладка «Встроенный» — для модуля WireGuard со встроенным клиентом wg-obfuscator (см. ниже);
- конвертер конфига клиента (секция обфускатора + конфиг WireGuard) в `.conf` AmneziaWG для импорта
  в KeeneticOS — во вкладке «Встроенный» или из консоли: `wg-obfuscator-panel -awgconf client.txt > ob.conf`.

| Архитектура Entware | Модели (примеры) |
| --- | --- |
| `mipsel-3.4` | Titan/Ultra KN-1810, Giga KN-1010/1011, Viva, Extra, Hopper KN-3810 |
| `mips-3.4` | DSL KN-2010, Duo KN-2110, Skipper DSL, Giga SE KN-2410 |
| `aarch64-3.10` | Peak KN-2710, Ultra KN-1811, Giga KN-1012, Hopper KN-3811 |

Свою узнать: `opkg print-architecture`.

## Установка из репозитория

opkg в Entware по умолчанию скачивает через busybox `wget`, а он не умеет HTTPS (ошибка
`not an http or ftp url`). Сначала поставьте wget с TLS и корневые сертификаты:

```sh
opkg update && opkg install wget-ssl ca-certificates
ARCH=mipsel-3.4   # ваша архитектура
echo "src/gz wg-obfuscator https://artt652.github.io/wg-obfuscator-keenetic/$ARCH" >> /opt/etc/opkg.conf
opkg update
opkg install wg-obfuscator-keenetic
```

В конце установки будут напечатаны адрес панели и пароль. Обновление: `opkg update && opkg upgrade`.

Без репозитория — скачайте `.ipk` из [Releases](https://github.com/artt652/wg-obfuscator-keenetic/releases)
и выполните `opkg install /opt/tmp/<файл>.ipk`.

## Встроенный обфускатор

Отдельный пакет `wgobfs-kmod` заменяет модуль `wireguard.ko` KeeneticOS на сборку со встроенным клиентом
wg-obfuscator (STUN-маскировка): туннель идёт прямо на сервер обфускатора, без процесса на роутере.
Модуль включается параметром I5 туннеля. Пока есть сборка только для KN-1810 (Titan),
KeeneticOS 5.2 Beta 2; сам пакет модуля в этот репозиторий не входит.

Если пакет установлен, во вкладке «Встроенный» панели:

- состояние модуля и автозапуска, журнал последней подмены, кнопка «Загрузить модуль сейчас»;
- режим каждого туннеля, связанного с секцией обфускатора:
  - **встроенный** — I5 и endpoint сервера берутся из секции;
  - **внешний** — endpoint `127.0.0.1:<порт секции>`, работает процесс `wg-obfuscator`;
  - **авто** — встроенный, если модуль загружен, иначе внешний (например, после обновления прошивки);
- ручная настройка I5 для туннелей без секции.

Ключ, сервер и маскировка задаются один раз в секции обфускатора; после её сохранения туннели
во встроенном режиме обновляются сами.

## Удаление

```sh
opkg remove wg-obfuscator-keenetic
```

Обе службы (обфускатор и панель) останавливаются, конфиги остаются на месте. Туннели WireGuard с
endpoint `127.0.0.1:<порт>` после этого не подключатся: укажите в них адрес сервера WireGuard напрямую
или другой способ подключения.

Если стоит и пакет встроенного обфускатора [`wgobfs-kmod`](https://github.com/artt652/keenetic-wgobfs),
сначала удалите его по инструкции в его README: режим «внешний» в нём опирается на этот пакет.

Оставшиеся файлы, если они больше не нужны:

```sh
rm -f /opt/etc/wg-obfuscator.conf /opt/etc/wg-obfuscator-panel.conf /opt/var/log/wg-obfuscator.log
sed -i '/wg-obfuscator-keenetic/d' /opt/etc/opkg.conf          # строка репозитория
```

## Сборка

```sh
./pkg/build-ipk.sh             # все архитектуры, результат в pkg/out/
./pkg/build-ipk.sh mipsel-3.4  # одна
./pkg/make-feed.sh             # opkg-репозиторий в dist/
```

Нужны Go ≥ 1.24, curl, tar, gzip. Выпуск: тег `vX.Y-Z` → GitHub Actions собирает пакеты, прикладывает
их к релизу и публикует репозиторий на GitHub Pages.

## Лицензия

GPL-3.0. wg-obfuscator — © ClusterM, GPL-3.0.
