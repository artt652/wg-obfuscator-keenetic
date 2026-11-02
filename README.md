# wg-obfuscator-keenetic

Пакет [WireGuard Obfuscator](https://github.com/ClusterM/wg-obfuscator) (ClusterM) для роутеров
Keenetic с Entware, с веб-панелью управления.

- `wg-obfuscator` v1.6 — официальная статическая сборка;
- веб-панель (`http://<IP роутера>:8090`): форма настроек и текстовый режим, импорт конфига с сервера,
  старт/стоп/перезапуск, журнал, туннели WireGuard с именами из KeeneticOS, время работы, MTU;
- проверка конфига по правилам парсера v1.6 и автоматический откат, если обфускатор не запустился.

| Архитектура Entware | Модели (примеры) |
| --- | --- |
| `mipsel-3.4` | Titan/Ultra KN-1810, Giga KN-1010/1011, Viva, Extra, Hopper KN-3810 |
| `mips-3.4` | DSL KN-2010, Duo KN-2110, Skipper DSL, Giga SE KN-2410 |
| `aarch64-3.10` | Peak KN-2710, Ultra KN-1811, Giga KN-1012, Hopper KN-3811 |

Свою узнать: `opkg print-architecture`.

## Установка из репозитория

```sh
ARCH=mipsel-3.4   # ваша архитектура
echo "src/gz wg-obfuscator https://artt652.github.io/wg-obfuscator-keenetic/$ARCH" >> /opt/etc/opkg.conf
opkg update
opkg install wg-obfuscator-keenetic
```

В конце установки будут напечатаны адрес панели и пароль. Обновление: `opkg update && opkg upgrade`.

Без репозитория — скачайте `.ipk` из [Releases](https://github.com/artt652/wg-obfuscator-keenetic/releases)
и выполните `opkg install /opt/tmp/<файл>.ipk`.

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
