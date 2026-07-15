#!/usr/bin/env python3

import argparse
import importlib
import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import unquote, urlparse
from urllib.request import Request, urlopen


YOPASS_URL = "https://pass.rtlabs.ru"
DEFAULT_LINKS_FILE = "total"
DEFAULT_OUTPUT_FILE = "restored.txt"
DEFAULT_DELAY_SECONDS = 1
DEPENDENCIES_DIR = Path(tempfile.gettempdir()) / "yopass_split_dependencies"


def load_pgpy():
    """Загружает PGPy или устанавливает её во временный каталог."""
    try:
        import pgpy
        return pgpy
    except ImportError:
        pass

    DEPENDENCIES_DIR.mkdir(parents=True, exist_ok=True)

    if str(DEPENDENCIES_DIR) not in sys.path:
        sys.path.insert(0, str(DEPENDENCIES_DIR))

    try:
        import pgpy
        return pgpy
    except ImportError:
        print("Устанавливаю зависимость PGPy во временный каталог...")

    try:
        subprocess.check_call(
            [
                sys.executable,
                "-m",
                "pip",
                "install",
                "--quiet",
                "--disable-pip-version-check",
                "--no-cache-dir",
                "--target",
                str(DEPENDENCIES_DIR),
                "PGPy",
            ]
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise RuntimeError(
            "Не удалось установить PGPy. Установите её вручную командой: "
            "python -m pip install PGPy"
        ) from error

    importlib.invalidate_caches()

    try:
        import pgpy
        return pgpy
    except ImportError as error:
        raise RuntimeError(
            f"PGPy установлена, но не импортируется из {DEPENDENCIES_DIR}"
        ) from error


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Читает ссылки Yopass из файла, расшифровывает их по порядку "
            "и объединяет содержимое в один восстановленный файл."
        )
    )

    parser.add_argument(
        "links_file",
        nargs="?",
        type=Path,
        default=Path(DEFAULT_LINKS_FILE),
        help=f"Файл со ссылками. По умолчанию: {DEFAULT_LINKS_FILE}.",
    )

    parser.add_argument(
        "--output",
        type=Path,
        default=Path(DEFAULT_OUTPUT_FILE),
        help=f"Восстановленный файл. По умолчанию: {DEFAULT_OUTPUT_FILE}.",
    )

    parser.add_argument(
        "--delay",
        type=float,
        default=DEFAULT_DELAY_SECONDS,
        help=(
            "Задержка между скачиваниями в секундах. "
            f"По умолчанию: {DEFAULT_DELAY_SECONDS}."
        ),
    )

    return parser.parse_args()


def validate_arguments(args: argparse.Namespace) -> None:
    if not args.links_file.exists():
        raise ValueError(f"Файл со ссылками не найден: {args.links_file}")

    if not args.links_file.is_file():
        raise ValueError(
            f"Указанный путь не является файлом: {args.links_file}"
        )

    if args.delay < 0:
        raise ValueError("--delay не может быть отрицательным.")

    try:
        if args.links_file.resolve() == args.output.resolve():
            raise ValueError(
                "Файл со ссылками и восстановленный файл не должны совпадать."
            )
    except OSError:
        pass


def check_yopass() -> None:
    """Проверяет доступность Yopass до чтения одноразовых секретов."""
    print("Проверка доступности Yopass...")

    request = Request(
        f"{YOPASS_URL}/",
        method="GET",
        headers={"User-Agent": "yopass-decode/1.0"},
    )

    try:
        with urlopen(request, timeout=10) as response:
            print(f"Yopass доступен (HTTP {response.status})")
    except HTTPError as error:
        # Сервер отвечает, поэтому соединение с ним установлено.
        print(f"Yopass отвечает (HTTP {error.code})")
    except URLError as error:
        raise RuntimeError(
            "Не удалось подключиться к pass.rtlabs.ru. "
            f"Причина: {error.reason}. Проверьте VPN и доступ из текущей сети."
        ) from error
    except TimeoutError as error:
        raise RuntimeError(
            "Истекло время ожидания подключения к pass.rtlabs.ru. "
            "Проверьте VPN и доступ из текущей сети."
        ) from error


def read_links(links_file: Path) -> list[str]:
    links = [
        line.strip()
        for line in links_file.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]

    if not links:
        raise ValueError(f"В файле {links_file} нет ссылок.")

    return links


def parse_yopass_url(url: str) -> tuple[str, str]:
    """
    Разбирает ссылку вида:
    https://pass.rtlabs.ru/#/s/<secret_id>/<password>
    """
    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        raise ValueError("в ссылке отсутствует корректный протокол HTTP/HTTPS")

    if parsed.netloc.lower() != "pass.rtlabs.ru":
        raise ValueError(
            f"ожидался хост pass.rtlabs.ru, получен {parsed.netloc!r}"
        )

    fragment_parts = [
        unquote(part)
        for part in parsed.fragment.strip("/").split("/")
        if part
    ]

    if len(fragment_parts) < 3 or fragment_parts[0] != "s":
        raise ValueError(
            "ожидался формат #/s/<идентификатор>/<ключ>"
        )

    secret_id = fragment_parts[1]
    password = "/".join(fragment_parts[2:])

    if not secret_id or not password:
        raise ValueError("в ссылке отсутствует идентификатор или ключ")

    return secret_id, password


def extract_encrypted_message(response_data: object) -> str:
    if isinstance(response_data, str) and response_data:
        return response_data

    if not isinstance(response_data, dict):
        raise RuntimeError(
            f"Неожиданный формат ответа Yopass: {response_data!r}"
        )

    for field in ("message", "secret", "data"):
        value = response_data.get(field)
        if isinstance(value, str) and value:
            return value

    raise RuntimeError(
        f"В ответе Yopass нет зашифрованного сообщения: {response_data}"
    )


def download_encrypted_secret(secret_id: str) -> str:
    request = Request(
        f"{YOPASS_URL}/secret/{secret_id}",
        method="GET",
        headers={
            "Accept": "application/json, text/plain, */*",
            "Origin": YOPASS_URL,
            "User-Agent": "yopass-decode/1.0",
        },
    )

    try:
        with urlopen(request, timeout=30) as response:
            response_text = response.read().decode("utf-8")
    except HTTPError as error:
        body = error.read().decode("utf-8", errors="replace")

        if error.code == 404:
            raise RuntimeError(
                "секрет не найден, уже был открыт или срок его действия истёк"
            ) from error

        raise RuntimeError(
            f"Yopass вернул HTTP {error.code}: {body[:500]}"
        ) from error
    except URLError as error:
        raise RuntimeError(
            f"ошибка подключения к Yopass: {error.reason}"
        ) from error
    except TimeoutError as error:
        raise RuntimeError(
            "истекло время ожидания ответа от Yopass"
        ) from error

    try:
        response_data = json.loads(response_text)
    except json.JSONDecodeError:
        # Некоторые инстансы могут вернуть PGP-блок как обычный текст.
        if "-----BEGIN PGP MESSAGE-----" in response_text:
            return response_text

        raise RuntimeError(
            f"Yopass вернул неожиданный ответ: {response_text[:500]}"
        )

    return extract_encrypted_message(response_data)


def decrypt_message(encrypted_message: str, password: str) -> str:
    pgpy = load_pgpy()

    try:
        pgp_message = pgpy.PGPMessage.from_blob(encrypted_message)
        decrypted_message = pgp_message.decrypt(password)
    except Exception as error:
        raise RuntimeError(
            "не удалось расшифровать секрет: возможно, ключ в ссылке неверный"
        ) from error

    content = decrypted_message.message

    if isinstance(content, bytes):
        try:
            return content.decode("utf-8")
        except UnicodeDecodeError as error:
            raise RuntimeError(
                "расшифрованное содержимое не является текстом UTF-8"
            ) from error

    return str(content)


def main() -> int:
    args = parse_arguments()

    try:
        validate_arguments(args)
        check_yopass()
        links = read_links(args.links_file)
    except (ValueError, RuntimeError, OSError, UnicodeError) as error:
        print(f"Ошибка: {error}", file=sys.stderr)
        return 1

    print(f"Файл со ссылками: {args.links_file}")
    print(f"Количество ссылок: {len(links)}")
    print(f"Восстановленный файл: {args.output}")
    print(f"Задержка: {args.delay:g} сек.")
    print()
    print(
        "Внимание: одноразовая ссылка удаляется с сервера при чтении. "
        "Не запускайте скрипт повторно для уже обработанных ссылок."
    )
    print()

    args.output.parent.mkdir(parents=True, exist_ok=True)

    try:
        # Проверяем зависимость до обращения к первой одноразовой ссылке.
        load_pgpy()
    except RuntimeError as error:
        print(f"Ошибка: {error}", file=sys.stderr)
        return 1

    processed = 0

    try:
        # Файл пересоздаётся при каждом новом запуске.
        with args.output.open("wb") as output_file:
            for index, url in enumerate(links, start=1):
                print(f"[{index}/{len(links)}] Получение секрета...")

                try:
                    secret_id, password = parse_yopass_url(url)
                    encrypted_message = download_encrypted_secret(secret_id)
                    content = decrypt_message(encrypted_message, password)
                except (ValueError, RuntimeError) as error:
                    print(
                        f"Ошибка при обработке ссылки {index}: {error}",
                        file=sys.stderr,
                    )
                    print(
                        f"Успешно восстановлено частей: {processed}",
                        file=sys.stderr,
                    )
                    print(
                        f"Частичный результат сохранён в: {args.output}",
                        file=sys.stderr,
                    )
                    return 1

                # Записываем исходные байты без добавления разделителей,
                # чтобы восстановить исходный файл строка в строку.
                output_file.write(content.encode("utf-8"))
                output_file.flush()

                processed += 1
                print(f"[{index}/{len(links)}] Готово")

                if index < len(links) and args.delay > 0:
                    time.sleep(args.delay)

    except OSError as error:
        print(f"Ошибка записи в файл {args.output}: {error}", file=sys.stderr)
        return 1

    print()
    print(f"Готово. Восстановлено частей: {processed}")
    print(f"Результат записан в: {args.output}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
