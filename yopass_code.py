#!/usr/bin/env python3

import argparse
import importlib
import json
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen


YOPASS_URL = "https://pass.rtlabs.ru"
DEFAULT_INPUT_FILE = "text.txt"
DEFAULT_OUTPUT_FILE = "total"
DEFAULT_LINES_PER_PART = 50
DEFAULT_DELAY_SECONDS = 1
DEFAULT_EXPIRATION = "1h"

# Установка PGPy выполняется во временный каталог, чтобы не требовать
# прав на /home/trinket/.local и не изменять системные пакеты.
DEPENDENCIES_DIR = Path(tempfile.gettempdir()) / "yopass_split_dependencies"


def load_pgpy():
    try:
        import pgpy
        from pgpy.constants import SymmetricKeyAlgorithm
        return pgpy, SymmetricKeyAlgorithm
    except ImportError:
        pass

    DEPENDENCIES_DIR.mkdir(parents=True, exist_ok=True)

    if str(DEPENDENCIES_DIR) not in sys.path:
        sys.path.insert(0, str(DEPENDENCIES_DIR))

    try:
        import pgpy
        from pgpy.constants import SymmetricKeyAlgorithm
        return pgpy, SymmetricKeyAlgorithm
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
            "Не удалось установить PGPy. Среда выполнения должна разрешать "
            "загрузку пакетов из PyPI."
        ) from error

    importlib.invalidate_caches()

    try:
        import pgpy
        from pgpy.constants import SymmetricKeyAlgorithm
        return pgpy, SymmetricKeyAlgorithm
    except ImportError as error:
        raise RuntimeError(
            f"PGPy установлена, но не импортируется из {DEPENDENCIES_DIR}"
        ) from error


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Разбивает текстовый файл на части, шифрует каждую часть локально, "
            "загружает её в Yopass и записывает ссылки в файл total."
        )
    )

    parser.add_argument(
        "input_file",
        nargs="?",
        type=Path,
        default=Path(DEFAULT_INPUT_FILE),
        help=f"Исходный файл. По умолчанию: {DEFAULT_INPUT_FILE}.",
    )

    parser.add_argument(
        "--lines",
        type=int,
        default=DEFAULT_LINES_PER_PART,
        help=(
            "Количество строк в одной части. "
            f"По умолчанию: {DEFAULT_LINES_PER_PART}."
        ),
    )

    parser.add_argument(
        "--delay",
        type=float,
        default=DEFAULT_DELAY_SECONDS,
        help=(
            "Задержка между загрузками в секундах. "
            f"По умолчанию: {DEFAULT_DELAY_SECONDS}."
        ),
    )

    parser.add_argument(
        "--output",
        type=Path,
        default=Path(DEFAULT_OUTPUT_FILE),
        help=f"Файл со ссылками. По умолчанию: {DEFAULT_OUTPUT_FILE}.",
    )

    parser.add_argument(
        "--parts-dir",
        type=Path,
        default=None,
        help=(
            "Каталог для разделённых файлов. По умолчанию: "
            "<имя_исходного_файла>_parts."
        ),
    )

    parser.add_argument(
        "--expiration",
        choices=("1h", "1d", "1w"),
        default=DEFAULT_EXPIRATION,
        help=f"Срок действия ссылок. По умолчанию: {DEFAULT_EXPIRATION}.",
    )

    parser.add_argument(
        "--multiple",
        action="store_true",
        help="Создавать многоразовые ссылки вместо одноразовых.",
    )

    return parser.parse_args()


def validate_arguments(args: argparse.Namespace) -> None:
    if not args.input_file.exists():
        raise ValueError(f"Файл не найден: {args.input_file}")

    if not args.input_file.is_file():
        raise ValueError(f"Указанный путь не является файлом: {args.input_file}")

    if args.lines <= 0:
        raise ValueError("--lines должен быть больше нуля.")

    if args.delay < 0:
        raise ValueError("--delay не может быть отрицательным.")


def split_file(
    input_file: Path,
    parts_dir: Path,
    lines_per_part: int,
) -> list[Path]:
    if parts_dir.exists():
        shutil.rmtree(parts_dir)

    parts_dir.mkdir(parents=True, exist_ok=True)

    parts: list[Path] = []
    buffer: list[str] = []

    with input_file.open("r", encoding="utf-8") as source:
        for line in source:
            buffer.append(line)

            if len(buffer) == lines_per_part:
                part_path = parts_dir / f"part_{len(parts) + 1:04d}.txt"
                part_path.write_text("".join(buffer), encoding="utf-8")
                parts.append(part_path)
                buffer.clear()

    if buffer:
        part_path = parts_dir / f"part_{len(parts) + 1:04d}.txt"
        part_path.write_text("".join(buffer), encoding="utf-8")
        parts.append(part_path)

    return parts


def encrypt_message(content: str, password: str) -> str:
    pgpy, SymmetricKeyAlgorithm = load_pgpy()

    message = pgpy.PGPMessage.new(content)

    encrypted_message = message.encrypt(
        password,
        cipher=SymmetricKeyAlgorithm.AES256,
    )

    return str(encrypted_message)


def extract_secret_id(response_data: object) -> str:
    if isinstance(response_data, str) and response_data:
        return response_data

    if not isinstance(response_data, dict):
        raise RuntimeError(
            f"Неожиданный формат ответа Yopass: {response_data!r}"
        )

    for field in ("message", "key", "id", "secret"):
        value = response_data.get(field)
        if isinstance(value, str) and value:
            return value

    raise RuntimeError(
        f"В ответе Yopass нет идентификатора секрета: {response_data}"
    )


def upload_part(
    part_path: Path,
    expiration: str,
    one_time: bool,
) -> str:
    content = part_path.read_text(encoding="utf-8")

    if not content:
        raise RuntimeError(f"Файл части пуст: {part_path}")

    password = secrets.token_urlsafe(24)
    encrypted_message = encrypt_message(content, password)

    expiration_seconds = {
        "1h": 3600,
        "1d": 86400,
        "1w": 604800,
    }[expiration]

    payload = {
        "expiration": expiration_seconds,
        "message": encrypted_message,
        "one_time": one_time,
    }

    body = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")

    request = Request(
        f"{YOPASS_URL}/secret",
        data=body,
        method="POST",
        headers={
            "Accept": "*/*",
            "Content-Type": "text/plain;charset=UTF-8",
            "Origin": YOPASS_URL,
            "User-Agent": "yopass-split/1.0",
        },
    )

    try:
        with urlopen(request, timeout=30) as response:
            response_text = response.read().decode("utf-8")
    except HTTPError as error:
        response_text = error.read().decode("utf-8", errors="replace")
        raise RuntimeError(
            f"Yopass вернул HTTP {error.code}: {response_text[:500]}"
        ) from error
    except URLError as error:
        raise RuntimeError(f"Ошибка подключения к Yopass: {error.reason}") from error

    try:
        response_data = json.loads(response_text)
    except json.JSONDecodeError as error:
        raise RuntimeError(
            f"Yopass вернул не JSON: {response_text[:500]}"
        ) from error

    secret_id = extract_secret_id(response_data)

    return (
        f"{YOPASS_URL}/#/s/"
        f"{quote(secret_id, safe='')}/"
        f"{quote(password, safe='')}"
    )


def main() -> int:
    args = parse_arguments()

    try:
        validate_arguments(args)
    except ValueError as error:
        print(f"Ошибка: {error}", file=sys.stderr)
        return 1

    parts_dir = (
        args.parts_dir
        if args.parts_dir is not None
        else args.input_file.parent / f"{args.input_file.stem}_parts"
    )

    try:
        parts = split_file(
            input_file=args.input_file,
            parts_dir=parts_dir,
            lines_per_part=args.lines,
        )
    except (OSError, UnicodeError) as error:
        print(f"Ошибка при разделении файла: {error}", file=sys.stderr)
        return 1

    if not parts:
        print("Исходный файл пуст.", file=sys.stderr)
        return 1

    print(f"Исходный файл: {args.input_file}")
    print(f"Количество частей: {len(parts)}")
    print(f"Каталог частей: {parts_dir}")
    print(f"Файл результатов: {args.output}")
    print(f"Строк в части: {args.lines}")
    print(f"Задержка: {args.delay:g} сек.")
    print(f"Срок действия: {args.expiration}")
    print(f"Одноразовые ссылки: {'да' if not args.multiple else 'нет'}")
    print()

    args.output.parent.mkdir(parents=True, exist_ok=True)

    try:
        # Проверяем и при необходимости устанавливаем PGPy до начала цикла.
        load_pgpy()

        with args.output.open("w", encoding="utf-8") as output_file:
            for index, part_path in enumerate(parts, start=1):
                print(f"[{index}/{len(parts)}] Загрузка {part_path.name}...")

                try:
                    url = upload_part(
                        part_path=part_path,
                        expiration=args.expiration,
                        one_time=not args.multiple,
                    )
                except Exception as error:
                    print(
                        f"Ошибка при обработке {part_path.name}: {error}",
                        file=sys.stderr,
                    )
                    print(
                        f"Успешно обработано частей: {index - 1}",
                        file=sys.stderr,
                    )
                    return 1

                # В total записываются только ссылки, без нумерации и имён файлов.
                output_file.write(f"{url}\n")
                output_file.flush()

                print(f"[{index}/{len(parts)}] Готово: {url}")

                if index < len(parts) and args.delay > 0:
                    time.sleep(args.delay)

    except OSError as error:
        print(f"Ошибка работы с файлом {args.output}: {error}", file=sys.stderr)
        return 1
    except RuntimeError as error:
        print(f"Ошибка: {error}", file=sys.stderr)
        return 1

    try:
        if parts_dir.exists():
            shutil.rmtree(parts_dir)
            print(f"Временный каталог удалён: {parts_dir}")
    except OSError as error:
        print(f"Предупреждение: не удалось удалить {parts_dir}: {error}", file=sys.stderr)

    print()
    print(f"Готово. Получено ссылок: {len(parts)}")
    print(f"Результат записан в: {args.output}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
