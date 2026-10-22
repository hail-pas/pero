#!/usr/bin/env bash
# Generate SeaORM entities and apply project-specific post-processing.
#
# Usage:
#   ./scripts/generate-entity.sh <service> <database_url>
#   ./scripts/generate-entity.sh --postprocess-only <service>
#
# Requires: sea-orm-cli installed for generation (cargo install sea-orm-cli)

set -euo pipefail

usage() {
    cat >&2 <<'EOF'
Usage:
  scripts/generate-entity.sh <service> <database_url>
  scripts/generate-entity.sh --postprocess-only <service>

Arguments:
  service       Service name under services/ (e.g. user-center)
  database_url  Database connection URL
EOF
}

require_service() {
    local service="$1"

    if [ -z "$service" ]; then
        usage
        exit 2
    fi

    if [ ! -d "services/${service}" ]; then
        echo "Error: service directory 'services/${service}' not found" >&2
        exit 1
    fi
}

require_entity_dir() {
    local entity_dir="$1"

    if [ ! -d "$entity_dir" ]; then
        echo "Error: entity directory '${entity_dir}' not found" >&2
        exit 1
    fi
}

generate_entities() {
    local db_url="$1"
    local entity_dir="$2"

    echo "==> Generating SeaORM entities for ${SERVICE}..."
    sea-orm-cli generate entity \
        --database-url "$db_url" \
        --output-dir "$entity_dir" \
        --with-serde both \
        --date-time-crate time
}

postprocess_entities() {
    local db_dir="$1"
    local entity_dir="$2"

    echo "==> Post-processing generated entities..."
    python3 - "$db_dir" "$entity_dir" <<'PY'
from pathlib import Path
import re
import shutil
import sys

db_dir = Path(sys.argv[1])
entity_dir = Path(sys.argv[2])


def rewrite_custom_attr(attr: str, remove_select_as: bool) -> str:
    attr = re.sub(r'(?m)^\s*ignore,\n', '', attr)
    attr = re.sub(r'(\(\s*)ignore,\s*', r'\1', attr)
    attr = re.sub(r',\s*ignore(?=\s*[,)]\s*)', '', attr)

    if remove_select_as:
        attr = re.sub(r'(?m)^\s*select_as = "text",\n', '', attr)
        attr = re.sub(r',\s*select_as = "text"(?=\s*[,)]\s*)', '', attr)
        attr = re.sub(r'(\(\s*)select_as = "text",\s*', r'\1', attr)

    return attr


def fix_custom_attrs(text: str) -> str:
    attr_pattern = re.compile(
        r'#\[sea_orm\((?:(?!\]\n).)*?column_type = "custom\(\\"[^"]+\\"\)"(?:(?!\]\n).)*?\)\]',
        re.DOTALL,
    )

    def replace(match):
        attr = match.group(0)
        is_inet = 'column_type = "custom(\\"inet\\")"' in attr
        return rewrite_custom_attr(attr, remove_select_as=is_inet)

    return attr_pattern.sub(replace, text)


def fix_inet_fields(text: str) -> str:
    inet_field_pattern = re.compile(
        r'(?P<attr>#\[sea_orm\((?:(?!\]\n).)*?column_type = "custom\(\\"inet\\"\)"(?:(?!\]\n).)*?\)\]\n)'
        r'(?P<prefix>\s*pub\s+\w+:\s*)'
        r'(?P<option>Option<)?String(?P<option_end>>)?(?P<trailing>,)',
        re.DOTALL,
    )

    def replace(match):
        rust_type = "Option<IpNetwork>" if match.group("option") else "IpNetwork"
        return f'{match.group("attr")}{match.group("prefix")}{rust_type}{match.group("trailing")}'

    text = inet_field_pattern.sub(replace, text)

    if "IpNetwork" not in text:
        return text

    if "use ipnetwork::IpNetwork;" in text:
        return text

    sea_orm_import = "use sea_orm::entity::prelude::*;\n"
    if sea_orm_import in text:
        return text.replace(sea_orm_import, f"use ipnetwork::IpNetwork;\n{sea_orm_import}", 1)

    return text.replace("\n\n", "\n\nuse ipnetwork::IpNetwork;\n", 1)


def postprocess_entity_file(path: Path) -> None:
    text = path.read_text()
    text = text.replace("use super::sea_orm_active_enums::", "use super::super::enums::")
    text = fix_custom_attrs(text)
    text = fix_inet_fields(text)
    path.write_text(text)


enum_src = entity_dir / "sea_orm_active_enums.rs"
enum_dst = db_dir / "enums.rs"
if enum_src.exists():
    shutil.move(str(enum_src), str(enum_dst))
    print("    Moved sea_orm_active_enums.rs -> db/enums.rs")
else:
    print("    No enum file found. Skipping enum move.")

for path in sorted(entity_dir.glob("*.rs")):
    postprocess_entity_file(path)

mod_rs = entity_dir / "mod.rs"
if mod_rs.exists():
    lines = mod_rs.read_text().splitlines(keepends=True)
    mod_rs.write_text("".join(line for line in lines if line.strip() != "pub mod sea_orm_active_enums;"))
PY
}

format_generated_files() {
    local db_dir="$1"
    local entity_dir="$2"
    local files=()

    if ! command -v rustfmt >/dev/null 2>&1; then
        echo "==> rustfmt not found. Skipping generated file formatting."
        return
    fi

    while IFS= read -r file; do
        files+=("$file")
    done < <(find "$entity_dir" -maxdepth 1 -type f -name '*.rs' | sort)

    if [ -f "${db_dir}/enums.rs" ]; then
        files+=("${db_dir}/enums.rs")
    fi

    if [ "${#files[@]}" -gt 0 ]; then
        echo "==> Formatting generated db files..."
        rustfmt --edition 2024 "${files[@]}"
    fi
}

if [ "${1:-}" = "--postprocess-only" ]; then
    SERVICE="${2:-}"
    require_service "$SERVICE"
    DB_DIR="services/${SERVICE}/src/db"
    ENTITY_DIR="${DB_DIR}/entity"
    require_entity_dir "$ENTITY_DIR"
    postprocess_entities "$DB_DIR" "$ENTITY_DIR"
    format_generated_files "$DB_DIR" "$ENTITY_DIR"
    echo "==> Done. Run 'cargo check -p ${SERVICE}' to verify."
    exit 0
fi

if [ "$#" -ne 2 ]; then
    usage
    exit 2
fi

SERVICE="$1"
DB_URL="$2"
require_service "$SERVICE"

DB_DIR="services/${SERVICE}/src/db"
ENTITY_DIR="${DB_DIR}/entity"

generate_entities "$DB_URL" "$ENTITY_DIR"
postprocess_entities "$DB_DIR" "$ENTITY_DIR"
format_generated_files "$DB_DIR" "$ENTITY_DIR"

echo "==> Done. Run 'cargo check -p ${SERVICE}' to verify."
