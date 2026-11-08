#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."

version=
changes=()
while IFS= read -r line || [[ -n $line ]]; do
    if [[ $line == "Version "* ]]; then
        [[ -z $version ]] || break
        read -r _ version _ <<< "$line"
    elif [[ -n $version && -n ${line//[[:space:]]/} ]]; then
        changes+=("  $line")
    fi
done < Changelog
[[ -n $version ]] || { echo "Changelog has no release" >&2; exit 1; }

mapfile -t debian < debian/changelog
header=${debian[0]:-}
pattern='^borderline \(([^)]+)\) '
[[ $header =~ $pattern ]] ||
    { echo "Invalid Debian changelog header" >&2; exit 1; }
previous=${BASH_REMATCH[1]}
signature=
for index in "${!debian[@]}"; do
    if [[ ${debian[index]} == " -- "* ]]; then
        signature=${debian[index]}
        history=$((index + 1))
        break
    fi
done
[[ -n $signature ]] ||
    { echo "Invalid Debian changelog entry" >&2; exit 1; }

if [[ $version != "$previous" ]]; then
    dpkg --compare-versions "$version" gt "$previous" ||
        { echo "Changelog version $version is older than $previous" >&2; exit 1; }
    timestamp=$(git show -s --format=%cD "refs/tags/$version^{commit}" --)
    header="borderline ($version) unstable; urgency=medium"
    signature=" -- Anders Peter Fugmann <anders@fugmann.net>  $timestamp"
fi

temp=$(mktemp)
trap 'rm -f -- "$temp"' EXIT
{
    printf '%s\n\n' "$header"
    if ((${#changes[@]})); then
        printf '%s\n' "${changes[@]}"
    fi
    printf '\n%s\n' "$signature"
    if [[ $version == "$previous" ]]; then
        if ((history < ${#debian[@]})); then
            printf '%s\n' "${debian[@]:history}"
        fi
    else
        printf '\n'
        cat debian/changelog
    fi
} > "$temp"

if ! cmp -s "$temp" debian/changelog; then
    cat "$temp" > debian/changelog
fi
