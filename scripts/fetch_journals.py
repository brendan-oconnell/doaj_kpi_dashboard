#!/usr/bin/env python3
# Copyright (c) 2026 Ikhwan Arief, Universitas Andalas.
# Code license: PolyForm Noncommercial 1.0.0
# https://polyformproject.org/licenses/noncommercial/1.0.0/
# See LICENSE and LICENSE-CODE.md
"""Fetch DOAJ journal CSV and write normalized snapshots for the dashboard.

Outputs:
    docs/data/journals.json
    docs/data/aggregates.json
    docs/data/meta.json
"""
from __future__ import annotations

import csv
import io
import json
import os
import re
import sys
import unicodedata
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

CSV_URL = os.environ.get("DOAJ_CSV_URL", "https://doaj.org/csv")
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "..", "docs", "data")


def build_session() -> requests.Session:
    retry = Retry(
        total=5,
        connect=5,
        read=5,
        backoff_factor=1.0,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset({"GET"}),
    )
    adapter = HTTPAdapter(max_retries=retry)
    session = requests.Session()
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    session.headers.update(
        {
            "Accept": "text/csv,*/*",
            "User-Agent": "doaj-dashboard-csv-fetch/1.0",
        }
    )
    return session


def get_most_recent_article_date(session: requests.Session, issn: Optional[str]) -> Optional[str]:
    """Query DOAJ API to get the most recent article update date for a journal by ISSN."""
    if not issn or not issn.strip():
        return None
    
    try:
        # Search articles by journal ISSN, get the most recent one
        from urllib.parse import quote
        import time
        search_query = f'issn:"{issn.strip()}"'
        url = f'https://doaj.org/api/v3/search/articles/{quote(search_query)}'
        
        response = session.get(url, params={'pageSize': 1}, timeout=5)
        # Rate limit: add small delay to avoid overwhelming the API
        time.sleep(0.05)
        
        if response.status_code == 200:
            data = response.json()
            if data.get('results') and len(data['results']) > 0:
                article = data['results'][0]
                # Return the last_updated date of the most recent article
                return article.get('last_updated')
    except Exception:
        # Silently fail - article data is not critical
        pass
    
    return None


def normalize_header(value: str) -> str:
    return "".join(ch.lower() for ch in value if ch.isalnum())


def split_multi(value: Optional[str]) -> List[str]:
    if not value:
        return []
    text = value.strip()
    if not text:
        return []

    if any(sep in text for sep in ("|", ";", "\n")):
        parts = [p.strip() for p in re.split(r"[|;\n]+", text) if p and p.strip()]
    elif "," in text:
        parts = [p.strip() for p in text.split(",") if p and p.strip()]
    else:
        parts = [text]

    # Keep insertion order while removing duplicates.
    seen = set()
    unique: List[str] = []
    for part in parts:
        if part not in seen:
            seen.add(part)
            unique.append(part)
    return unique


def normalize_for_match(value: str) -> str:
    folded = "".join(ch for ch in unicodedata.normalize("NFKD", value) if not unicodedata.combining(ch))
    normalized = re.sub(r"[^a-z0-9\s]", " ", folded.lower())
    return re.sub(r"\s+", " ", normalized).strip()


def smart_title(value: str) -> str:
    if value.islower() or value.isupper():
        return value.title()
    return value


def canonicalize_preservation_term(value: str) -> str:
    cleaned = re.sub(r"\s+", " ", value.strip()).strip(" .;,:-")
    if not cleaned:
        return ""

    normalized = normalize_for_match(cleaned)

    aliases = [
        (r"\bajol\b|\bafrican journals? online\b", "African Journals Online"),
        (r"\bzenodo\b|\bzenedo\b|\bzenodoo\b", "Zenodo"),
        (r"\bclockss\b", "CLOCKSS"),
        (r"\blockss\b", "LOCKSS"),
        (r"\bpkp\b.*\bpn\b|\bpkp preservation network\b", "PKP Preservation Network"),
        (r"\bpkp\s*pln\b|\bpublic knowledge project pln\b", "PKP Preservation Network"),
        (r"\bportico\b", "Portico"),
        (r"\bpubmed central\b|\bpmc\b", "PubMed Central"),
        (r"\binternet archive\b", "Internet Archive"),
        (r"\bweb archive\b|\barchive org\b", "Internet Archive"),
        (r"\bcariniana\b", "Cariniana Network"),
        (r"\bscholars?\s*portal\b", "Scholars Portal"),
        (
            r"\bhrcak\b|\bhr cak\b|\bhr ak\b|portal of (croatian|scientific journals of croatia)",
            "Hrcak Portal of Croatian Scientific Journals",
        ),
        (r"\be\s*library\b|\belibrary\b|russian electronic scientific library", "eLIBRARY.RU"),
        (r"\bmagiran\b", "Magiran"),
        (r"\bnoormags?\b", "Noormags"),
        (r"\bisc\b|\bislamic world science citation center\b", "Islamic World Science Citation Center"),
        (r"\bscindeks\b|serbian citation index", "SCIndeks (Serbian Citation Index)"),
        (r"\bcross\s*ref\b|\bcrossref\b", "CrossRef"),
        (r"\bkoreamed synapse\b", "KoreaMed Synapse"),
        (r"\bkoreamed\b", "KoreaMed"),
        (r"\bceeol\b", "CEEOL"),
        (r"\bcines\b", "CINES"),
        (r"\braco\b", "RACO"),
        (r"\bscience\s*central\b", "Science Central"),
        (r"\bkorea\s*med\b", "KoreaMed"),
        (r"\beuro\s*pub\b", "Europub"),
        (r"\bportal\s*garuda\b", "Garuda"),
        (r"\bsynapse\b", "KoreaMed Synapse"),
        (r"\bscholar\b.*\bportal\b", "Scholars Portal"),
        (r"\buniversity computing centre srce\b", "Hrcak Portal of Croatian Scientific Journals"),
        (r"\bgoogle scholar\b", "Google Scholar"),
        (r"\bsid\b", "SID"),
        (r"\bniscpr online periodicals repository\b", "NIScPR Online Periodicals Repository"),
        (r"\bin[- ]?house archiving\b", "In-house Archiving"),
        (
            r"\bjournal'?s?\s+website\b|\bjournal\s+s?\s+website\b|\bjournal\s+website\b|"
            r"\bwebsite of the journal\b|\barchived in the journal\b|\bissues of the journal\b",
            "Journal Website",
        ),
        (r"\bnational digital archives of iranian scholarly journals\b", "National Digital Archives of Iranian Scholarly Journals"),
        (r"\be\s*depot\b", "E-Depot"),
        (
            r"\bnational library of the netherlands\b|\bkoninklijke bibliotheek\b|\bkb\b",
            "KB National Library of the Netherlands",
        ),
    ]

    for pattern, canonical in aliases:
        if re.search(pattern, normalized):
            return canonical

    if re.search(r"https?://|www\.", cleaned, flags=re.I):
        url_aliases = [
            (r"\bhrcak\b", "Hrcak Portal of Croatian Scientific Journals"),
            (r"\belibrary\b|\bru\b", "eLIBRARY.RU"),
            (r"\bkoreamed\b", "KoreaMed"),
            (r"\bscholar\b", "Google Scholar"),
            (r"\barchive\b|\bjournal\b|\brepository\b", "Journal Website"),
        ]
        for pattern, canonical in url_aliases:
            if re.search(pattern, normalized):
                return canonical
        return "Journal Website"

    # Prefer expanded name inside parentheses when available.
    paren = re.search(r"\(([^)]+)\)", cleaned)
    if paren:
        inner = re.sub(r"\s+", " ", paren.group(1).strip())
        if len(inner) > 4 and " " in inner:
            return inner

    return smart_title(cleaned)


def canonicalize_preservation_services(values: Sequence[str]) -> List[str]:
    seen = set()
    canonical: List[str] = []
    for value in values:
        term = canonicalize_preservation_term(value)
        if term and term not in seen:
            seen.add(term)
            canonical.append(term)
    return canonical


def canonicalize_pid_scheme_term(value: str) -> str:
    cleaned = re.sub(r"\s+", " ", value.strip())
    if not cleaned:
        return ""

    normalized = normalize_for_match(cleaned)
    cleaned_lower = cleaned.lower()
    if "удк" in cleaned_lower:
        return "UDC"

    aliases = [
        (r"\bcross\s*ref\b|\bcrossref\b|\bcrossreff\b|\bcrossref doi\b|\bdoi.*crossref\b|\bcrossref.*doi\b", "CrossRef"),
        (r"\bdata\s*cite\b|\bdatacite\b|\bdatacitee\b", "DataCite"),
        (r"\borcid\b", "ORCID"),
        (r"\bpmcid\b", "PMCID"),
        (r"\bpmid\b", "PMID"),
        (r"\bissn\b", "ISSN"),
        (r"\bdoi\b", "DOI"),
        (r"\bark\b", "ARK"),
        (r"\burns?\b", "URN"),
        (r"\bhandles?\b", "Handle"),
        (r"\bdors?\b|\bdigital object recognizer\b", "DOR"),
        (r"\bpurls?\b", "PURL"),
        (r"\bcoden\b", "CODEN"),
        (r"\budc\b|\budk\b|\buniversal decimal classification\b|\bудк\b", "UDC"),
        (r"\bedn\b", "EDN"),
        (r"\buri\b|\bdc identifier uri\b", "URI"),
        (r"\bnbn\b", "NBN"),
        (r"\bgicid\b", "GICID"),
        (r"\bbiblid\b", "BIBLID"),
        (r"\bcu\s*id\b", "CU-ID"),
        (r"\bcrossmark\b", "Crossmark"),
        (r"\bcstr\b", "CSTR"),
        (r"\bjel\b", "JEL"),
        (r"\boai\b", "OAI"),
        (r"\bqr\b.*\bcode\b", "QR Code"),
        (r"\bpid\b", "PID"),
        (r"\bedu\s*nl\b", "Edu.nl"),
    ]

    for pattern, canonical in aliases:
        if re.search(pattern, normalized):
            return canonical

    if re.search(r"https?://|www\.", cleaned_lower):
        return "URL"

    return smart_title(cleaned)


def canonicalize_pid_schemes(values: Sequence[str]) -> List[str]:
    seen = set()
    canonical: List[str] = []
    for value in values:
        term = canonicalize_pid_scheme_term(value)
        if term and term not in seen:
            seen.add(term)
            canonical.append(term)
    return canonical


def canonicalize_peer_review_term(value: str) -> str:
    cleaned = re.sub(r"\s+", " ", value.strip())
    if not cleaned:
        return ""

    normalized = normalize_for_match(cleaned)

    aliases = [
        (r"\bpartial\b.*\bdouble\b.*\b(anonymous|blind)\b|\bdouble\b.*\b(anonymous|blind)\b", "Double anonymous peer review"),
        (r"\btriple\b.*\b(anonymous|blind)\b", "Triple anonymous peer review"),
        (r"\bopen peer commentary\b|\bopen\b.*\bpeer\b.*\breview\b", "Open peer review"),
        (r"\bpost publication\b.*\bpeer\b.*\breview\b", "Post-publication peer review"),
        (r"\bcrowd\b.*\breview\b", "Crowd review"),
        (r"\bcommittee\b.*\breview\b", "Committee review"),
        (r"\b(editorial review|collaborative editorial)\b", "Editorial review"),
        (r"\b(single|anonymous|blind)\b.*\bpeer\b.*\breview\b|\banonymous peer review\b", "Anonymous peer review"),
        (r"\bpeer\b.*\breview\b", "Peer review"),
    ]

    for pattern, canonical in aliases:
        if re.search(pattern, normalized):
            return canonical

    return smart_title(cleaned)


def canonicalize_peer_review_types(values: Sequence[str]) -> List[str]:
    seen = set()
    canonical: List[str] = []
    for value in values:
        term = canonicalize_peer_review_term(value)
        if term and term not in seen:
            seen.add(term)
            canonical.append(term)
    return canonical


def canonicalize_deposit_policy_term(value: str) -> str:
    cleaned = re.sub(r"\s+", " ", value.strip()).strip(" .;,:-")
    if not cleaned:
        return ""

    normalized = normalize_for_match(cleaned)

    aliases = [
        (r"\bopen policy finder\b|\bsherpa\s*romeo\b", "Open Policy Finder"),
        (r"\bdiadorim\b", "Diadorim"),
        (r"\bdulcinea\b", "Dulcinea"),
        (r"\bmir\s*bel\b|\bmirabel\b", "Mir@bel"),
        (r"\bmalena\b", "Malena"),
        (r"\baura\b", "AURA"),
        (r"\bdergi\s*park\b", "DergiPark"),
        (r"\bgaruda\b|\bgarba rujukan digital\b", "Garuda"),
        (
            r"\b(publisher|publishers|pulisher|pulishers)\b.*\b(site|website)\b|"
            r"\b(publisher|publishers|pulisher|pulishers)\b.*\bown\b.*\b(site|website)\b",
            "Publisher's own site",
        ),
        (r"\bjournal\b.*\bown\b.*\b(site|website)\b|\bjournal own website\b", "Journal's own site"),
        (r"\bjournal\b.*\b(site|website)\b", "Journal website"),
        (r"\bpreprint\b.*\bpostprint\b.*\bpolicy\b", "Preprint and postprint policy"),
        (r"\bpre[- ]?print\b.*\bpost[- ]?print\b.*\bdeposition\b.*\bpolicy\b", "Preprint and postprint policy"),
        (r"\bself\b.*\barchiving\b", "Self-archiving policy"),
        (r"\brepository\b.*\bpolicy\b", "Repository policy"),
        (r"\bin[- ]?house\b.*\brepository\b", "In-house repository"),
        (r"\bcopyright\b", "Copyright notice"),
        (r"\bauthors?\b.*\brights?\b", "Authors' rights"),
        (r"\bauthors?\b.*\bpersonal\b.*\binstitutional\b.*\brepositor", "Authors' personal and institutional repositories"),
        (r"\binstruction(s)?\s+to\s+authors\b|\binstructions?\s+for\s+authors\b", "Instructions for authors"),
        (r"\bopen access statement\b|\bopen access policy\b", "Open access policy"),
        (r"\binstitutional\b.*\brepository\b", "Institutional repository"),
        (r"\bbrill\b", "Brill.com"),
        (r"\bour own site\b", "Publisher's own site"),
        (r"\bpublic and\s+or commercial subject based repositories\b", "Public and/or commercial subject-based repositories"),
        (r"\bkarger permits authors of open access articles\b", "Karger policy statement"),
        (r"\bvcgate\b", "VCgate"),
        (r"\bvjol\b", "VJOL"),
        (r"\bscpj\b", "SCPJ"),
        (r"\bojs\s*/?\s*pkp\b", "OJS/PKP"),
        (r"\blockss\b", "LOCKSS"),
        (r"\bcross\s*ref\b|\bcrossref\b", "CrossRef"),
    ]

    for pattern, canonical in aliases:
        if re.search(pattern, normalized):
            return canonical

    if re.search(r"https?://|www\.", cleaned, flags=re.I):
        url_aliases = [
            (r"\bdergi\s*park\b", "DergiPark"),
            (r"\bsherpa\b|\bromeo\b|\bopen policy finder\b", "Open Policy Finder"),
            (r"\bcreative\s*commons\b", "Creative Commons"),
            (r"\barxiv\b", "arXiv"),
            (r"\bzenodo\b", "Zenodo"),
            (r"\bfairsharing\b", "FAIRsharing"),
        ]
        for pattern, canonical in url_aliases:
            if re.search(pattern, normalized):
                return canonical
        return "Journal website"

    if re.search(r"\bpublisher\b", normalized) and re.search(r"\b(site|website)\b", normalized):
        return "Publisher's own site"
    if re.search(r"\bjournal\b", normalized) and re.search(r"\b(site|website)\b", normalized):
        return "Journal website"

    return smart_title(cleaned)


def canonicalize_deposit_policy_directories(values: Sequence[str]) -> List[str]:
    seen = set()
    canonical: List[str] = []
    for value in values:
        term = canonicalize_deposit_policy_term(value)
        if term and term not in seen:
            seen.add(term)
            canonical.append(term)
    return canonical


def parse_bool(value: Optional[str]) -> Optional[bool]:
    if value is None:
        return None
    cleaned = value.strip().lower()
    if not cleaned:
        return None
    if cleaned in {"yes", "y", "true", "1"}:
        return True
    if cleaned in {"no", "n", "false", "0"}:
        return False
    return None


def parse_float(value: Optional[str]) -> Optional[float]:
    if value is None:
        return None
    cleaned = value.strip()
    if not cleaned:
        return None
    cleaned = cleaned.replace(",", "")
    match = re.search(r"-?\d+(\.\d+)?", cleaned)
    if not match:
        return None
    try:
        return float(match.group(0))
    except ValueError:
        return None


def parse_apc_amount_number(segment: str) -> Optional[float]:
    # Remove spacing inside numbers so values like "7 500 USD" parse correctly.
    compact = re.sub(r"(?<=\d)\s+(?=\d)", "", segment)
    return parse_float(compact)


def parse_apc_amount_entries(value: Optional[str]) -> List[Dict[str, Any]]:
    if not value:
        return []

    entries: List[Dict[str, Any]] = []
    for raw_part in re.split(r"[;\n|]+", value):
        part = raw_part.strip()
        if not part:
            continue

        amount = parse_apc_amount_number(part)
        currency_match = re.search(r"\b([A-Z]{3})\b", part.upper())
        currency = currency_match.group(1) if currency_match else None
        if amount is None or not currency:
            continue

        entries.append(
            {
                "amount": amount,
                "currency": currency,
                "raw": part,
            }
        )

    return entries


def parse_int(value: Optional[str]) -> Optional[int]:
    if value is None:
        return None
    cleaned = value.strip()
    if not cleaned:
        return None
    cleaned = cleaned.replace(",", "")
    match = re.search(r"-?\d+", cleaned)
    if not match:
        return None
    try:
        return int(match.group(0))
    except ValueError:
        return None


def parse_date(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    text = value.strip()
    if not text:
        return None

    iso_candidate = text.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(iso_candidate)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat()
    except ValueError:
        pass

    for fmt in ("%Y-%m-%d", "%Y/%m/%d", "%d/%m/%Y", "%m/%d/%Y", "%d-%m-%Y", "%d.%m.%Y"):
        try:
            dt = datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)
            return dt.isoformat()
        except ValueError:
            continue

    year_match = re.search(r"\b(19|20)\d{2}\b", text)
    if year_match:
        year = int(year_match.group(0))
        return datetime(year, 1, 1, tzinfo=timezone.utc).isoformat()
    return None


def parse_license_flags(license_values: Sequence[str]) -> Dict[str, Optional[bool]]:
    if not license_values:
        return {"BY": None, "NC": None, "ND": None, "SA": None}
    normalized = " ".join(license_values).upper().replace("/", " ").replace("-", " ")
    has_by = " BY " in f" {normalized} "
    has_nc = " NC " in f" {normalized} "
    has_nd = " ND " in f" {normalized} "
    has_sa = " SA " in f" {normalized} "
    return {"BY": has_by, "NC": has_nc, "ND": has_nd, "SA": has_sa}


def header_lookup(headers: Sequence[str]) -> Dict[str, str]:
    return {normalize_header(h): h for h in headers if h}


def find_header(lookup: Dict[str, str], candidates: Sequence[str]) -> Optional[str]:
    normalized_candidates = [normalize_header(c) for c in candidates]

    for candidate in normalized_candidates:
        if candidate in lookup:
            return lookup[candidate]

    for candidate in normalized_candidates:
        for key, raw in lookup.items():
            if candidate and candidate in key:
                return raw
    return None


def get_value(row: Dict[str, str], lookup: Dict[str, str], candidates: Sequence[str]) -> Optional[str]:
    header = find_header(lookup, candidates)
    if not header:
        return None
    value = row.get(header)
    if value is None:
        return None
    value = value.strip()
    return value if value else None


def normalize_row(row: Dict[str, str], lookup: Dict[str, str], index: int) -> Dict[str, Any]:
    title = get_value(row, lookup, ["title", "journaltitle", "journal title"])
    doaj_url = get_value(row, lookup, ["urlindoaj", "url in doaj"]) or get_value(row, lookup, ["journalurl", "journal url"])
    publisher = get_value(row, lookup, ["publisher", "publishername"])
    country = get_value(row, lookup, ["country", "countryofpublisher", "journalcountry"])
    license_type = split_multi(get_value(row, lookup, ["license", "journallicense", "licensetype", "license terms"]))
    license_url = get_value(row, lookup, ["licenseurl", "licensetermsurl"])

    apc_raw = get_value(row, lookup, ["apc", "articleprocessingcharges", "journalapc"])
    apc_amount_raw = get_value(row, lookup, ["apcamount", "apcmax", "maximumapc", "maxapc"])
    apc_amounts = parse_apc_amount_entries(apc_amount_raw)
    apc_price = None
    apc_currency = None
    if apc_amounts:
        max_entry = max(apc_amounts, key=lambda item: item.get("amount", 0) or 0)
        apc_price = max_entry.get("amount")
        apc_currency = max_entry.get("currency")
    else:
        apc_price = parse_float(apc_amount_raw)
        apc_currency = get_value(row, lookup, ["apccurrency", "currency"])
    apc_has = parse_bool(apc_raw)

    author_retains = parse_bool(
        get_value(
            row,
            lookup,
            [
                "authorholdscopyrightwithoutrestrictions",
                "authorretaincopyright",
                "authorcopyrightholder",
                "copyrightholder",
            ],
        )
    )

    preservation_services = canonicalize_preservation_services(
        split_multi(
            # Use only the "Preservation Services" CSV column (not national library).
            get_value(row, lookup, ["preservationservices"])
        )
    )
    pid_schemes = canonicalize_pid_schemes(
        split_multi(
            get_value(
                row,
                lookup,
                [
                    "persistentarticleidentifiers",
                    "pidscheme",
                    "persistentidentifiers",
                ],
            )
        )
    )
    subjects = split_multi(
        get_value(
            row,
            lookup,
            [
                "subject",
                "subjects",
                "lccsubjectcategory",
                "lcccodes",
            ],
        )
    )
    languages = split_multi(get_value(row, lookup, ["language", "journallanguage"]))
    peer_review_type = canonicalize_peer_review_types(split_multi(get_value(row, lookup, ["reviewprocess"])))
    deposit_policy_directory = canonicalize_deposit_policy_directories(
        split_multi(get_value(row, lookup, ["depositpolicydirectory"]))
    )
    keywords = split_multi(get_value(row, lookup, ["keywords", "keyword"]))

    created_date = parse_date(get_value(row, lookup, ["addedondate", "addeddate", "createddate", "dateadded"]))
    last_updated = parse_date(
        get_value(
            row,
            lookup,
            ["lastupdated", "updatedon", "mostrecentupdate", "dateupdated"],
        )
    )

    issn_print = get_value(row, lookup, ["printissn", "pissn", "issnprint"])
    issn_online = get_value(row, lookup, ["onlineissn", "eissn", "issnonline"])
    fallback_id = get_value(row, lookup, ["id", "journalid", "doajid", "identifier"])
    record_id = fallback_id or issn_online or issn_print or f"row-{index}"
    article_records = parse_int(get_value(row, lookup, ["numberofarticlerecords", "articlecount", "numberofarticles"]))

    license_flags = parse_license_flags(license_type)

    return {
        "id": record_id,
        "title": title,
        "doaj_url": doaj_url,
        "publisher": publisher,
        "country": country,
        "pissn": issn_print,
        "eissn": issn_online,
        "apc_has": apc_has,
        "apc_amount_raw": apc_amount_raw,
        "apc_amounts": apc_amounts,
        "apc_max_price": apc_price,
        "apc_max_currency": apc_currency,
        "waiver_has": parse_bool(get_value(row, lookup, ["waiver", "waiverpolicy", "waiveravailable"])),
        "license_type": license_type,
        "license_url": license_url,
        "license_BY": license_flags["BY"],
        "license_NC": license_flags["NC"],
        "license_ND": license_flags["ND"],
        "license_SA": license_flags["SA"],
        "author_retains": author_retains,
        "preservation_has": bool(preservation_services),
        "preservation_service": preservation_services,
        "pid_has": bool(pid_schemes),
        "pid_scheme": pid_schemes,
        "subject_terms": subjects,
        "language": languages,
        "peer_review_type": peer_review_type,
        "deposit_policy_directory": deposit_policy_directory,
        "keywords": keywords,
        "article_records": article_records,
        "oa_start": get_value(row, lookup, ["oastart", "openaccessstart"]),
        "created_date": created_date,
        "last_updated": last_updated,
        "last_manual_update": None,
        "in_doaj": True,
    }


def aggregate(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    country = Counter(r.get("country") for r in records if r.get("country"))
    license_type = Counter()
    for record in records:
        values = record.get("license_type")
        if isinstance(values, list):
            for val in values:
                if val:
                    license_type[val] += 1
        elif values:
            license_type[str(values)] += 1
    apc = Counter("yes" if r.get("apc_has") else "no" for r in records if r.get("apc_has") is not None)
    waiver = Counter("yes" if r.get("waiver_has") else "no" for r in records if r.get("waiver_has") is not None)
    preservation = Counter("yes" if r.get("preservation_has") else "no" for r in records if r.get("preservation_has") is not None)
    pid = Counter("yes" if r.get("pid_has") else "no" for r in records if r.get("pid_has") is not None)
    author_retains = Counter("yes" if r.get("author_retains") else "no" for r in records if r.get("author_retains") is not None)

    subjects = Counter()
    for record in records:
        for term in record.get("subject_terms", []) or []:
            subjects[term] += 1

    created_year = Counter()
    for record in records:
        created = record.get("created_date")
        if not created:
            continue
        try:
            year = datetime.fromisoformat(created.replace("Z", "+00:00")).year
        except ValueError:
            continue
        created_year[year] += 1

    last_updated_max = None
    for record in records:
        updated = record.get("last_updated")
        if not updated:
            continue
        try:
            parsed = datetime.fromisoformat(updated.replace("Z", "+00:00"))
        except ValueError:
            continue
        if last_updated_max is None or parsed > last_updated_max:
            last_updated_max = parsed

    return {
        "total_journals": len(records),
        "by_country": dict(country),
        "by_license_type": dict(license_type),
        "apc": dict(apc),
        "waiver": dict(waiver),
        "preservation": dict(preservation),
        "pid": dict(pid),
        "author_retains": dict(author_retains),
        "subjects_top": subjects.most_common(100),
        "created_year": dict(created_year),
        "last_updated_max": last_updated_max.isoformat() if last_updated_max else None,
    }


def load_csv_records(session: requests.Session) -> tuple[List[Dict[str, Any]], List[str], Dict[str, str]]:
    response = session.get(CSV_URL, timeout=120)
    response.raise_for_status()

    text = response.content.decode("utf-8-sig", errors="replace")
    reader = csv.DictReader(io.StringIO(text))
    headers = reader.fieldnames or []
    lookup = header_lookup(headers)

    normalized: List[Dict[str, Any]] = []
    for idx, row in enumerate(reader, start=1):
        normalized.append(normalize_row(row, lookup, idx))

    response_meta = {
        "etag": response.headers.get("ETag"),
        "last_modified": response.headers.get("Last-Modified"),
        "content_length": response.headers.get("Content-Length"),
    }
    return normalized, headers, response_meta


def main() -> int:
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    session = build_session()

    print(f"Downloading CSV from {CSV_URL}", file=sys.stderr)
    records, headers, response_meta = load_csv_records(session)
    print(f"Fetched {len(records)} journal rows from CSV", file=sys.stderr)

    # Query article API to get most recent article update date for each journal
    print("Fetching article metadata...", file=sys.stderr)
    for idx, record in enumerate(records, start=1):
        if idx % 100 == 0:
            print(f"  Processed {idx}/{len(records)} journals", file=sys.stderr)
        
        # Try both eissn and pissn
        issn = record.get("eissn") or record.get("pissn")
        if issn:
            most_recent = get_most_recent_article_date(session, issn)
            record["most_recent_article_date"] = most_recent

    print(f"Finished fetching article metadata", file=sys.stderr)

    aggregates = aggregate(records)
    fetched_at = datetime.now(timezone.utc).isoformat()

    journals_path = os.path.join(OUTPUT_DIR, "journals.json")
    aggregates_path = os.path.join(OUTPUT_DIR, "aggregates.json")
    meta_path = os.path.join(OUTPUT_DIR, "meta.json")

    with open(journals_path, "w", encoding="utf-8") as handle:
        json.dump(records, handle, ensure_ascii=False)

    with open(aggregates_path, "w", encoding="utf-8") as handle:
        json.dump(aggregates, handle, ensure_ascii=False)

    with open(meta_path, "w", encoding="utf-8") as handle:
        json.dump(
            {
                "source_type": "csv",
                "source_url": CSV_URL,
                "source_headers": headers,
                "source_header_count": len(headers),
                "source_total": len(records),
                "fetched_total": len(records),
                "is_capped": False,
                "result_cap": None,
                "fetched_at": fetched_at,
                "source_last_updated_max": aggregates.get("last_updated_max"),
                "source_response": response_meta,
            },
            handle,
            ensure_ascii=False,
        )

    print(f"Wrote {journals_path} ({len(records)} records)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
