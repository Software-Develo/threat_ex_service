CREATE TABLE threats (
    md5         TEXT PRIMARY KEY CHECK (md5 ~ '^[a-f0-9]{32}$'),
    name        TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 255),
    type        TEXT NOT NULL CHECK (type IN ('trojan','ransomware','worm','spyware','adware','other')),
    severity    TEXT NOT NULL CHECK (severity IN ('low','medium','high','critical')),
    description TEXT NOT NULL DEFAULT '',
    sha256      TEXT CHECK (sha256 ~ '^[a-f0-9]{64}$'),
    cve         TEXT[] NOT NULL DEFAULT '{}',
    vuln_status TEXT NOT NULL DEFAULT 'unknown' CHECK (vuln_status IN ('unpatched','patch_available','patched','unknown')),
    playbook    TEXT[] NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);