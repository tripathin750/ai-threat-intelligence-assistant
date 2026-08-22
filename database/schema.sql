-- AI-Based Threat Intelligence Assistant — reference PostgreSQL schema
--
-- This file is generated for reference/documentation purposes from the
-- SQLAlchemy models in backend/models.py (the single source of truth).
-- The application creates/updates these tables itself via
-- `Base.metadata.create_all()` (backend/database.py::init_db) on startup —
-- running this file by hand is optional and only useful for provisioning a
-- PostgreSQL database ahead of time or for schema review.

-- Core vulnerability record, normalized and validated from the NVD.
CREATE TABLE vulnerabilities (
	cve_id VARCHAR(30) NOT NULL,
	description TEXT NOT NULL,
	cvss_score FLOAT,
	severity VARCHAR(20),
	cwe_id VARCHAR(20),
	published_date TIMESTAMP WITHOUT TIME ZONE,
	last_modified TIMESTAMP WITHOUT TIME ZONE,
	source VARCHAR(50) NOT NULL,
	PRIMARY KEY (cve_id)
);
CREATE INDEX ix_vulnerabilities_cve_id ON vulnerabilities (cve_id);
CREATE INDEX ix_vulnerabilities_severity ON vulnerabilities (severity);

-- Curated MITRE ATT&CK Enterprise technique catalogue (see backend/data/attack_catalog.py).
CREATE TABLE attack_techniques (
	technique_id VARCHAR(20) NOT NULL,
	name VARCHAR(200) NOT NULL,
	description TEXT NOT NULL,
	tactics JSON NOT NULL,
	external_url VARCHAR(500) NOT NULL,
	PRIMARY KEY (technique_id)
);

-- Tracks the last successful/attempted synchronization per source, enabling
-- incremental NVD ingestion instead of full re-downloads.
CREATE TABLE sync_state (
	source VARCHAR(50) NOT NULL,
	last_successful_sync TIMESTAMP WITH TIME ZONE,
	last_attempted_sync TIMESTAMP WITH TIME ZONE,
	updated_records INTEGER NOT NULL,
	PRIMARY KEY (source)
);

-- Evidence-grounded, advisory analysis for one CVE. Never authoritative —
-- see IntelligenceResponseSchema.disclaimer in backend/schemas.py.
CREATE TABLE intelligence_analyses (
	id SERIAL NOT NULL,
	cve_id VARCHAR(30) NOT NULL,
	summary TEXT NOT NULL,
	impact TEXT NOT NULL,
	affected_component TEXT NOT NULL,
	risk VARCHAR(20) NOT NULL,
	confidence FLOAT NOT NULL,
	evidence JSON NOT NULL,
	model VARCHAR(100) NOT NULL,
	generated_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(cve_id) REFERENCES vulnerabilities (cve_id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX ix_intelligence_analyses_cve_id ON intelligence_analyses (cve_id);

-- Advisory mitigation guidance for one CVE.
CREATE TABLE mitigation_recommendations (
	id SERIAL NOT NULL,
	cve_id VARCHAR(30) NOT NULL,
	immediate_action TEXT NOT NULL,
	short_term TEXT NOT NULL,
	long_term TEXT NOT NULL,
	recommendations JSON NOT NULL,
	source VARCHAR(100) NOT NULL,
	generated_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(cve_id) REFERENCES vulnerabilities (cve_id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX ix_mitigation_recommendations_cve_id ON mitigation_recommendations (cve_id);

-- Explicitly labelled *inferred* CVE → ATT&CK technique mappings (never
-- presented as an official MITRE assertion — see mapping_type).
CREATE TABLE vulnerability_attack_mappings (
	id SERIAL NOT NULL,
	cve_id VARCHAR(30) NOT NULL,
	technique_id VARCHAR(20) NOT NULL,
	mapping_type VARCHAR(30) NOT NULL,
	confidence FLOAT NOT NULL,
	rationale TEXT NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	CONSTRAINT uq_cve_technique UNIQUE (cve_id, technique_id),
	FOREIGN KEY(cve_id) REFERENCES vulnerabilities (cve_id) ON DELETE CASCADE,
	FOREIGN KEY(technique_id) REFERENCES attack_techniques (technique_id)
);
CREATE INDEX ix_vulnerability_attack_mappings_cve_id ON vulnerability_attack_mappings (cve_id);
CREATE INDEX ix_vulnerability_attack_mappings_technique_id ON vulnerability_attack_mappings (technique_id);
