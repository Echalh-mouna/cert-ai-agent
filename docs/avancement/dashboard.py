"""
dashboard.py

Dashboard de synthèse du pipeline CERT AI Agent (Semaine 7).
Lancer avec : streamlit run dashboard.py

Vue en lecture seule sur la base SQLite existante - ne modifie jamais les
données (aucune action déclenchée depuis le dashboard, uniquement de la
consultation).
"""

import sqlite3
import pandas as pd
import streamlit as st

from database import DB_PATH

st.set_page_config(page_title="CERT AI Agent — Dashboard", layout="wide")


def get_connection():
    return sqlite3.connect(DB_PATH)


@st.cache_data(ttl=30)
def load_overview():
    conn = get_connection()
    total_cve = pd.read_sql("SELECT COUNT(*) as n FROM cve", conn).iloc[0]["n"]
    critical_cve = pd.read_sql(
        "SELECT COUNT(*) as n FROM cve WHERE cvss_score >= 7.0 OR exploit_public = 1", conn
    ).iloc[0]["n"]
    total_remediations = pd.read_sql("SELECT COUNT(*) as n FROM remediation_status", conn).iloc[0]["n"]
    fixed_remediations = pd.read_sql(
        "SELECT COUNT(*) as n FROM remediation_status WHERE status = 'corrige'", conn
    ).iloc[0]["n"]
    conn.close()
    return total_cve, critical_cve, total_remediations, fixed_remediations


@st.cache_data(ttl=30)
def load_agent_decisions():
    conn = get_connection()
    df = pd.read_sql("SELECT decision, COUNT(*) as nombre FROM agent_log GROUP BY decision", conn)
    conn.close()
    return df


@st.cache_data(ttl=30)
def load_sources_breakdown():
    conn = get_connection()
    df = pd.read_sql("""
        SELECT s.name AS source, COUNT(DISTINCT cs.cve_id) AS nb_cve
        FROM cve_sources cs
        JOIN sources s ON cs.source_id = s.source_id
        GROUP BY s.name
        ORDER BY nb_cve DESC
    """, conn)
    conn.close()
    return df


@st.cache_data(ttl=30)
def load_remediation_detail():
    conn = get_connection()
    df = pd.read_sql("""
        SELECT rs.cve_id, e.company, e.vendor, e.product, e.version,
               e.responsible_name, rs.status, rs.notified_at,
               rs.last_reminder_at, rs.fixed_at,
               CAST(julianday('now') - julianday(rs.notified_at) AS INTEGER) AS jours_ecoules
        FROM remediation_status rs
        JOIN equipment e ON rs.equipment_id = e.equipment_id
        ORDER BY rs.status ASC, jours_ecoules DESC
    """, conn)
    conn.close()
    return df


@st.cache_data(ttl=30)
def load_company_summary():
    conn = get_connection()
    df = pd.read_sql("""
        SELECT e.company,
               COUNT(*) AS total_alertes,
               SUM(CASE WHEN rs.status = 'corrige' THEN 1 ELSE 0 END) AS corrigees,
               SUM(CASE WHEN rs.status = 'en_attente' THEN 1 ELSE 0 END) AS en_attente
        FROM remediation_status rs
        JOIN equipment e ON rs.equipment_id = e.equipment_id
        GROUP BY e.company
        ORDER BY total_alertes DESC
    """, conn)
    conn.close()
    return df


# ---------------------------------------------------------------------------
# Interface
# ---------------------------------------------------------------------------

st.title("🛡️ CERT AI Agent — Tableau de bord")
st.caption("Vue de synthèse du pipeline de veille, matching et remédiation")

total_cve, critical_cve, total_rem, fixed_rem = load_overview()

col1, col2, col3, col4 = st.columns(4)
col1.metric("CVE collectées", f"{total_cve:,}")
col2.metric("CVE critiques", f"{critical_cve:,}")
col3.metric("Alertes envoyées", total_rem)
taux = f"{(fixed_rem / total_rem * 100):.0f}%" if total_rem else "N/A"
col4.metric("Taux de correction", taux, delta=f"{fixed_rem}/{total_rem} corrigées")

st.divider()

col_left, col_right = st.columns(2)

with col_left:
    st.subheader("Décisions de l'agent")
    decisions_df = load_agent_decisions()
    if not decisions_df.empty:
        st.bar_chart(decisions_df.set_index("decision"))
    else:
        st.info("Aucune décision enregistrée pour le moment.")

with col_right:
    st.subheader("Sources CTI")
    sources_df = load_sources_breakdown()
    if not sources_df.empty:
        st.bar_chart(sources_df.set_index("source"))
    else:
        st.info("Aucune source enregistrée pour le moment.")

st.divider()

st.subheader("Suivi de remédiation par entreprise")
company_df = load_company_summary()
if not company_df.empty:
    st.dataframe(company_df, use_container_width=True, hide_index=True)
else:
    st.info("Aucune alerte envoyée pour le moment.")

st.divider()

st.subheader("Détail des suivis de remédiation")
remediation_df = load_remediation_detail()
if not remediation_df.empty:
    # Surligne les suivis en attente depuis plus de 7 jours (seuil de relance)
    def highlight_late(row):
        if row["status"] == "en_attente" and row["jours_ecoules"] >= 7:
            return ["background-color: #ffe0e0"] * len(row)
        return [""] * len(row)

    st.dataframe(
        remediation_df.style.apply(highlight_late, axis=1),
        use_container_width=True,
        hide_index=True,
    )
else:
    st.info("Aucun suivi de remédiation pour le moment.")

st.caption("Dashboard en lecture seule — actualisation automatique toutes les 30 secondes (cache).")