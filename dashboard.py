#!/usr/bin/env python3
"""
Identity Sprawl & Privileged Access Abuse Detection Dashboard
Phase 10: Interactive Streamlit Dashboard

Views:
  - Executive Summary
  - Risk Intelligence (heatmaps, distributions)
  - Identity Investigation (search + deep dive)
  - Offboarding Watchlist
  - Cross-Platform Privilege View
  - Behavioral Anomalies
"""

import streamlit as st
import json
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from collections import Counter

# ============================================================
# Globals & Colors
# ============================================================
LEVEL_COLORS = {
    'Critical': '#FF4136',
    'High': '#FF851B',
    'Medium': '#FFDC00',
    'Low': '#2ECC40'
}

# ============================================================
# Page Configuration & Custom CSS
# ============================================================
st.set_page_config(
    page_title="Identity Privilege Risk Platform",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700;800&display=swap');

html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
}



h1 {
    font-weight: 800 !important;
    background: -webkit-linear-gradient(45deg, #FF6B6B, #4ECDC4) !important;
    -webkit-background-clip: text !important;
    -webkit-text-fill-color: transparent !important;
    margin-bottom: 2rem !important;
}

h2, h3 {
    font-weight: 600 !important;
    color: #e0e0e0 !important;
}

/* Metric cards & Container styling */
div[data-testid="stMetric"], .stContainer > div > div {
    background: linear-gradient(135deg, rgba(30, 30, 40, 0.8), rgba(20, 20, 30, 0.6));
    backdrop-filter: blur(12px);
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-radius: 12px;
    padding: 16px;
    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.15);
    transition: all 0.3s ease;
}

div[data-testid="stMetric"]:hover, .stContainer > div > div:hover {
    transform: translateY(-2px);
    box-shadow: 0 8px 16px rgba(0, 0, 0, 0.25);
    border-color: rgba(255, 255, 255, 0.2);
}

div[data-testid="stMetricValue"] {
    font-size: 2.2rem !important;
    font-weight: 800 !important;
}

/* Dataframes */
.stDataFrame {
    border-radius: 12px;
    overflow: hidden;
    border: 1px solid rgba(255, 255, 255, 0.08);
}

/* Expanders */
div[data-testid="stExpander"] {
    border-radius: 12px;
    border: 1px solid rgba(255, 255, 255, 0.1);
    background: rgba(30, 30, 40, 0.4);
}
div[data-testid="stExpander"]:hover {
    border-color: rgba(255, 255, 255, 0.2);
}

/* Tabs */
.stTabs [data-baseweb="tab-list"] {
    gap: 1.5rem;
    padding-bottom: 0.5rem;
}

.stTabs [data-baseweb="tab"] {
    height: 45px;
    white-space: pre-wrap;
    background-color: transparent;
    border-radius: 4px;
    gap: 1px;
    padding: 8px 16px;
    font-weight: 600;
    transition: all 0.2s ease;
}

.stTabs [data-baseweb="tab"]:hover {
    background: rgba(255, 255, 255, 0.05);
}

/* Sidebar */
.css-1d391kg {
    background: rgba(20, 20, 30, 0.95) !important;
}

/* Info boxes */
.stAlert, div[data-testid="stAlert"] {
    border-radius: 12px !important;
}
</style>
""", unsafe_allow_html=True)

# ============================================================
# Data Loading
# ============================================================
@st.cache_data
def load_data():
    try:
        with open('output_files/identity_360_enriched.json', 'r') as f:
            data = json.load(f)
        return data
    except Exception as e:
        st.error(f"Error loading data: {e}. Please run the pipeline first.")
        return {}

data = load_data()
if not data:
    st.error("Enriched data not found. Run phase2_identity_correlation.py, then pipeline.py, in that order, before launching the dashboard.")
    st.stop()

# Validation check for enriched data
has_risk = any('risk' in info for info in data.values())
if not has_risk:
    st.error("Enriched data not found. Run phase2_identity_correlation.py, then pipeline.py, in that order, before launching the dashboard.")
    st.stop()

# Build main DataFrame
rows = []
for uid, info in data.items():
    ident = info.get('identity', {})
    risk = info.get('risk', {})
    behavioral = info.get('behavioral', {})
    
    rows.append({
        'Identity ID': uid,
        'Name': ident.get('full_name', 'Unknown'),
        'Department': ident.get('department', 'Unknown'),
        'Employment Type': ident.get('employment_type', 'Unknown'),
        'Status': ident.get('employment_status', 'Active'),
        'Risk Score': risk.get('score', 0),
        'Level': risk.get('level', 'Low'),
        'Flags': risk.get('flags_count', 0),
        'Platform Count': len(info.get('accounts', {})),
        'Last Login Days': behavioral.get('last_login_days', 999),
        'explanations': info.get('explainability', []),
        'remediations': info.get('remediations', []),
        'accounts': info.get('accounts', {})
    })

df = pd.DataFrame(rows)

# ============================================================
# Reusable Components
# ============================================================
def render_top_identities(display_df, title="Top 10 Riskiest Identities", empty_msg="No risky identities found."):
    st.markdown(f"### {title}")
    if display_df.empty:
        st.info(empty_msg)
        return
        
    for idx, (_, row) in enumerate(display_df.head(10).iterrows(), 1):
        with st.container(border=True):
            col1, col2, col3, col4 = st.columns([1, 4, 3, 2])
            with col1:
                st.markdown(f"**#{idx}**")
            with col2:
                st.markdown(f"**{row['Name']}** ({row['Identity ID']})")
                st.caption(f"{row['Department']} | {row['Employment Type']}")
            with col3:
                color = LEVEL_COLORS.get(row['Level'], '#888')
                st.markdown(f"<div style='background-color: {color}20; border: 1px solid {color}; color: {color}; padding: 6px 12px; border-radius: 20px; display: inline-block; font-weight: bold;'>Risk Score: {row['Risk Score']:.0f} ({row['Level']})</div>", unsafe_allow_html=True)
            with col4:
                st.markdown(f"**Flags:** {row['Flags']}")

# ============================================================
# Sidebar Navigation & Filters
# ============================================================
st.title("Identity Privilege Risk Platform")
st.markdown("*Cross-platform identity governance for hybrid enterprises*")

tabs = st.tabs([
    "Executive Summary", 
    "Risk Intelligence", 
    "Identity Investigation", 
    "Offboarding Watchlist", 
    "Cross-Platform Privilege", 
    "Behavioral Anomalies"
])

st.sidebar.markdown("### Global Filters")
selected_dept = st.sidebar.multiselect(
    "Department",
    options=sorted(df['Department'].unique()),
    default=[]
)
st.sidebar.markdown("#### Risk Level")
selected_level = []
if st.sidebar.checkbox("Critical", value=False): selected_level.append("Critical")
if st.sidebar.checkbox("High", value=False): selected_level.append("High")
if st.sidebar.checkbox("Medium", value=False): selected_level.append("Medium")
if st.sidebar.checkbox("Low", value=False): selected_level.append("Low")
selected_type = st.sidebar.multiselect(
    "Employment Type",
    options=sorted(df['Employment Type'].unique()),
    default=[]
)

# Apply filters
filtered_df = df.copy()
if selected_dept:
    filtered_df = filtered_df[filtered_df['Department'].isin(selected_dept)]
if selected_level:
    filtered_df = filtered_df[filtered_df['Level'].isin(selected_level)]
if selected_type:
    filtered_df = filtered_df[filtered_df['Employment Type'].isin(selected_type)]

# ============================================================
# PAGE: Executive Summary
# ============================================================
with tabs[0]:
    if filtered_df.empty:
        st.warning("No identities match the selected filters.")
        with st.spinner("Awaiting matching data..."):
            st.empty()
    else:
        # --- Risk Distribution Charts (Moved to top) ---
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("### Risk Distribution by Level")
            level_counts = filtered_df['Level'].value_counts().reindex(['Critical', 'High', 'Medium', 'Low'], fill_value=0)
            colors = [LEVEL_COLORS['Critical'], LEVEL_COLORS['High'], LEVEL_COLORS['Medium'], LEVEL_COLORS['Low']]
            fig = go.Figure(data=[go.Pie(
                labels=level_counts.index,
                values=level_counts.values,
                hole=0.5,
                marker_colors=colors,
                textinfo='label+percent'
            )])
            fig.update_layout(
                showlegend=True,
                margin=dict(l=0, r=0, t=10, b=0),
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                height=300
            )
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            st.markdown("### Risk by Employment Type")
            type_risk = filtered_df.groupby('Employment Type')['Risk Score'].mean().sort_values(ascending=True)
            fig = go.Figure(data=[go.Bar(
                x=type_risk.values,
                y=type_risk.index,
                orientation='h',
                marker_color='#4ECDC4'
            )])
            fig.update_layout(
                xaxis_title='Average Risk Score',
                margin=dict(l=0, r=0, t=10, b=0),
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                height=300
            )
            st.plotly_chart(fig, use_container_width=True)
            
        st.markdown("---")
        
        # --- Metric Cards ---
        total_id = len(filtered_df)
        critical = len(filtered_df[filtered_df['Level'] == 'Critical'])
        high = len(filtered_df[filtered_df['Level'] == 'High'])
        medium = len(filtered_df[filtered_df['Level'] == 'Medium'])
        dormant = sum(1 for _, row in filtered_df.iterrows() if any('Dormant Admin' in str(e) for e in row['explanations']))
        offboard = sum(1 for _, row in filtered_df.iterrows() if any('Offboarding Gap' in str(e) for e in row['explanations']))
        cross_admin = sum(1 for _, row in filtered_df.iterrows() if any('Cross-Platform Admin' in str(e) for e in row['explanations']))
        old_creds = sum(1 for _, row in filtered_df.iterrows() if any('Old Credentials' in str(e) for e in row['explanations']))
        
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total Identities", f"{total_id:,}")
        c2.metric("Critical Risk", critical, delta="Requires Action" if critical > 0 else None, delta_color="inverse")
        c3.metric("High Risk", high)
        c4.metric("Medium Risk", medium)
        
        c5, c6, c7, c8 = st.columns(4)
        c5.metric("Dormant Admins", dormant)
        c6.metric("Offboarding Gaps", offboard)
        c7.metric("Cross-Platform Admins", cross_admin)
        c8.metric("Old Credentials", old_creds)
        
        st.markdown("---")
        
        # --- Top Risky Identities Component ---
        top_10 = filtered_df.sort_values(by='Risk Score', ascending=False)
        render_top_identities(top_10, title="Top 10 Riskiest Identities", empty_msg="No risky identities found in current filter.")
    


# ============================================================
# PAGE: Risk Intelligence
# ============================================================
with tabs[1]:
    if filtered_df.empty:
        st.warning("No identities match the selected filters.")
        with st.spinner("Awaiting matching data..."):
            st.empty()
    else:
        tab1, tab2, tab3 = st.tabs(["Department Heatmap", "Platform Coverage", "Risk Factor Analysis"])
        
        with tab1:
            st.markdown("### Departmental Risk Heatmap")
            heatmap_data = pd.crosstab(filtered_df['Department'], filtered_df['Level'])
            cols_order = ['Critical', 'High', 'Medium', 'Low']
            cols_present = [c for c in cols_order if c in heatmap_data.columns]
            heatmap_data = heatmap_data[cols_present] if cols_present else heatmap_data
            
            fig = px.imshow(
                heatmap_data.values,
                x=heatmap_data.columns,
                y=heatmap_data.index,
                color_continuous_scale='Inferno',
                aspect='auto',
                text_auto=True
            )
            fig.update_layout(
                title="Identity Count by Department and Risk Level",
                margin=dict(l=0, r=0, t=50, b=0),
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                height=400
            )
            st.plotly_chart(fig, use_container_width=True)
        
        with tab2:
            st.markdown("### Platform Coverage & Admin Distribution")
            
            # Build platform data from filtered_df
            platform_data = []
            for uid in filtered_df['Identity ID']:
                if uid in data:
                    info = data[uid]
                    ident = info['identity']
                    for plat, acct in info.get('accounts', {}).items():
                        platform_data.append({
                            'identity_id': uid,
                            'platform': plat.upper(),
                            'department': ident.get('department', 'Unknown'),
                            'employment_type': ident.get('employment_type', 'Unknown'),
                            'privilege_level': acct.get('privilege_level', 'Unknown'),
                            'effective_privilege': int(acct.get('effective_privilege', 1) or 1),
                            'account_status': acct.get('account_status', 'Unknown'),
                            'last_login_days': int(acct.get('last_login_days', 999) or 999)
                        })
            
            if platform_data:
                plat_df = pd.DataFrame(platform_data)
                
                col1, col2 = st.columns(2)
                
                with col1:
                    # Platform distribution
                    plat_counts = plat_df['platform'].value_counts()
                    fig = px.bar(
                        x=plat_counts.index,
                        y=plat_counts.values,
                        color=plat_counts.values,
                        color_continuous_scale='Viridis',
                        labels={'x': 'Platform', 'y': 'Account Count'}
                    )
                    fig.update_layout(
                        margin=dict(l=0, r=0, t=10, b=0),
                        paper_bgcolor='rgba(0,0,0,0)',
                        plot_bgcolor='rgba(0,0,0,0)',
                        height=350
                    )
                    st.plotly_chart(fig, use_container_width=True)
                
                with col2:
                    # Effective privilege distribution
                    priv_counts = plat_df['effective_privilege'].value_counts().sort_index()
                    fig = px.bar(
                        x=priv_counts.index,
                        y=priv_counts.values,
                        color=priv_counts.values,
                        color_continuous_scale='Reds',
                        labels={'x': 'Effective Privilege Level', 'y': 'Count'}
                    )
                    fig.update_layout(
                        margin=dict(l=0, r=0, t=10, b=0),
                        paper_bgcolor='rgba(0,0,0,0)',
                        plot_bgcolor='rgba(0,0,0,0)',
                        height=350
                    )
                    st.plotly_chart(fig, use_container_width=True)
                
                # Platform privilege heatmap
                st.markdown("### Average Effective Privilege by Department and Platform")
                pivot = plat_df.pivot_table(values='effective_privilege', index='department', columns='platform', aggfunc='mean')
                fig = px.imshow(
                    pivot.values,
                    x=pivot.columns,
                    y=pivot.index,
                    color_continuous_scale='RdYlGn_r',
                    aspect='auto',
                    text_auto='.1f'
                )
                fig.update_layout(
                    margin=dict(l=0, r=0, t=10, b=0),
                    paper_bgcolor='rgba(0,0,0,0)',
                    plot_bgcolor='rgba(0,0,0,0)',
                    height=350
                )
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No platform data available for current selection.")
        
        with tab3:
            st.markdown("### Risk Factor Analysis")
            
            # Rule distribution
            all_flags = []
            for uid in filtered_df['Identity ID']:
                if uid in data:
                    info = data[uid]
                    for exp in info.get('explainability', []):
                        if ':' in str(exp):
                            rule_name = str(exp).split(':')[0]
                            all_flags.append(rule_name)
            
            if all_flags:
                rule_counts = Counter(all_flags)
                top_rules = dict(rule_counts.most_common(15))
                
                fig = px.bar(
                    x=list(top_rules.values()),
                    y=list(top_rules.keys()),
                    orientation='h',
                    color=list(top_rules.values()),
                    color_continuous_scale='Inferno',
                    labels={'x': 'Count', 'y': 'Risk Factor'}
                )
                fig.update_layout(
                    margin=dict(l=0, r=0, t=10, b=0),
                    paper_bgcolor='rgba(0,0,0,0)',
                    plot_bgcolor='rgba(0,0,0,0)',
                    height=450
                )
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No risk factors found in current selection.")
        
        st.markdown("---")
        top_10 = filtered_df.sort_values(by='Risk Score', ascending=False)
        render_top_identities(top_10, title="Top Riskiest Identities in Selection")

# ============================================================
# PAGE: Identity Investigation
# ============================================================
with tabs[2]:
    st.markdown("### Identity Investigation")
    
    search = st.text_input(
        "Search by Identity ID, Name, or Department",
        placeholder="e.g. EMP0045, Christopher Brown, or IT..."
    )
    
    if search:
        matches = filtered_df[
            filtered_df['Identity ID'].str.contains(search, case=False) |
            filtered_df['Name'].str.contains(search, case=False) |
            filtered_df['Department'].str.contains(search, case=False)
        ]
        
        if matches.empty:
            st.warning("No matches found.")
        else:
            # Show search results
            if len(matches) > 1:
                st.markdown(f"#### {len(matches)} matches found")
                st.dataframe(
                    matches[['Identity ID', 'Name', 'Department', 'Employment Type', 'Risk Score', 'Level', 'Flags']].sort_values('Risk Score', ascending=False),
                    use_container_width=True,
                    hide_index=True
                )
            
            # Deep dive for the top match (or single match)
            uid = matches.iloc[0]['Identity ID']
            p_data = data[uid]
            level = p_data['risk']['level']
            score = p_data['risk']['score']
            
            # Color based on level
            color = LEVEL_COLORS.get(level, '#888')
            
            st.markdown("---")
            st.markdown(f"### Identity Profile: {matches.iloc[0]['Name']}")
            
            # Header row
            c1, c2, c3, c4 = st.columns([1, 1, 1, 2])
            c1.metric("ID", uid)
            c2.metric("Department", matches.iloc[0]['Department'])
            c3.metric("Type", matches.iloc[0]['Employment Type'])
            with c4:
                st.markdown("##### Risk Score")
                st.markdown(f"<div style='background-color: {color}20; border: 2px solid {color}; color: {color}; padding: 10px 20px; border-radius: 20px; display: inline-block; font-weight: bold; font-size: 1.5rem;'>{score:.1f} ({level})</div>", unsafe_allow_html=True)
            
            st.markdown("---")
            
            # Two-column layout
            col_left, col_right = st.columns(2)
            
            with col_left:
                with st.expander("Risk Explanations", expanded=True):
                    exps = p_data.get('explainability', [])
                    if exps:
                        for exp in exps:
                            st.markdown(f"- {exp}")
                    else:
                        st.info("No risk explanations.")
                
                st.markdown("#### Behavioral Profile")
                beh = p_data.get('behavioral', {})
                beh_df = pd.DataFrame([
                    ['Days Since Login', beh.get('last_login_days', 'N/A')],
                    ['Platforms Active (30d)', beh.get('platforms_active_30d', 'N/A')],
                    ['Admin Actions (30d)', beh.get('admin_actions_30d', 'N/A')],
                    ['Admin Actions (Total)', beh.get('admin_actions_total', 'N/A')],
                    ['Token Usage Count', beh.get('token_usage_count', 'N/A')],
                    ['Unique IPs', beh.get('unique_ip_count', 'N/A')],
                    ['Dominant IP Ratio', beh.get('dominant_ip_ratio', 'N/A')],
                    ['Activity Spike', 'Yes' if beh.get('activity_spike_flag') else 'No'],
                    ['IP Anomaly', 'Yes' if beh.get('anomalous_ip_flag') else 'No'],
                    ['After-Hours %', f"{beh.get('after_hours_activity_ratio', 0):.0%}"],
                    ['Privilege Changes (30d)', beh.get('privilege_changes_30d', 'N/A')],
                ], columns=['Metric', 'Value'])
                st.dataframe(beh_df, use_container_width=True, hide_index=True)
            
            with col_right:
                with st.expander("Remediation Actions", expanded=True):
                    rems = p_data.get('remediations', [])
                    if rems:
                        for rem in rems:
                            st.markdown(f"- {rem}")
                    else:
                        st.success("No remediation required.")
                
                # Access Footprint Table
                st.markdown("#### Cross-Platform Access Footprint")
                accts = []
                for plat, acct in p_data.get('accounts', {}).items():
                    eff_priv = int(acct.get('effective_privilege', 1) or 1)
                    priv_label = {1: 'Low', 2: 'Low+', 3: 'Medium', 4: 'High', 5: 'Critical'}.get(eff_priv, 'Unknown')
                    
                    accts.append({
                        "Platform": plat.upper(),
                        "Status": acct.get('account_status', 'Unknown'),
                        "Last Login": f"{acct.get('last_login_days', 'N/A')} days ago",
                        "Raw Role": acct.get('privilege_level', 'N/A'),
                        "Effective Priv": f"{eff_priv} ({priv_label})",
                        "Inheritance": ', '.join(acct.get('inheritance_path', [])) or 'Direct only',
                        "API Token Age": f"{acct.get('api_token_age_days', 'N/A')} days" if acct.get('api_token_age_days') else 'N/A',
                        "Access Key Age": f"{acct.get('access_key_age_days', 'N/A')} days" if acct.get('access_key_age_days') else 'N/A'
                    })
                
                if accts:
                    st.dataframe(pd.DataFrame(accts), use_container_width=True, hide_index=True)
                else:
                    st.info("No platform accounts found.")
            
            # Risk Score Components
            st.markdown("---")
            st.markdown("#### Risk Score Breakdown")
            components = p_data.get('risk', {}).get('components', {})
            if components:
                comp_df = pd.DataFrame([
                    ['Privilege (40%)', components.get('privilege_score', 0)],
                    ['Dormancy (20%)', components.get('dormancy_score', 0)],
                    ['Platform Spread (20%)', components.get('platform_spread_score', 0)],
                    ['Credential Age (10%)', components.get('credential_score', 0)],
                    ['Offboarding (10%)', components.get('offboarding_score', 0)],
                    ['Behavioral Boost', components.get('behavioral_boost', 0)],
                ], columns=['Component', 'Score'])
                
                fig = px.bar(
                    comp_df,
                    x='Component',
                    y='Score',
                    color='Score',
                    color_continuous_scale='Reds',
                    range_y=[0, 100]
                )
                fig.update_layout(
                    margin=dict(l=0, r=0, t=10, b=0),
                    paper_bgcolor='rgba(0,0,0,0)',
                    plot_bgcolor='rgba(0,0,0,0)',
                    height=300
                )
                st.plotly_chart(fig, use_container_width=True)

# ============================================================
# PAGE: Offboarding Watchlist
# ============================================================
with tabs[3]:
    st.markdown("### Offboarding Watchlist")
    st.markdown("Identities terminated in HR but still holding active platform credentials.")
    
    if filtered_df.empty:
        st.info("No identities match the selected filters.")
    else:
        offboard_df = filtered_df[
            filtered_df['explanations'].apply(lambda x: any('Offboarding Gap' in str(e) for e in x))
        ].sort_values('Risk Score', ascending=False)
        
        if offboard_df.empty:
            st.success("No offboarding gaps detected! Excellent security posture.")
        else:
            st.error(f"Found {len(offboard_df)} identities with offboarding gaps")
            
            for _, row in offboard_df.iterrows():
                with st.container(border=True):
                    col1, col2, col3 = st.columns([2, 2, 3])
                    with col1:
                        st.markdown(f"**{row['Name']}** ({row['Identity ID']})")
                        st.markdown(f"Dept: {row['Department']} | Type: {row['Employment Type']}")
                    with col2:
                        color = LEVEL_COLORS.get(row['Level'], '#888')
                        st.markdown(f"Risk Score: <span style='color:{color};font-weight:bold;'>{row['Risk Score']:.0f} ({row['Level']})</span>", unsafe_allow_html=True)
                        active_plats = []
                        for plat, acct in row['accounts'].items():
                            if acct.get('account_status') == 'Active':
                                active_plats.append(plat.upper())
                        st.markdown(f"Active on: {', '.join(active_plats)}")
                    with col3:
                        rems = [r for r in row['remediations'] if 'OFFBOARDING' in str(r)]
                        for rem in rems[:2]:
                            st.markdown(f"- {rem}")
            
            st.markdown("---")
            st.markdown("### Full Offboarding Gap List")
            display_cols = ['Identity ID', 'Name', 'Department', 'Employment Type', 'Risk Score', 'Level', 'Platform Count']
            st.dataframe(offboard_df[display_cols], use_container_width=True, hide_index=True)

# ============================================================
# PAGE: Cross-Platform Privilege
# ============================================================
with tabs[4]:
    st.markdown("### Cross-Platform Privilege View")
    st.markdown("Identities with admin-level access across multiple platforms — highest blast radius.")
    
    if filtered_df.empty:
        st.info("No identities match the selected filters.")
    else:
        # Find cross-platform admins
        cross_admin_df = filtered_df[
            filtered_df['explanations'].apply(lambda x: any('Cross-Platform Admin' in str(e) for e in x))
        ].sort_values('Risk Score', ascending=False)
        
        if cross_admin_df.empty:
            st.success("No cross-platform admins detected matching current filters.")
        else:
            st.warning(f"Found {len(cross_admin_df)} cross-platform administrators")
            
            # Summary cards
            col1, col2, col3 = st.columns(3)
            col1.metric("Critical Level", len(cross_admin_df[cross_admin_df['Level'] == 'Critical']))
            col2.metric("High Level", len(cross_admin_df[cross_admin_df['Level'] == 'High']))
            col3.metric("Average Risk Score", f"{cross_admin_df['Risk Score'].mean():.0f}")
            
            st.markdown("---")
            
            # Detailed cards
            for _, row in cross_admin_df.iterrows():
                with st.container(border=True):
                    col1, col2 = st.columns([2, 3])
                    with col1:
                        st.markdown(f"**{row['Name']}** ({row['Identity ID']})")
                        st.markdown(f"{row['Department']} | {row['Employment Type']}")
                        color = LEVEL_COLORS.get(row['Level'], '#888')
                        st.markdown(f"Risk: <span style='color:{color};font-weight:bold;'>{row['Risk Score']:.0f} ({row['Level']})</span>", unsafe_allow_html=True)
                    with col2:
                        # Show admin platforms
                        admin_details = []
                        for plat, acct in row['accounts'].items():
                            eff_priv = int(acct.get('effective_privilege', 1) or 1)
                            if eff_priv >= 4:
                                priv = acct.get('privilege_level', 'Unknown')
                                admin_details.append(f"**{plat.upper()}**: {priv} (eff. level {eff_priv})")
                        if admin_details:
                            st.markdown("Admin on: " + " | ".join(admin_details))
                        
                        rems = [r for r in row['remediations'] if 'PRIVILEGE REVIEW' in str(r)]
                        for rem in rems[:1]:
                            st.info(rem)
            
            st.markdown("---")
            st.markdown("### Full Cross-Platform Admin List")
            display_cols = ['Identity ID', 'Name', 'Department', 'Employment Type', 'Risk Score', 'Level', 'Platform Count']
            st.dataframe(cross_admin_df[display_cols], use_container_width=True, hide_index=True)

# ============================================================
# PAGE: Behavioral Anomalies
# ============================================================
with tabs[5]:
    st.markdown("### Behavioral Anomalies")
    st.markdown("Identities exhibiting anomalous access patterns requiring investigation.")
    
    if filtered_df.empty:
        st.info("No identities match the selected filters.")
    else:
        # Find anomalies
        anomaly_df = filtered_df[
            (filtered_df['explanations'].apply(lambda x: any('Behavioral' in str(e) for e in x))) |
            (filtered_df['explanations'].apply(lambda x: any('Dormant' in str(e) for e in x))) |
            (filtered_df['explanations'].apply(lambda x: any('Service Account Abuse' in str(e) for e in x)))
        ].sort_values('Risk Score', ascending=False)
        
        if anomaly_df.empty:
            st.success("No behavioral anomalies detected matching current filters.")
        else:
            # Summary
            col1, col2, col3 = st.columns(3)
            spike_count = sum(1 for _, row in anomaly_df.iterrows() 
                             if any('spike' in str(e).lower() for e in row['explanations']))
            ip_anomaly_count = sum(1 for _, row in anomaly_df.iterrows() 
                                  if any('IP' in str(e) for e in row['explanations']))
            col1.metric("Total Anomalies", len(anomaly_df))
            col2.metric("Activity Spikes", spike_count)
            col3.metric("IP Anomalies", ip_anomaly_count)
            
            st.markdown("---")
            
            # Distribution by type
            fig = px.histogram(
                anomaly_df,
                x='Department',
                color='Level',
                color_discrete_map=LEVEL_COLORS,
                barmode='group',
                labels={'count': 'Anomaly Count'}
            )
            fig.update_layout(
                margin=dict(l=0, r=0, t=10, b=0),
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                height=350
            )
            st.plotly_chart(fig, use_container_width=True)
            
            st.markdown("---")
            st.markdown("### Anomalous Identities")
            display_cols = ['Identity ID', 'Name', 'Department', 'Employment Type', 'Risk Score', 'Level', 'Flags']
            st.dataframe(anomaly_df[display_cols], use_container_width=True, hide_index=True)

# ============================================================
# Footer
# ============================================================
st.markdown("---")
st.markdown(
    "<p style='text-align:center;color:#666;font-size:0.8em'>"
    "Identity Privilege Risk Platform | Built for Hybrid Enterprise Security | "
    "NIST 800-53 AC-2/AC-6 Aligned</p>",
    unsafe_allow_html=True
)
