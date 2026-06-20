import streamlit as st
import json
import pandas as pd
import plotly.express as px

# ---------------------------------------------------------
# Page Config & Custom CSS
# ---------------------------------------------------------
st.set_page_config(page_title="Identity Risk Dashboard", layout="wide", initial_sidebar_state="collapsed")

# Injecting Custom CSS for a premium, modern, glassmorphic dark mode look
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;800&display=swap');

html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
}

/* Hide the Streamlit Deploy button and Main Menu */
#MainMenu {visibility: hidden;}
[data-testid="stHeader"] {visibility: hidden;}
[data-testid="stToolbar"] {visibility: hidden;}
footer {visibility: hidden;}

/* Make headers pop with a gradient */
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

/* Style the metric cards */
div[data-testid="stMetric"] {
    background: rgba(30, 30, 35, 0.6);
    backdrop-filter: blur(12px);
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-radius: 16px;
    padding: 24px;
    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
    transition: all 0.3s ease;
}

div[data-testid="stMetric"]:hover {
    transform: translateY(-4px);
    box-shadow: 0 12px 24px rgba(0, 0, 0, 0.2);
    border: 1px solid rgba(255, 255, 255, 0.2);
}

div[data-testid="stMetricValue"] {
    font-size: 2.5rem !important;
    font-weight: 800 !important;
}

/* Clean up dataframes */
.stDataFrame {
    border-radius: 12px;
    overflow: hidden;
    border: 1px solid rgba(255, 255, 255, 0.08);
}

/* Tabs styling */
.stTabs [data-baseweb="tab-list"] {
    gap: 2rem;
}

.stTabs [data-baseweb="tab"] {
    height: 50px;
    white-space: pre-wrap;
    background-color: transparent;
    border-radius: 4px 4px 0px 0px;
    gap: 1px;
    padding-top: 10px;
    padding-bottom: 10px;
}
</style>
""", unsafe_allow_html=True)

# ---------------------------------------------------------
# Data Loading & Processing
# ---------------------------------------------------------
@st.cache_data
def load_data():
    try:
        with open('output_files/identity_360.json', 'r') as f:
            return json.load(f)
    except Exception as e:
        st.error(f"Error loading data: {e}. Please ensure the pipeline has been run.")
        return {}

data = load_data()
if not data:
    st.stop()

# Build DataFrame
rows = []
for uid, info in data.items():
    ident = info.get('identity', {})
    risk = info.get('risk', {})
    
    rows.append({
        'Identity ID': uid,
        'Name': ident.get('full_name', 'Unknown'),
        'Department': ident.get('department', 'Unknown'),
        'Status': ident.get('employment_status', 'Active'),
        'Risk Score': risk.get('score', 0),
        'Level': risk.get('level', 'Low'),
        'Flags': risk.get('flags_count', 0),
        'explanations': ", ".join(info.get('explainability', [])),
        'remediations': ", ".join(info.get('remediations', []))
    })

df = pd.DataFrame(rows)

# ---------------------------------------------------------
# UI Components
# ---------------------------------------------------------
st.title("Identity Privilege Risk Platform")

# Executive Metrics
total_id = len(df)
critical = len(df[df['Level'] == 'Critical'])
high = len(df[df['Level'] == 'High'])
dormant = df['explanations'].str.contains('Dormant Admin', na=False).sum()
offboard = df['explanations'].str.contains('Offboarding Gap', na=False).sum()

c1, c2, c3, c4, c5 = st.columns(5)
c1.metric("Total Identities", f"{total_id:,}")
c2.metric("Critical Risk", critical, delta="Requires Action", delta_color="inverse")
c3.metric("High Risk", high)
c4.metric("Dormant Admins", dormant)
c5.metric("Offboarding Gaps", offboard)

st.markdown("<br><br>", unsafe_allow_html=True)

# Tabs
t1, t2, t3, t4 = st.tabs([
    "🚨 Top Risky Identities", 
    "🔍 Identity Investigation", 
    "📊 Risk Intelligence", 
    "🚪 Offboarding Watchlist"
])

# Tab 1: Top Risky Identities
with t1:
    st.markdown("### Most Critical Identities")
    st.markdown("Prioritize remediation for these identities immediately. They represent the highest blast radius in the event of compromise.")
    
    top_20 = df.sort_values(by='Risk Score', ascending=False).head(20)
    display_df = top_20[['Identity ID', 'Name', 'Department', 'Risk Score', 'Level', 'Flags']]
    
    st.dataframe(
        display_df,
        use_container_width=True,
        hide_index=True,
        column_config={
            "Risk Score": st.column_config.ProgressColumn(
                "Risk Score", help="Risk magnitude", format="%d", min_value=0, max_value=100
            )
        }
    )

# Tab 2: Identity Investigation
with t2:
    st.markdown("### Deep Dive Investigation")
    search = st.text_input("Search by Name or ID (e.g. Christopher Brown or EMP0045)", placeholder="Start typing...")
    
    if search:
        matches = df[df['Identity ID'].str.contains(search, case=False) | df['Name'].str.contains(search, case=False)]
        
        if not matches.empty:
            uid = matches.iloc[0]['Identity ID']
            p_data = data[uid]
            level = p_data['risk']['level']
            
            # Card Container
            with st.container(border=True):
                st.subheader(f"👤 {matches.iloc[0]['Name']} ({uid})")
                st.markdown(f"**Department:** {matches.iloc[0]['Department']} &nbsp; | &nbsp; **Risk Score:** `{p_data['risk']['score']}` &nbsp; | &nbsp; **Severity:** `{level}`")
                
                st.divider()
                
                c_why, c_how = st.columns(2)
                with c_why:
                    st.markdown("#### 🚩 Why is this risky?")
                    for e in p_data.get('explainability', []):
                        st.markdown(f"- {e}")
                        
                with c_how:
                    st.markdown("#### 🛠️ Recommended Actions")
                    for r in p_data.get('remediations', []):
                        st.markdown(f"- {r}")
                
                st.divider()
                st.markdown("#### 🌐 Access Footprint")
                accts = []
                for plat, acct in p_data.get('accounts', {}).items():
                    accts.append({
                        "Platform": plat.upper(),
                        "Status": acct.get('account_status'),
                        "Last Login": f"{acct.get('last_login_days')} days ago",
                        "Raw Role": acct.get('privilege_level'),
                        "Effective Priv (1-5)": acct.get('effective_privilege')
                    })
                st.dataframe(pd.DataFrame(accts), use_container_width=True, hide_index=True)
        else:
            st.warning("No matches found.")

# Tab 3: Risk Intelligence Heatmap
with t3:
    st.markdown("### Departmental Risk Heatmap")
    heatmap_data = pd.crosstab(df['Department'], df['Level'])
    cols = ['Critical', 'High', 'Medium', 'Low']
    cols_present = [c for c in cols if c in heatmap_data.columns]
    
    fig = px.density_heatmap(
        x=df['Level'],
        y=df['Department'],
        category_orders={"x": cols},
        color_continuous_scale="Inferno",
        template="plotly_dark",
        height=500
    )
    fig.update_layout(margin=dict(l=0, r=0, t=30, b=0), paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)')
    st.plotly_chart(fig, use_container_width=True)

# Tab 4: Offboarding
with t4:
    st.markdown("### High-Risk Offboarding Gaps")
    st.info("The following users have been marked as Terminated in HR, but still hold active platform credentials.")
    offboard_df = df[df['explanations'].str.contains('Offboarding Gap', na=False)]
    
    if offboard_df.empty:
        st.success("No offboarding gaps detected! Excellent posture.")
    else:
        st.dataframe(
            offboard_df[['Identity ID', 'Name', 'Department', 'Risk Score', 'remediations']],
            use_container_width=True,
            hide_index=True
        )
