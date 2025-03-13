import streamlit as st
import matplotlib.pyplot as plt
import numpy as np
import re
from matplotlib.patches import Circle, Wedge
import math
import secrets
import string

# Set page configuration
st.set_page_config(
    page_title="Password Strength Analyzer",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
def load_css():
    st.markdown("""
    <style>
        .stApp {
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            color: #333333;
        }
        
        .title {
            color: #1a73e8;
            text-align: center;
            font-size: 2.5rem;
            font-weight: 700;
            margin-bottom: 0.5rem;
        }
        
        .subtitle {
            text-align: center;
            color: #666666;
            font-size: 1.2rem;
            margin-bottom: 2rem;
        }
        
        .metric-card {
            background: white;
            padding: 1.5rem;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            margin: 0.5rem;
        }
        
        .strength-meter {
            text-align: center;
            padding: 1rem;
        }
        
        .strength-weak { color: #ff4444; font-weight: 600; }
        .strength-moderate { color: #ffbb33; font-weight: 600; }
        .strength-strong { color: #00C851; font-weight: 600; }
        .strength-excellent { color: #007E33; font-weight: 600; }
        
        .sidebar .sidebar-content {
            background-color: #ffffff;
            border-right: 1px solid #e0e0e0;
        }
        
        .suggestion-box {
            background: #fff3e0;
            padding: 1rem;
            border-radius: 8px;
            border-left: 4px solid #ff9800;
            margin: 0.5rem 0;
        }
    </style>
    """, unsafe_allow_html=True)

# Advanced password analysis
def analyze_password(password):
    score = 0
    entropy = 0
    suggestions = []
    criteria = {
        "length": len(password) >= 12,
        "uppercase": bool(re.search(r'[A-Z]', password)),
        "lowercase": bool(re.search(r'[a-z]', password)),
        "digits": bool(re.search(r'\d', password)),
        "special": bool(re.search(r'[!@#$%^&*(),.?":{}|<>[\]]', password))
    }
    
    # Calculate character pool size for entropy
    char_pool = 0
    if criteria["uppercase"]: char_pool += 26
    if criteria["lowercase"]: char_pool += 26
    if criteria["digits"]: char_pool += 10
    if criteria["special"]: char_pool += 32
    
    # Calculate entropy
    if char_pool > 0:
        entropy = len(password) * math.log2(char_pool)
    
    # Scoring system (0-100)
    score += min(len(password) * 2, 30)  # Length bonus
    if criteria["uppercase"]: score += 15
    if criteria["lowercase"]: score += 15
    if criteria["digits"]: score += 20
    if criteria["special"]: score += 20
    
    # Common password check (simplified)
    common_patterns = ['password', '1234', 'qwerty', 'admin']
    if any(pattern in password.lower() for pattern in common_patterns):
        score = max(10, score - 40)
        suggestions.append("Avoid common passwords or predictable patterns")
    
    # Additional checks
    if len(set(password)) < len(password) / 2:
        suggestions.append("Reduce character repetition")
        score = max(20, score - 20)
    
    # Strength classification
    if score < 40 or entropy < 30:
        strength = ("Weak", "strength-weak")
    elif score < 70 or entropy < 50:
        strength = ("Moderate", "strength-moderate")
    elif score < 90 or entropy < 70:
        strength = ("Strong", "strength-strong")
    else:
        strength = ("Excellent", "strength-excellent")
    
    # Suggestions
    if not criteria["length"]: suggestions.append("Use 12+ characters for better security")
    if not criteria["uppercase"]: suggestions.append("Add uppercase letters (A-Z)")
    if not criteria["lowercase"]: suggestions.append("Add lowercase letters (a-z)")
    if not criteria["digits"]: suggestions.append("Include numbers (0-9)")
    if not criteria["special"]: suggestions.append("Add special characters (!@#$%^&*)")
    
    return score, entropy, criteria, suggestions, strength

# Enhanced circular gauge
def create_gauge(score):
    fig, ax = plt.subplots(figsize=(5, 5))
    
    # Color gradient
    color = plt.cm.RdYlGn(score/100)
    
    # Background
    background = Circle((0, 0), 0.9, color='#f0f0f0')
    ax.add_patch(background)
    
    # Progress wedge - corrected angle calculation
    progress = Wedge((0, 0), 0.9, 0, score * 3.6, width=0.2, color=color)
    ax.add_patch(progress)
    
    # Inner circle
    inner = Circle((0, 0), 0.7, color='white')
    ax.add_patch(inner)
    
    # Text
    ax.text(0, 0, f"{score}", ha='center', va='center', fontsize=28, fontweight='bold')
    ax.text(0, -0.2, "SCORE", ha='center', va='center', fontsize=12, color='#666')
    
    ax.set_xlim(-1, 1)
    ax.set_ylim(-1, 1)
    ax.axis('off')
    return fig

def main():
    load_css()
    
    # Header
    st.markdown('<h1 class="title">Password  Strength Analyzer</h1>', unsafe_allow_html=True)
    st.markdown('<p class="subtitle">Comprehensive password security assessment with entropy analysis</p>', unsafe_allow_html=True)
    
    # Sidebar
    with st.sidebar:
        st.header("Password Generator")
        length = st.slider("Length", 8, 32, 12)
        include_special = st.checkbox("Special Characters", True)
        if st.button("Generate"):
            chars = string.ascii_letters + string.digits + (string.punctuation if include_special else "")
            password = ''.join(secrets.choice(chars) for _ in range(length))
            st.code(password)
    
    # Main content
    col1, col2 = st.columns([1, 2])
    
    with col1:
        password = st.text_input("Enter Password", type="password", key="password_input")
        if password:
            score, entropy, criteria, suggestions, (strength_text, strength_class) = analyze_password(password)
            
            # Gauge
            st.pyplot(create_gauge(score))
            st.markdown(f'<div class="strength-meter">Strength: <span class="{strength_class}">{strength_text}</span></div>', unsafe_allow_html=True)
    
    with col2:
        if password:
            st.markdown('<div class="metric-card">', unsafe_allow_html=True)
            st.subheader("Security Metrics")
            
            # Display metrics
            col_a, col_b = st.columns(2)
            col_a.metric("Entropy (bits)", f"{entropy:.1f}")
            col_a.metric("Length", len(password))
            col_b.metric("Score (0-100)", score)
            col_b.metric("Unique Chars", len(set(password)))
            
            # Criteria
            st.subheader("Criteria Check")
            for key, value in criteria.items():
                st.write(f"{key.capitalize()}: {'✅' if value else '❌'}")
            
            # Suggestions
            if suggestions:
                st.subheader("Security Recommendations")
                for s in suggestions:
                    st.markdown(f'<div class="suggestion-box">{s}</div>', unsafe_allow_html=True)
            
            st.markdown('</div>', unsafe_allow_html=True)

if __name__ == "__main__":
    main()