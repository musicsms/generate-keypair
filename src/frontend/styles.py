def get_styles():
    return """
    <style>
        .stButton > button {
            width: 100%;
            background-color: #4CAF50;
            color: white;
            border-radius: 5px;
            padding: 0.5rem;
        }
        .stButton > button:hover {
            background-color: #45a049;
        }
        .main .block-container {
            padding-top: 2rem;
        }
        div[data-testid="stExpander"] div[role="button"] p {
            font-size: 1.1rem;
            font-weight: 600;
        }
    </style>
    """
