import mysql.connector
import streamlit as st
from langchain_core.prompts import ChatPromptTemplate
from langchain_groq import ChatGroq
import os
import requests
import pandas as pd
import logging
import matplotlib.pyplot as plt
import fitz  
from transformers import pipeline
import asyncio
import streamlit as st
from collections import defaultdict
import threading
import time
import nltk
from nltk.tokenize import sent_tokenize
from queue import Queue  # Import the Queue class



# Configuration
DATABASE_CONFIG = {
    'host': "localhost",
    'user': "root",
    'password': "",
    'database': "cve_database"
}
API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="
USER_ROLES = ['general', 'developer', 'teacher', 'cybersecurity_specialist']

# Set environment variables
os.environ["TOKENIZERS_PARALLELISM"] = "false"

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Set Streamlit page configuration
st.set_page_config(page_title="CVE Data Fetcher", page_icon=":shield:", layout="wide")

# Custom CSS for styling
st.markdown("""
    <style>
        body {
            background-color: #f0f0f0;
            color: #333;
        }
        .main-container {
            padding: 20px;
        }
        .title {
            font-size: 2.5em;
            color: #333;
            text-align: center;
            margin-bottom: 20px;
        }
        .subheader {
            font-size: 1.5em;
            margin-top: 20px;
            margin-bottom: 10px;
            color: #666;
        }
        .instructions {
            background-color: #333;
            padding: 15px;
            border-radius: 5px;
            border: 1px solid #ddd;
            margin-bottom: 20px;
            color: white;
        }
        .btn {
            margin-top: 15px;
        }
        .report, .impact-analysis, .future-predictions {
            margin-top: 20px;
        }
        .footer {
            text-align: center;
            margin-top: 30px;
            color: #666;
        }
        .stButton>button {
            background-color: #333;
            color: white;
            border: none;
            padding: 10px 20px;
            text-align: center;
            text-decoration: none;
            display: inline-block;
            font-size: 16px;
            margin: 4px 2px;
            cursor: pointer;
            border-radius: 4px;
        }
        .stButton>button:hover {
            background-color: #555;
        }
    </style>
""", unsafe_allow_html=True)

# Establish connection to MySQL database
@st.cache_resource
def connect_to_database(config):
    try:
        connection = mysql.connector.connect(**config)
        return connection
    except mysql.connector.Error as err:
        st.error(f"Error connecting to MySQL database: {err}")
        logging.error(f"Error connecting to MySQL database: {err}")
        return None

connection = connect_to_database(DATABASE_CONFIG)

# Fetch CVE data from NVD API
@st.cache_data
def fetch_cve_data(cve_id):
    try:
        url = f"{API_URL}{cve_id}"
        response = requests.get(url)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        st.error(f"Error fetching CVE data: {e}")
        logging.error(f"Error fetching CVE data: {e}")
        return None

# Insert CVE data into MySQL database
def insert_cve_data(cve_data, connection):
    if connection is None or not connection.is_connected():
        st.error("No database connection.")
        return
    try:
        cursor = connection.cursor()
        cursor.execute("SELECT * FROM cve_table WHERE cve_id = %s", (cve_data['cve_id'],))
        result = cursor.fetchone()
        if result:
            cursor.execute("DELETE FROM cve_table WHERE cve_id = %s", (cve_data['cve_id'],))
            st.warning("Old entry deleted")
        
        cursor.execute("""
            INSERT INTO cve_table (cve_id, description, cvss_score, cvss_vector, cve_references)
            VALUES (%s, %s, %s, %s, %s)
        """, (cve_data['cve_id'], cve_data['description'], cve_data['cvss_score'],
              cve_data['cvss_vector'], ", ".join(cve_data['references'])))
        connection.commit()
        cursor.close()
        st.success("CVE data inserted successfully")
    except mysql.connector.Error as err:
        st.error(f"Error inserting CVE data into MySQL database: {err}")
        logging.error(f"Error inserting CVE data into MySQL database: {err}")

# Generate security assessment report using Groq API
def generate_security_assessment_report(cve_details, user_role, language='en'):
    if user_role not in USER_ROLES:
        raise ValueError(f"Invalid user role: {user_role}")
    chat = ChatGroq(temperature=0, model_name="llama3-8b-8192")
    if language == 'en':
        prompt = f"You are a cybersecurity expert. Analyze the following CVE details and provide actionable suggestions specific to a {user_role}: {cve_details}. Provide suggestions and mitigation for this CVE. Ensure your suggestions are clear and prioritize critical actions. Provide detailed steps for mitigation and suggest best practices to avoid such vulnerabilities in the future. Additionally, include an analysis of the potential impact and a summary report."
    else:
        prompt = f"Anda adalah ahli keamanan siber. Analisis detail CVE berikut dan berikan saran tindakan yang dapat diambil sesuai dengan peran pengguna {user_role}: {cve_details}. Berikan saran dan mitigasi untuk CVE ini. Pastikan saran Anda jelas dan mengutamakan tindakan yang kritis. Berikan langkah-langkah rinci untuk mitigasi dan sarankan praktik terbaik untuk menghindari kerentanan semacam ini di masa depan. Selain itu, sertakan analisis potensi dampak dan laporan ringkasan. Gunakan Bahasa Indonesia dalam hasilnya."
    
    prompt_template = ChatPromptTemplate.from_messages([("human", prompt)])
    chain = prompt_template | chat
    output = ""
    for chunk in chain.stream({"cve_details": cve_details}):
        output += chunk.content
    return output

# Insert generated report into MySQL database
def insert_report(cve_id, user_role, report, connection):
    if connection is None or not connection.is_connected():
        st.error("No database connection.")
        return
    try:
        cursor = connection.cursor()
        cursor.execute("INSERT INTO reports (cve_id, user_role, report) VALUES (%s, %s, %s)",
                       (cve_id, user_role, report))
        connection.commit()
        cursor.close()
        st.success("Security assessment report saved successfully")
    except mysql.connector.Error as err:
        st.error(f"Error inserting report into MySQL database: {err}")
        logging.error(f"Error inserting report into MySQL database: {err}")

# Generate impact analysis using Groq API
def generate_impact_analysis(cve_details, infrastructure_details):
    chat = ChatGroq(temperature=0, model_name="llama3-8b-8192")
    prompt = f"Analyze the following CVE details and provide an impact analysis based on the given infrastructure: {cve_details}. Infrastructure details: {infrastructure_details}. Include the potential impact on the systems, data, and operations."
    
    prompt_template = ChatPromptTemplate.from_messages([("human", prompt)])
    chain = prompt_template | chat
    output = ""
    for chunk in chain.stream({"cve_details": cve_details, "infrastructure_details": infrastructure_details}):
        output += chunk.content
    return output

# Fetch historical CVE data from the database and sort it by CVSS score
def fetch_historical_cve_data(connection):
    if connection is None or not connection.is_connected():
        st.error("No database connection.")
        return None
    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT cve_id, description, cvss_score, cvss_vector FROM cve_table ORDER BY cvss_score DESC")
        historical_data = cursor.fetchall()
        cursor.close()
        df = pd.DataFrame(historical_data)
        df['cvss_score'] = pd.to_numeric(df['cvss_score'], errors='coerce')
        return df
    except mysql.connector.Error as err:
        st.error(f"Error fetching historical CVE data from MySQL database: {err}")
        logging.error(f"Error fetching historical CVE data from MySQL database: {err}")
        return None
        
# Function to extract and tokenize text from PDF
@st.cache_data
def extract_and_tokenize_text_from_pdf(pdf_path):
    doc = fitz.open(pdf_path)
    text = ""
    for page in doc:
        text += page.get_text("text")
    sentences = sent_tokenize(text)
    return sentences

# Initialize the ChatGroq model
chat = ChatGroq(temperature=0, model_name="llama3-8b-8192")

def answer_question(question, sentences):
    if not sentences:
        return "I don't have that information."

    # Normalize question for better comparison
    question_words = set(word.lower() for word in question.split())

    # Filter sentences that contain any of the significant words from the question
    relevant_sentences = [sentence for sentence in sentences if set(word.lower() for word in sentence.split()) & question_words]

    # If no sentences are found relevant, return a message indicating no information
    if not relevant_sentences:
        return "I don't have that information."

    # Use the most relevant sentence to generate a response
    best_sentence = max(relevant_sentences, key=lambda s: sum(word in s.lower() for word in question.lower().split()))

    prompt = f"Question: {question}\nContext: {best_sentence}\nPlease elaborate on the information provided in a detailed and human-friendly manner."

    # Create a prompt template from the message
    prompt_template = ChatPromptTemplate.from_messages([("human", prompt)])
    
    # Create a chain with the chat model
    chain = prompt_template | chat
    
    # Generate the output using the streaming method
    output = ""
    try:
        for chunk in chain.stream({"question": question, "context": best_sentence}):
            output += chunk.content
        return output.strip() if output else "I don't have that information."
    except Exception as e:
        return f"Error in generating response: {e}"

# Example usage in your interface, assuming integration in a larger application like Streamlit
def chatbot_interface(sentences):
    st.subheader("PDF Knowledge Chatbot")
    user_query = st.text_input("Ask me anything about the document:")
    if st.button("Ask") and user_query:
        answer = answer_question(user_query, sentences)
        st.write("Answer:", answer)




# Streamlit app
def main():
    st.markdown("<h1 class='title'>CVE Analyzing Using AI</h1>", unsafe_allow_html=True)
    sentences = extract_and_tokenize_text_from_pdf('Generative AI and Large Language Models for Cyber Security.pdf')
    chatbot_interface(sentences)

    with st.expander("Instructions", expanded=True):
        st.markdown("""
            <div class="instructions">
                This application fetches CVE (Common Vulnerabilities and Exposures) data from the NIST NVD API and provides 
                mitigation recommendations based on your user role. Enter a valid CVE ID and select your user role to get started.
            </div>
        """, unsafe_allow_html=True)

    st.markdown("---")

    cve_id = st.text_input("Enter CVE ID", placeholder="e.g., CVE-2021-34527")
    user_role = st.selectbox("Select User Role", USER_ROLES, key="user_role_select")

    if cve_id and user_role:
        with st.spinner("Fetching CVE data..."):
            cve_data = fetch_cve_data(cve_id)
        
        if cve_data:
            try:
                cve_info = {
                    'cve_id': cve_id,
                    'description': cve_data["vulnerabilities"][0]["cve"]["descriptions"][0]["value"],
                    'cvss_score': cve_data["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"],
                    'cvss_vector': cve_data["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"]["vectorString"],
                    'references': [ref["url"] for ref in cve_data["vulnerabilities"][0]["cve"]["references"]]
                }

                insert_cve_data(cve_info, connection)

                cve_description = cve_info['description']
                cvss_score = cve_info['cvss_score']
                cvss_vector = cve_info['cvss_vector']
                references = cve_info['references']
                
                st.subheader("CVE Details")

                references_list = [{"Reference": reference} for reference in references]
                references_df = pd.DataFrame(references_list)
                cve_details_table = pd.DataFrame({
                    'Description': [cve_description],
                    'CVSS Base Score': [cvss_score],
                    'CVSS Vector': [cvss_vector]
                })

                st.table(cve_details_table)
                st.subheader("References")
                st.table(references_df)

                if st.button("Translate to Bahasa Indonesia"):
                    translated_report = generate_security_assessment_report(f"CVE-{cve_id}: {cve_description}", user_role, language='id')
                    st.subheader("Translated Security Assessment Report (Bahasa Indonesia)")
                    st.write(translated_report)
                else:
                    report = generate_security_assessment_report(f"CVE-{cve_id}: {cve_description}", user_role)
                    st.subheader(f"Security Assessment Report for {user_role.capitalize()}")
                    st.write(report)
                    insert_report(cve_id, user_role, report, connection)

                st.subheader("Additional Features")

                infrastructure_details = st.text_area("Enter Infrastructure Details:", placeholder="Describe your infrastructure details here...")
                if st.button("Generate Impact Analysis"):
                    impact_analysis = generate_impact_analysis(f"CVE-{cve_id}: {cve_description}", infrastructure_details)
                    st.subheader("Impact Analysis")
                    st.write(impact_analysis)

                historical_data = fetch_historical_cve_data(connection)
                if historical_data is not None:
                    # Apply conditional formatting to the DataFrame
                    def colorize(val):
                        color = 'maroon' if val >= 9 else 'coral' if val >= 7 else 'greenyellow'
                        return f'background-color: {color}'

                    st.dataframe(historical_data.style.applymap(colorize, subset=['cvss_score']))
                else:
                    st.write("No data available.")
                    st.subheader("Historical CVE Data")
                    
                    st.dataframe(historical_data)

            except KeyError as e:
                st.error(f"Error extracting CVE data: {e}")
                logging.error(f"Error extracting CVE data: {e}")
            except mysql.connector.Error as err:
                st.error(f"Error connecting to MySQL database: {err}")
                logging.error(f"Error connecting to MySQL database: {err}")
        else:
            st.warning("Failed to fetch CVE data. Please check the CVE ID and try again.")

    st.markdown("---")
    st.write("<div class='footer'>This application was developed using Streamlit and Groq.<br>For more information or support, please contact <a href='mailto:your_email@example.com'>your_email@example.com</a>.</div>", unsafe_allow_html=True)

if __name__ == "__main__":
    main()
