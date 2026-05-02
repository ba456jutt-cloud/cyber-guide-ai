import os
import hashlib
import json
import re
import datetime
import base64
import io
import tempfile
from urllib.parse import urlparse
from typing import Optional
from fastapi import FastAPI, UploadFile, File, Form, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy import create_engine, Column, Integer, String, Text, text as sqlalchemy_text
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from pydantic import BaseModel
from groq import Groq
import google.generativeai as genai
import PIL.Image
from fastapi.middleware.cors import CORSMiddleware
from fpdf import FPDF
import gradio as gr
from link import check_domain_forensics


# Tier 0: Initialization
# ----------------------
DATABASE_URL = "sqlite:///./threat_intel.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class ScamPattern(Base):
    __tablename__ = "scam_patterns"
    id = Column(Integer, primary_key=True, index=True)
    category = Column(String)
    keywords = Column(Text)
    warning_urdu = Column(Text)
    risk_level = Column(String)
    last_checked = Column(String, default=lambda: datetime.datetime.now().isoformat())

class ScamRecord(Base):
    __tablename__ = "scam_records"
    id = Column(Integer, primary_key=True, index=True)
    media_hash = Column(String, unique=True, index=True)
    threat_level = Column(String)
    category = Column(String)
    explanation = Column(Text)
    warning_text = Column(Text)
    next_steps = Column(Text)
    fia_complaint = Column(Text)
    forensics_json = Column(Text)
    timestamp = Column(String, default=lambda: datetime.datetime.now().isoformat())

Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# API Keys - Use Environment Variables or Defaults
GROQ_API_KEY = os.environ.get("GROQ_API_KEY")
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")

if not GROQ_API_KEY:
    print("Warning: GROQ_API_KEY not found.")
if not GEMINI_API_KEY:
    print("Warning: GEMINI_API_KEY not found.")

groq_client = Groq(api_key=GROQ_API_KEY) if GROQ_API_KEY else None
genai.configure(api_key=GEMINI_API_KEY) if GEMINI_API_KEY else None
gemini_model = genai.GenerativeModel('gemini-flash-latest') if GEMINI_API_KEY else None

# Official Government Domain Registry for Instant Validation
OFFICIAL_GOVT_DOMAINS = {
    "PSCA & E-Challan": ["psca.gop.pk", "punjab.gov.pk", "punjabpolice.gov.pk"],
    "BISP & Ehsaas Program": ["bisp.gov.pk", "8171.pass.gov.pk", "pass.gov.pk", "nser.gov.pk"],
    "Bank & Wallet Fraud": [".com.pk", "hbl.com", "easypaisa.com.pk", "jazzcash.com.pk", "sadapay.pk", "nayapay.com"],
    "FBR & Tax": ["fbr.gov.pk", "iris.fbr.gov.pk"]
}

app = FastAPI(title="Cyber Guider Agentic Backend", version="2.0.0")

# Enable CORS for custom frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def init_scam_data(db: Session):
    """Populates the database with initial patterns if empty."""
    if db.query(ScamPattern).count() == 0:
        patterns = [
            ("BISP & Ehsaas Program", "8171, bisp, ehsaas, mubarak, kafaalat, check, qist, verification, rabta, imdad", "Yeh BISP ya Ehsaas program ka dhoka hai. Hukoomat hamesha 8171 se message bhejti hai.", "High"),
            ("PSCA & E-Challan", "psca, fine, challan, .cc, .top, .info, .xyz, offense, pending, penalty, violation, safe city", "Fake E-Challan links se bachein. Asli challan hamesha official website (.gov.pk) par hota hai.", "High"),
            ("Bank & Wallet Fraud", "block, otp, pin, hbl, easypaisa, jazzcash, meezan, sadapay, suspended, verify, technical update, locked, unusual activity", "Bank ya Easypaisa kabhi bhi phone par OTP ya PIN nahi maangta.", "Critical"),
            ("Prize & Lottery Scams", "jeeto pakistan, zam zam, inam, gift, reward, winner, car, gold, lakh, samsung, coca cola, claim, delivery charges, lucky draw", "Inam ke naam par yeh log aapse 'delivery charges' mangenge. Yeh scam hai.", "High"),
            ("Fake Relative & Emergency", "hospital, accident, jail, pohancho, naya number, museebat, thane, dubai, operation, load, help chahiye", "Yeh emotional blackmailing hai. Pehle kisi purane number se tasdeeq karein.", "Critical"),
            ("Job & Investment Scams", "work from home, salary, investment, amazon, part-time, double, telegram, earning, free registration, fbr, tax refund", "Online earning aur 'paisa double' schemes dhoka hoti hain.", "Medium")
        ]
        for cat, keys, warn, risk in patterns:
            db.add(ScamPattern(category=cat, keywords=keys, warning_urdu=warn, risk_level=risk))
        db.commit()

# Helper Functions
def check_for_scam_local(text: str, db: Session):
    text = text.lower()
    patterns = db.query(ScamPattern).all()
    for p in patterns:
        keyword_list = [k.strip() for k in p.keywords.split(',')]
        if any(k in text for k in keyword_list):
            return {
                "is_scam": True,
                "risk_level": p.risk_level,
                "category": p.category,
                "warning": p.warning_urdu,
                "source": "Local Database",
                "last_checked": p.last_checked
            }
    return None

def is_stale(iso_date_str: str, hours=48):
    if not iso_date_str: return True
    last_check = datetime.datetime.fromisoformat(iso_date_str)
    diff = datetime.datetime.now() - last_check
    return diff.total_seconds() > (hours * 3600)

@app.on_event("startup")
def startup_event():
    db = SessionLocal()
    # Migration: Add columns if they don't exist
    columns_to_add = {
        "scam_patterns": ["last_checked"],
        "scam_records": ["media_hash", "category", "explanation", "warning_text", "next_steps", "fia_complaint", "forensics_json", "timestamp"]
    }
    
    for table, cols in columns_to_add.items():
        for col in cols:
            try:
                # Check if column exists first
                cursor = db.execute(sqlalchemy_text(f"PRAGMA table_info({table})"))
                existing_cols = [row[1] for row in cursor.fetchall()]
                if col not in existing_cols:
                    db.execute(sqlalchemy_text(f"ALTER TABLE {table} ADD COLUMN {col} TEXT"))
                    db.commit()
                    print(f"Migration: Added {col} to {table}.")
            except Exception as e:
                db.rollback()
                print(f"Migration Error on {table}.{col}: {e}")
        
    init_scam_data(db)
    db.close()

# Gradio Interface Logic (Functional Mirror for Hugging Face)
async def analyze_media_gradio(text):
    if not text: return "Please enter some text."
    db = SessionLocal()
    try:
        res = await analyze_media(text_content=text, db=db)
        output = f"### 🛡️ Cyber Guider Report\n"
        output += f"**Status:** {'🚨 SCAM DETECTED' if res['is_scam'] else '✅ SAFE'}\n"
        output += f"**Risk Level:** {res['risk_level']}\n"
        output += f"**Source:** {res['source']}\n\n"
        output += f"**🔍 Analysis:**\n{res['agent_explanation']}\n\n"
        output += f"**🚩 Warning:**\n{res['warning_text']}\n\n"
        output += f"**✅ Next Steps:**\n{res['next_steps']}"
        return output
    except Exception as e:
        return f"Error: {str(e)}"
    finally:
        db.close()

with gr.Blocks(title="Cyber Guider AI", theme=gr.themes.Soft()) as demo:
    gr.Markdown("# 🛡️ CYBER GUIDER AI")
    gr.Markdown("Analyse suspicious messages and protect yourself from scams.")
    with gr.Column():
        input_text = gr.Textbox(label="Paste SMS or WhatsApp Message", lines=4)
        btn = gr.Button("Analyze Threat", variant="primary")
        output_report = gr.Markdown()
    
    btn.click(fn=analyze_media_gradio, inputs=input_text, outputs=output_report)

@app.get("/")
async def read_index():
    return FileResponse("index.html")

@app.post("/analyze-media")
async def analyze_media(
    file: Optional[UploadFile] = File(None),
    text_content: Optional[str] = Form(None),
    db: Session = Depends(get_db)
):
    print("--- New Request Received ---")
    try:
        extracted_text = ""
        transcription = ""
        media_type = "text"
        
        # Step 1: Extraction Layer
        if file:
            content_type = file.content_type
            file_bytes = await file.read()
            print(f"Received file: {file.filename}, Type: {content_type}")
            
            if "image" in content_type:
                media_type = "image"
                # Using Gemini Vision for better extraction and speed
                # No OCR needed separately as we'll pass the image to Gemini later
                extracted_text = "Image content analysis requested."
                
            elif "audio" in content_type or "mpeg" in content_type:
                media_type = "audio"
                with tempfile.NamedTemporaryFile(delete=False, suffix=".m4a") as tmp:
                    tmp.write(file_bytes)
                    tmp_path = tmp.name
                
                try:
                    with open(tmp_path, "rb") as f:
                        transcript_res = groq_client.audio.transcriptions.create(
                            file=(file.filename, f.read()),
                            model="whisper-large-v3",
                        )
                    transcription = transcript_res.text
                    extracted_text = transcription
                finally:
                    if os.path.exists(tmp_path): os.remove(tmp_path)
            else:
                raise HTTPException(status_code=400, detail="Unsupported file type")
        elif text_content:
            extracted_text = text_content
            print(f"Received text content: {extracted_text[:100]}...")
        else:
            print("No input provided")
            raise HTTPException(status_code=400, detail="No input provided")

        # Step 2: Tiered Decision Flow
        
        # --- NEW: Instant Intelligence (Tier 1 - Cache Hit) ---
        # Move this to the top to avoid ANY slow calls (Forensics, Gemini, etc.)
        if file and file_bytes:
            media_hash = hashlib.sha256(file_bytes).hexdigest()
        else:
            media_hash = hashlib.sha256(extracted_text.strip().encode()).hexdigest()
        
        cached_record = db.query(ScamRecord).filter(ScamRecord.media_hash == media_hash).first()
        if cached_record:
            print(f"Instant Hit: Found identical threat in local database (Self-Learning).")
            return {
                "status": "success",
                "media_type": media_type,
                "transcription": transcription if media_type == "audio" else extracted_text,
                "is_scam": True,
                "risk_level": cached_record.threat_level,
                "source": "Local Intelligence (System-Learned)",
                "category": cached_record.category,
                "warning_text": cached_record.warning_text,
                "next_steps": cached_record.next_steps,
                "agent_explanation": cached_record.explanation,
                "forensics": json.loads(cached_record.forensics_json) if cached_record.forensics_json else None,
                "fia_complaint": cached_record.fia_complaint
            }

        # Link Forensics Layer - Only runs if Cache Misses
        link_forensics = None
        urls = re.findall(r'(https?://[^\s]+)', extracted_text)
        if urls:
            print(f"URL(s) detected: {urls[0]}")
            # Analyze the first URL found
            try:
                link_forensics = check_domain_forensics(urls[0])
                print("Link forensics complete.")
            except Exception as e:
                print(f"Forensics Error: {e}")

        # --- NEW: Official Government Domain Validation ---
        gov_scam_detected = False
        urls = re.findall(r'(https?://[^\s]+)', extracted_text)
        if urls:
            detected_domain = urlparse(urls[0]).netloc
            for category, officials in OFFICIAL_GOVT_DOMAINS.items():
                category_match = category.lower().replace(" & ", " ").split()
                if any(word in extracted_text.lower() for word in category_match):
                    # If category keyword is mentioned but domain is NOT official
                    if not any(off in detected_domain for off in officials):
                        gov_scam_detected = True
                        print(f"Gov Impersonation Detected: {detected_domain} is NOT in {officials}")
                        
                        warning_text = f"Khabardar! Yeh message {category} ka naam istemal kar raha hai lekin link official nahi hai."
                        explanation = f"Yeh ek khatarnak scam hai kyunke link '{detected_domain}' official government domain nahi hai. Hukoomat hamesha official domains (.gov.pk) istemal karti hai."
                        next_steps = "1. Is link par hargiz click na karein.\n2. Sirf official govt websites (.gov.pk) par yaqeen karein.\n3. Is fraud ki report FIA ko karein."
                        
                        # Save this gov impersonation to cache immediately
                        new_record = ScamRecord(
                            media_hash=media_hash,
                            threat_level="Critical",
                            category=category,
                            explanation=explanation,
                            warning_text=warning_text,
                            next_steps=next_steps,
                            forensics_json=json.dumps(link_forensics) if link_forensics else None,
                            timestamp=datetime.datetime.now().isoformat()
                        )
                        db.add(new_record)
                        db.commit()

                        return {
                            "status": "success",
                            "media_type": media_type,
                            "is_scam": True,
                            "risk_level": "Critical",
                            "source": "Official Domain Validator",
                            "warning_text": warning_text,
                            "next_steps": next_steps,
                            "agent_explanation": explanation,
                            "forensics": link_forensics
                        }

        # Tier 1: Local Check (Priority - Instant)
        print("Checking local database...")
        local_result = check_for_scam_local(extracted_text, db)
        
        # --- NEW: 48-hour Re-verification Check ---
        force_re_analysis = False
        if local_result and is_stale(local_result.get("last_checked")):
            print("Database record is older than 48h. Forcing re-analysis...")
            force_re_analysis = True

        if local_result and not force_re_analysis:
            # We found it in the database and it's fresh!
            print(f"Local hit found and fresh: {local_result['category']}")
            # We found it in the database! We return IMMEDIATELY for 0ms latency
            category_details = {
                "PSCA & E-Challan": {
                    "explanation": "Yeh ek fake E-Challan scam hai. PSCA hamesha official link (.gov.pk) bhejti hai, .cc ya .top nahi.",
                    "steps": "1. Is link par hargiz click na karein.\n2. Apne challan ki tasdeeq official website (psca.gop.pk) se karein.\n3. Is SMS ko delete karein aur number block karein."
                },
                "BISP & Ehsaas Program": {
                    "explanation": "Yeh BISP ya Ehsaas program ke naam par dhoka hai. Hukoomat sirf 8171 se message bhejti hai.",
                    "steps": "1. 8171 ke ilawa kisi number par yaqeen na karein.\n2. Apni CNIC ya personal info share na karein.\n3. Nazdeeki BISP daftar se ruju karein."
                },
                "Bank & Wallet Fraud": {
                    "explanation": "Yeh bank fraud hai jo aapka account access karna chahte hain. Bank kabhi phone par OTP nahi maangta.",
                    "steps": "1. Apna OTP, PIN ya Password kisi ko na batayein.\n2. Bank ki helpline par call karke block karwayein.\n3. Suspicious apps delete kar dein."
                },
                "Prize & Lottery Scams": {
                    "explanation": "Inam ka lalach de kar yeh log aapse 'processing fee' mangenge. Yeh fraud hai.",
                    "steps": "1. Kisi qisam ki 'delivery' ya 'tax' fee na dein.\n2. Inam ke jhanse mein na aayien.\n3. Aise calls/SMS ko block karein."
                }
            }
            
            details = category_details.get(local_result["category"], {
                "explanation": local_result["warning"],
                "steps": "1. Is par amal na karein.\n2. Maloomat share na karein.\n3. Delete kar dein."
            })

            # For local hits, we still want a formal complaint. 
            # We'll do a quick async Gemini call for the complaint while returning the rest.
            # Or better, we can just use a template for speed, or a quick prompt.
            
            fia_complaint = f"""
To:
The Director,
Cyber Crime Wing,
Federal Investigation Agency (FIA),
Government of Pakistan.

Subject: FORMAL COMPLAINT REGARDING {local_result['category'].upper()} FRAUD

Respected Sir,

I am writing to formally report a cyber-fraud attempt involving {local_result['category']}. The details of the suspicious communication are as follows:

- Content Received: "{transcription if media_type == 'audio' else extracted_text}"
- Detected Risk Level: {local_result['risk_level']}
- Fraud Category: {local_result['category']}

This communication has been analyzed and identified as a scam using the Cyber Guider AI security framework. The patterns detected strongly suggest an attempt to impersonate official bodies or deceive citizens for financial/data theft.

I request the FIA Cyber Crime Wing to investigate this matter, track the origin of this communication, and take necessary legal action to protect other citizens from falling victim to this fraud.

Supporting Evidence:
- Analysis Platform: Cyber Guider AI
- Detection Mode: Pattern Match (Verified Threat Intel)
- Timestamp: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Yours faithfully,

[Complainant Name]
[Contact Details]
"""

            return {
                "status": "success",
                "media_type": media_type,
                "transcription": transcription if media_type == "audio" else extracted_text,
                "is_scam": True,
                "risk_level": local_result["risk_level"],
                "source": "Local Database",
                "warning_text": local_result["warning"],
                "next_steps": details["steps"],
                "agent_explanation": details["explanation"],
                "forensics": link_forensics,
                "fia_complaint": fia_complaint
            }


        # Tier 2: AI Reasoning (Gemini Flash) - Only if DB misses
        system_prompt = "You are a Cybersecurity Expert specializing in Pakistani scams. Analyze the input and provide a detailed forensic report in Roman Urdu."
        
        analysis_prompt = f"""
        {system_prompt}
        Analyze this content for potential fraud or scam in Pakistan.
        Content: "{extracted_text}"
        {"Link Forensics: " + json.dumps(link_forensics) if link_forensics else ""}
        
        Return ONLY a JSON object:
        {{
            "is_scam": true/false,
            "risk_level": "High/Medium/Low",
            "explanation": "2-3 lines Roman Urdu explanation starting with 'Yeh ek scam hai...' for the user interface.",
            "warning": "Short Roman Urdu warning summary",
            "next_steps": "3-step actionable 'Next Action Plan' in Roman Urdu",
            "fia_complaint": "A 300-word highly professional legal complaint in English. Address it to 'The Director, Cyber Crime Wing, FIA'. Include a 'Forensic Evidence' section INSIDE the complaint text that lists URLs, IP/Domain info, and specific reasons why this is a scam (e.g. impersonation of BISP, absence of SSL, recent domain registration). Mention that this report is generated via Cyber Guider AI's Forensic Engine."
        }}


        """
        
        is_scam = False
        risk_level = "Low"
        warning_text = "Nizam ne isay mehfooz paya hai."
        next_steps = "1. Ihtiyat karein.\n2. Unknown links par click na karein.\n3. Kisi ko OTP na batayein."
        agent_explanation = "Yeh mehfooz lag raha hai."
        source = "AI Analysis (Gemini Flash)"

        try:
            if media_type == "image" and file_bytes:
                img = PIL.Image.open(io.BytesIO(file_bytes))
                gemini_res = gemini_model.generate_content([analysis_prompt, img])
            else:
                gemini_res = gemini_model.generate_content(analysis_prompt)
                
            res_text = gemini_res.text.strip()
            if "```json" in res_text:
                res_text = res_text.split("```json")[1].split("```")[0].strip()
            res_json = json.loads(res_text)
            
            is_scam = res_json.get("is_scam", is_scam)
            risk_level = res_json.get("risk_level", risk_level)
            agent_explanation = res_json.get("explanation", agent_explanation)
            warning_text = res_json.get("warning", warning_text)
            next_steps = res_json.get("next_steps", next_steps)
            fia_complaint = res_json.get("fia_complaint", "No complaint generated.")
            
            # Post-analysis forensics: If Gemini found a URL that we missed (common in images)
            if not link_forensics:
                combined_text = extracted_text + " " + res_text + " " + agent_explanation
                new_urls = re.findall(r'(https?://[^\s]+)', combined_text)
                if new_urls:
                    print(f"Post-analysis: URL detected in image content: {new_urls[0]}")
                    try:
                        link_forensics = check_domain_forensics(new_urls[0])
                        print("Post-analysis forensics complete.")
                    except Exception as e:
                        print(f"Post-analysis Forensics Error: {e}")
        except Exception as e:
            print(f"Gemini Error: {e}")
            source = "AI Analysis (Fallback)"

        result_data = {
            "status": "success",
            "media_type": media_type,
            "transcription": transcription if media_type == "audio" else extracted_text,
            "is_scam": is_scam,
            "risk_level": risk_level,
            "source": source,
            "warning_text": warning_text,
            "next_steps": next_steps,
            "agent_explanation": agent_explanation,
            "forensics": link_forensics,
            "fia_complaint": fia_complaint
        }

        
        # Auto-Learning: If AI detected a high-risk scam, save it to the DB for future speed
        if is_scam and risk_level in ["High", "Critical"]:
            print(f"Auto-Learning: Saving new {risk_level} threat to database...")
            try:
                # 1. Save to ScamRecord for exact content matching (Instant Tier 1)
                if not cached_record:
                    new_record = ScamRecord(
                        media_hash=media_hash,
                        threat_level=risk_level,
                        category="AI Detected Scam",
                        explanation=agent_explanation,
                        warning_text=warning_text,
                        next_steps=next_steps,
                        fia_complaint=fia_complaint,
                        forensics_json=json.dumps(link_forensics) if link_forensics else None,
                        timestamp=datetime.datetime.now().isoformat()
                    )
                    db.add(new_record)
                
                # 2. Save to ScamPattern for keyword matching (Fuzzy Tier 1)
                if not local_result:
                    # Extract identifiers for future matching
                    urls = re.findall(r'(https?://[^\s]+)', extracted_text)
                    domain = urlparse(urls[0]).netloc if urls else ""
                    
                    # Create a concise pattern
                    keywords = f"{domain}, " if domain else ""
                    keywords += ", ".join([w for w in extracted_text.split() if len(w) > 4][:3])
                    
                    new_pattern = ScamPattern(
                        category="Auto-Detected Threat",
                        keywords=keywords,
                        warning_urdu=warning_text,
                        risk_level=risk_level,
                        last_checked=datetime.datetime.now().isoformat()
                    )
                    db.add(new_pattern)
                
                db.commit()
                print("Self-Learning complete: Data saved to database.")
            except Exception as e:
                db.rollback()
                print(f"Auto-Learning Error: {e}")

        return result_data

    except Exception as e:
        print(f"Error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/report-scam")
async def report_scam(
    text_content: str = Form(...),
    category: str = Form("User Reported"),
    db: Session = Depends(get_db)
):
    try:
        # Simple extraction of identifiers (URLs, numbers, etc.)
        urls = re.findall(r'(https?://[^\s]+)', text_content)
        domain = ""
        if urls:
            domain = urlparse(urls[0]).netloc
            
        # Add to database
        keywords = f"{domain}, " if domain else ""
        # Add first 3 words as keywords if they are long enough
        words = [w for w in text_content.split() if len(w) > 3][:3]
        keywords += ", ".join(words)
        
        new_pattern = ScamPattern(
            category=category,
            keywords=keywords,
            warning_urdu="Yeh community ke zariye report kiya gaya scam hai.",
            risk_level="High"
        )
        db.add(new_pattern)
        db.commit()
        
        return {"status": "success", "message": "Scam added to global blacklist."}
    except Exception as e:
        print(f"Report Error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/chat")
async def chat_with_agent(
    question: str = Form(...),
    context: str = Form(...)
):
    try:
        chat_prompt = f"""
        Context about the scam: {context}
        User Question: {question}
        
        As a Cybersecurity Expert, answer the user's follow-up question in Roman Urdu. 
        Be concise, helpful, and protective. If they ask about safety, give them clear instructions.
        """
        response = gemini_model.generate_content(chat_prompt)
        return {"status": "success", "response": response.text}
    except Exception as e:
        print(f"Chat Error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/generate-pdf")
async def generate_pdf(
    complaint_text: str = Form(...),
    scam_type: str = Form("Scam Reporting"),
    evidence: str = Form("")
):
    try:
        pdf = FPDF()
        pdf.add_page()
        
        # Header
        pdf.set_font("Helvetica", 'B', 16)
        pdf.set_text_color(30, 41, 59) # Dark blue/slate
        pdf.cell(0, 15, "CYBER CRIME REPORTING FORM", ln=True, align='C')
        pdf.set_draw_color(129, 140, 248) # Primary color
        pdf.line(10, 25, 200, 25)
        pdf.ln(10)
        
        pdf.set_font("Helvetica", 'B', 12)
        pdf.set_text_color(0, 0, 0)
        pdf.cell(0, 8, "To: The Director, FIA Cybercrime Wing", ln=True, align='L')
        pdf.set_font("Helvetica", '', 11)
        pdf.cell(0, 8, f"Date: {datetime.datetime.now().strftime('%d %B, %Y')}", ln=True, align='L')
        pdf.cell(0, 8, f"Reference: CG-AI/{datetime.datetime.now().strftime('%Y%m%d')}/{os.urandom(2).hex().upper()}", ln=True, align='L')
        
        pdf.ln(10)
        
        # Subject
        pdf.set_font("Helvetica", 'B', 12)
        pdf.set_fill_color(241, 245, 249)
        pdf.multi_cell(0, 10, f"Subject: Formal Complaint Regarding {scam_type.upper()}", fill=True)
        
        pdf.ln(5)
        
        # Body
        pdf.set_font("Helvetica", size=11)
        
        # Clean markdown formatting (###, **, etc.)
        cleaned_text = complaint_text.replace('###', '').replace('**', '').replace('__', '')
        # Remove common placeholders like [Complainant Name]
        cleaned_text = re.sub(r'\[Your Name.*?\]', '', cleaned_text)
        cleaned_text = re.sub(r'\[Complainant Name\]', '', cleaned_text)
        cleaned_text = re.sub(r'\[Contact Details\]', '', cleaned_text)
        
        # Handle potential encoding issues
        clean_text = cleaned_text.encode('latin-1', 'replace').decode('latin-1')
        pdf.multi_cell(0, 7, clean_text)
        
        if evidence:
            pdf.ln(5)
            pdf.set_font("Helvetica", 'B', 11)
            pdf.cell(0, 10, "Technical Metadata:", ln=True)
            pdf.set_font("Helvetica", 'I', 10)
            
            # Clean evidence as well
            clean_evidence = evidence.replace('###', '').replace('**', '').replace('__', '')
            clean_evidence = clean_evidence.encode('latin-1', 'replace').decode('latin-1')
            pdf.multi_cell(0, 6, clean_evidence)
            
        pdf.ln(20)
        pdf.set_font("Helvetica", 'B', 11)
        pdf.cell(0, 10, "Report Generated by Cyber Guider AI Forensic Engine", ln=True)
        
        pdf.set_y(-30)
        pdf.set_font("Helvetica", 'I', 8)
        pdf.set_text_color(150, 150, 150)
        pdf.cell(0, 10, "This is an automated forensic report for legal verification purposes.", align='C')

        
        # Create a temporary file to save the PDF
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as tmp:
            pdf.output(tmp.name)
            tmp_path = tmp.name
            
        return FileResponse(
            tmp_path,
            media_type="application/pdf",
            filename="FIA_Complaint_Application.pdf"
        )
    except Exception as e:
        print(f"PDF Error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Mount Gradio for Hugging Face compatibility
app = gr.mount_gradio_app(app, demo, path="/gradio")

if __name__ == "__main__":
    import uvicorn
    # Hugging Face uses port 7860 by default
    port = int(os.environ.get("PORT", 7860))
    uvicorn.run(app, host="0.0.0.0", port=port)
