import os
import uuid
import joblib
import numpy as np
from flask import Flask, request, jsonify, render_template
from werkzeug.utils import secure_filename
from feature_extractor import extract_features

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 32 * 1024 * 1024
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

MODEL_PATH = "model.pkl"
if not os.path.exists(MODEL_PATH):
    raise FileNotFoundError("model.pkl not found! Run: python train_model.py")
model = joblib.load(MODEL_PATH)
print("Model loaded successfully.")

MALICIOUS_TIPS = [
    "Do NOT open or execute this file.",
    "Scan with a reputable antivirus (Windows Defender, Malwarebytes).",
    "Keep regular backups on an external drive or cloud.",
    "Keep your OS and software up to date.",
    "Never download software from unofficial sources.",
    "If already infected, disconnect from the internet immediately.",
]
BENIGN_TIPS = [
    "Always verify file sources before opening.",
    "Keep your antivirus definitions updated.",
    "Maintain regular data backups.",
    "Avoid clicking suspicious email attachments.",
]

def build_reasons(info, prediction):
    reasons = []
    if info["entropy"] >= 7.0:
        reasons.append(f"Very high entropy ({info['entropy']:.2f}/8.0) — file appears encrypted or packed.")
    elif info["entropy"] >= 6.0:
        reasons.append(f"Elevated entropy ({info['entropy']:.2f}/8.0) — possible compression or obfuscation.")
    if info["has_sus_strings"]:
        kw_str = ", ".join(info["suspicious_list"][:5])
        reasons.append(f"Suspicious keywords detected: {kw_str}.")
    if info["extension_risk"]:
        reasons.append(f"Risky file extension ({info['extension']}) — commonly used by malware.")
    if info["url_count"] > 3:
        reasons.append(f"Contains {info['url_count']} embedded URLs — possible C2 communication.")
    if info["ip_count"] > 2:
        reasons.append(f"Contains {info['ip_count']} embedded IP addresses.")
    if info["string_count"] < 15 and prediction == 1:
        reasons.append("Very few readable strings — content may be obfuscated.")
    if not reasons:
        reasons.append("No strong individual indicators, but overall pattern matches malicious samples.")
    return reasons

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded."}), 400
    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "Empty filename."}), 400

    original_name = secure_filename(file.filename)
    temp_name = f"{uuid.uuid4().hex}_{original_name}"
    temp_path = os.path.join(UPLOAD_FOLDER, temp_name)

    try:
        file.save(temp_path)
        info = extract_features(temp_path, original_name)
        features_array = np.array(info["features"]).reshape(1, -1)
        prediction = int(model.predict(features_array)[0])
        proba = model.predict_proba(features_array)[0]
        confidence = round(float(max(proba)) * 100, 1)
        label = "MALICIOUS" if prediction == 1 else "BENIGN"
        reasons = build_reasons(info, prediction)
        tips = MALICIOUS_TIPS if prediction == 1 else BENIGN_TIPS
        risk_score = round(float(proba[1]) * 100, 1)

        return jsonify({
            "filename": original_name,
            "prediction": label,
            "confidence": confidence,
            "risk_score": risk_score,
            "reasons": reasons,
            "tips": tips,
            "details": {
                "file_size": f"{info['file_size']:,} bytes",
                "entropy": f"{info['entropy']:.4f} / 8.0",
                "extension": info["extension"],
                "md5": info["md5"],
                "sha256": info["sha256"],
                "strings": info["string_count"],
                "urls": info["url_count"],
                "ips": info["ip_count"],
            }
        })
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)