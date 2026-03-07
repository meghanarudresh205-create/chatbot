from flask import Flask, render_template, request, jsonify
import json
import cv2
import emoji
from deepface import DeepFace
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

app = Flask(__name__)

# -------------------------------
# Load dataset
# -------------------------------
with open("dataset.json", encoding="utf-8") as f:
    data = json.load(f)

questions = [item["question"] for item in data]
answers = [item["answer"] for item in data]

# -------------------------------
# Train chatbot model
# -------------------------------
vectorizer = TfidfVectorizer()
X = vectorizer.fit_transform(questions)

def convert_emoji(text):
    return emoji.demojize(text)

user_input = input("You: ")

# Convert emoji to text
user_input = convert_emoji(user_input)

print("Processed input:", user_input)


# -------------------------------
# Chatbot response function
# -------------------------------
def get_response(user_input):

    user_vector = vectorizer.transform([user_input])
    similarity = cosine_similarity(user_vector, X)

    best_match_index = similarity.argmax()
    best_score = similarity[0][best_match_index]

    if best_score < 0.2:
        return "I'm not sure I understand. Can you explain more?"

    return answers[best_match_index]


# -------------------------------
# Emotion detection
# -------------------------------
def detect_emotion():

    try:
        camera = cv2.VideoCapture(0)

        if not camera.isOpened():
            return "Camera not accessible"

        ret, frame = camera.read()
        camera.release()

        if not ret:
            return "Could not capture image"

        result = DeepFace.analyze(
            frame,
            actions=['emotion'],
            enforce_detection=False
        )

        emotion = result[0]['dominant_emotion']
        return emotion

    except Exception as e:
        return "Emotion detection failed"


# -------------------------------
# Routes
# -------------------------------

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/chat", methods=["POST"])
def chat():

    user_message = request.json["message"]
    bot_response = get_response(user_message)

    return jsonify({"response": bot_response})


@app.route("/emotion")
def emotion():

    detected_emotion = detect_emotion()

    return jsonify({"emotion": detected_emotion})


# -------------------------------
# Run server
# -------------------------------
if __name__ == "__main__":
    app.run(debug=True)