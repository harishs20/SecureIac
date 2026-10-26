from dotenv import load_dotenv
from google import genai
from google.genai import types

load_dotenv()

client = genai.Client(
    http_options=types.HttpOptions(timeout=60000)
)

print("Connecting to Gemini...")

try:
    response = client.models.generate_content(
        model="gemini-3.8-flash",
        contents="Say hello in one short sentence.",
        config=types.GenerateContentConfig(
            thinking_config=types.ThinkingConfig(
                thinking_level="low"
            ),
            max_output_tokens=20
        )
    )

    print("\nGemini response:")
    print(response.text)

except Exception as e:
    print("\nRequest failed:")
    print(type(e).__name__)
    print(e)