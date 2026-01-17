import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    GROQ_API_KEY = os.getenv("GROQ_API_KEY")
    GROQ_MODEL = "mixtral-8x7b-32768"
    CHROME_DRIVER_PATH = os.getenv("CHROME_DRIVER_PATH", "chromedriver")
    HEADLESS = False
    TIMEOUT = 15
    USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    # Extra paths to probe on a host when no link points to them
    EXTRA_PATHS = [
        "/login",
        "/signin",
        "/account",
        "/my-account",
        "/user",
        "/profile",
    ]
    # When True the scanner will only print vulnerable findings to the console
    # and will suppress per-request progress output. Set to False to restore
    # verbose progress logging.
    ONLY_PRINT_VULNERABLE = True
    # If True, fall back to standard payload bruteforce when AI-generated
    # payloads don't confirm a vulnerability. Set to False to rely solely on
    # AI-generated payloads (recommended for faster, AI-driven scans).
    BRUTE_FORCE_FALLBACK = False