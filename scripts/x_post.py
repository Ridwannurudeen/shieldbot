"""
ShieldBot X (Twitter) Poster — API-based (tweepy)
Uses X API v2 with OAuth 1.0a to post tweets and threads.

Usage:
  # Post a single tweet:
  python x_post.py post "Your tweet text here"

  # Post a thread (tweets separated by ---):
  python x_post.py thread thread.txt

  # Check logged-in account:
  python x_post.py whoami
"""

import sys
import time
from pathlib import Path

import tweepy
from dotenv import load_dotenv
import os

load_dotenv(Path(__file__).parent / ".env")

def get_client():
    return tweepy.Client(
        consumer_key=os.getenv("X_CONSUMER_KEY"),
        consumer_secret=os.getenv("X_CONSUMER_SECRET"),
        access_token=os.getenv("X_ACCESS_TOKEN"),
        access_token_secret=os.getenv("X_ACCESS_TOKEN_SECRET"),
    )


def whoami():
    client = get_client()
    me = client.get_me()
    print(f"Logged in as: @{me.data.username} ({me.data.name})")


def post_tweet(text: str, reply_to: str = None, retries: int = 3) -> str:
    client = get_client()
    kwargs = {"text": text}
    if reply_to:
        kwargs["in_reply_to_tweet_id"] = reply_to
    for attempt in range(retries):
        try:
            response = client.create_tweet(**kwargs)
            tweet_id = response.data["id"]
            print(f"Posted [{tweet_id}]: {text[:80]}{'...' if len(text) > 80 else ''}")
            return tweet_id
        except Exception as e:
            if attempt < retries - 1:
                print(f"Attempt {attempt + 1} failed: {e}. Retrying in 5s...")
                time.sleep(5)
            else:
                raise


def post_thread(tweets: list[str], start_reply_to: str = None):
    reply_to = start_reply_to
    start = 0 if not start_reply_to else 0
    for i, tweet in enumerate(tweets, 1):
        reply_to = post_tweet(tweet, reply_to=reply_to)
        if i < len(tweets):
            time.sleep(3)
    print(f"\nThread posted — {len(tweets)} tweets.")


def load_thread_file(path: str) -> list[str]:
    content = Path(path).read_text(encoding="utf-8")
    tweets = [t.strip() for t in content.split("\n---\n") if t.strip()]
    return tweets


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return

    cmd = sys.argv[1]

    if cmd == "whoami":
        whoami()

    elif cmd == "post":
        if len(sys.argv) < 3:
            print("Usage: python x_post.py post 'Your tweet text'")
            return
        post_tweet(sys.argv[2])

    elif cmd == "thread":
        if len(sys.argv) < 3:
            print("Usage: python x_post.py thread thread.txt")
            return
        tweets = load_thread_file(sys.argv[2])
        print(f"Loaded {len(tweets)} tweets from {sys.argv[2]}")
        for i, t in enumerate(tweets, 1):
            print(f"\n[{i}] {t[:100]}{'...' if len(t) > 100 else ''}")
        print("\nPost this thread? (y/n): ", end="")
        if input().strip().lower() == "y":
            post_thread(tweets)
        else:
            print("Aborted.")

    else:
        print(f"Unknown command: {cmd}")
        print(__doc__)


if __name__ == "__main__":
    main()
