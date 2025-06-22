# main.py

import os
from dotenv import load_dotenv
from bot.teams_handler import TeamsBot

def main():
    """Main entry point for the MS Teams Bot"""
    # Load environment variables
    load_dotenv()
    
    print("🤖 Starting MS Teams Bot...")
    
    # Initialize and run the bot
    bot = TeamsBot()
    
    if not bot.validate_environment():
        print("❌ Environment validation failed. Exiting.")
        exit(1)
    
    try:
        bot.run()
    except KeyboardInterrupt:
        print("\n👋 Bot stopped by user")
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        exit(1)

if __name__ == "__main__":
    main()