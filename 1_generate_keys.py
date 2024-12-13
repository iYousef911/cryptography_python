from key_generator import KeyGenerator

def main():
    print("\nStep 1: Generating keys...")
    key_generator = KeyGenerator()
    
    print("Generating keys for Yousef...")
    key_generator.generate_key_pair("Yousef", "yousefpass123")
    print("✓ Generated keys for Yousef")
    
    print("Generating keys for Mohammed...")
    key_generator.generate_key_pair("Mohammed", "mohammedpass123")
    print("✓ Generated keys for Mohammed")
    
    print("\nKeys have been generated and stored in the 'keys' directory.")
    print("You can now proceed with encryption and signing.")

if __name__ == "__main__":
    main()
