# Import the KeyGenerator class from the key_generator module
from key_generator import KeyGenerator

# Define the main function that will execute the key generation process
def main():
    # Print a message indicating the start of key generation
    print("\nStep 1: Generating keys...")
    # Create an instance of the KeyGenerator class
    key_generator = KeyGenerator()
    
    # Print a message indicating the generation of keys for Yousef
    print("Generating keys for Yousef...")
    # Generate a key pair for Yousef with a specified password
    key_generator.generate_key_pair("Yousef", "yousefpass123")
    # Print a confirmation message for Yousef's keys
    print("✓ Generated keys for Yousef")
    
    # Print a message indicating the generation of keys for Mohammed
    print("Generating keys for Mohammed...")
    # Generate a key pair for Mohammed with a specified password
    key_generator.generate_key_pair("Mohammed", "mohammedpass123")
    # Print a confirmation message for Mohammed's keys
    print("✓ Generated keys for Mohammed")
    
    # Print a message indicating that keys have been generated and stored
    print("\nKeys have been generated and stored in the 'keys' directory.")
    # Print a message indicating the next steps for the user
    print("You can now proceed with encryption and signing.")

# Check if the script is being run directly (not imported)
if __name__ == "__main__":
    # Call the main function to execute the key generation process
    main()
